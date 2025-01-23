use alloy::node_bindings::AnvilInstance;
use futures::FutureExt;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use url::Url;

const BUF_SIZE: usize = 1024;

/// A simple TCP proxy designed for introducing faults at the network layer for testing purposes
/// Repurposed from https://github.com/mqudsi/tcpproxy
pub struct RpcTestProxy {
    local_addr: SocketAddr,
    fault_trigger: oneshot::Sender<()>,
}

impl RpcTestProxy {
    /// Create a new proxy that forwards traffic to the given Anvil instance
    pub async fn spawn_wrapping(instance: &AnvilInstance) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        tracing::info!("Starting proxy on: {:?}", listener.local_addr().unwrap());
        let local_addr = listener.local_addr().unwrap();

        let anvil_endpoint = instance.endpoint().replace("localhost", "127.0.0.1");
        let anvil_endpoint = anvil_endpoint.strip_prefix("http://").unwrap().to_string();

        let (tx, rx) = oneshot::channel();
        tokio::spawn(listen_and_forward(listener, anvil_endpoint, rx));
        Self { local_addr, fault_trigger: tx }
    }

    /// Get the HTTP URL of the proxy
    pub fn endpoint_url(&self) -> Url {
        Url::parse(&format!("http://{}", self.local_addr)).unwrap()
    }

    /// Get the HTTP URL of the proxy as a string
    pub fn endpoint(&self) -> String {
        self.local_addr.to_string()
    }

    /// Trigger a fault in the proxy and consume self
    pub fn trigger_fault(self) {
        self.fault_trigger.send(()).unwrap();
    }
}

async fn listen_and_forward(
    listener: TcpListener,
    remote: String,
    mut fault_trigger: oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Sync + Send + 'static>> {
    tracing::info!("Listening on {}", listener.local_addr().unwrap());
    tracing::info!("forwarding to {}", &remote);

    let remote: &str = Box::leak(remote.into_boxed_str());

    // Two instances of this function are spawned for each half of the connection: client-to-server,
    // server-to-client. We can't use tokio::io::copy() instead (no matter how convenient it might
    // be) because it doesn't give us a way to correlate the lifetimes of the two tcp read/write
    // loops: even after the client disconnects, tokio would keep the upstream connection to the
    // server alive until the connection's max client idle timeout is reached.
    async fn copy_with_abort<R, W>(
        read: &mut R,
        write: &mut W,
        mut abort: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::io::Result<usize>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut copied = 0;
        let mut buf = [0u8; BUF_SIZE];
        loop {
            let bytes_read;
            tokio::select! {
                biased;

                result = read.read(&mut buf) => {
                    use std::io::ErrorKind::{ConnectionReset, ConnectionAborted};
                    bytes_read = result.or_else(|e| match e.kind() {
                        // Consider these to be part of the proxy life, not errors
                        ConnectionReset | ConnectionAborted => Ok(0),
                        _ => Err(e)
                    })?;
                },
                _ = abort.recv() => {
                    break;
                }
            }

            if bytes_read == 0 {
                break;
            }

            // While we ignore some read errors above, any error writing data we've already read to
            // the other side is always treated as exceptional.
            write.write_all(&buf[0..bytes_read]).await?;
            copied += bytes_read;
        }

        Ok(copied)
    }

    loop {
        let (mut client, client_addr) = listener.accept().await?;

        if fault_trigger.try_recv().is_ok() {
            tracing::info!("Fault triggered");
            continue;
        }

        tokio::spawn(async move {
            println!("New connection from {}", client_addr);

            // Establish connection to upstream for each incoming client connection
            let mut remote = match TcpStream::connect(remote).await {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Error establishing upstream connection: {e}");
                    return;
                }
            };
            let (mut client_read, mut client_write) = client.split();
            let (mut remote_read, mut remote_write) = remote.split();

            let (cancel, _) = tokio::sync::broadcast::channel::<()>(1);
            let (remote_copied, client_copied) = tokio::join! {
                copy_with_abort(&mut remote_read, &mut client_write, cancel.subscribe())
                    .then(|r| { let _ = cancel.send(()); async { r } }),
                copy_with_abort(&mut client_read, &mut remote_write, cancel.subscribe())
                    .then(|r| { let _ = cancel.send(()); async { r } }),
            };

            match client_copied {
                Ok(count) => {
                    tracing::debug!(
                        "Transferred {} bytes from proxy client {} to upstream server",
                        count,
                        client_addr
                    );
                }
                Err(err) => {
                    tracing::error!(
                        "Error writing bytes from proxy client to upstream server: {}",
                        err
                    );
                }
            };

            match remote_copied {
                Ok(count) => {
                    tracing::debug!(
                        "Transferred {} bytes from upstream server to proxy client {}",
                        count,
                        client_addr
                    );
                }
                Err(err) => {
                    tracing::error!(
                        "Error writing bytes from upstream server to proxy client: {}",
                        err
                    );
                }
            };
        });
    }
}
