use crate::{Order, State};
use alloy::{
    primitives::U256,
    providers::{Provider, WalletProvider},
};
use anyhow::Context;
use broker::{upload_image_uri, upload_input_uri};

impl<P> State<P>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    pub async fn prove_order(&self, order_id: U256, order: &Order) -> anyhow::Result<String> {
        let (max_file_size, fetch_retries) = {
            let config = self.config.lock_all().context("Failed to read config")?;
            (config.market.max_file_size, config.market.max_fetch_retries)
        };

        let image_id = order
            .image_url
            .get_or_try_init(|| async {
                upload_image_uri(&self.prover, &order.request, max_file_size, fetch_retries).await
            })
            .await?;

        let input_id = order
            .input_url
            .get_or_try_init(|| async {
                upload_input_uri(&self.prover, &order.request, max_file_size, fetch_retries).await
            })
            .await?;

        tracing::info!("Proving order {order_id:x}");

        let proof_id = self
            .prover
            .prove_stark(image_id, input_id, /* TODO assumptions */ vec![])
            .await
            .context("Failed to prove customer proof STARK order")?;

        // TODO persist proof ID for order to avoid duplicate work on restart

        self.monitor_proof(order_id, &proof_id).await?;

        Ok(proof_id)
    }

    pub async fn monitor_proof(&self, order_id: U256, proof_id: &str) -> anyhow::Result<()> {
        let proof_res =
            self.prover.wait_for_stark(proof_id).await.context("Monitoring proof failed")?;

        // TODO this is where order would be marked for aggregation
        // self.db
        //     .set_aggregation_status(order_id)
        //     .await
        //     .with_context(|| format!("Failed to set the DB record to aggregation {order_id:x}"))?;

        tracing::info!(
            "Customer Proof complete, order_id: {order_id:x} cycles: {} time: {}",
            proof_res.stats.total_cycles,
            proof_res.elapsed_time,
        );

        Ok(())
    }
}
