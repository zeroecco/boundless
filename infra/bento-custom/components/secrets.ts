import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export async function setupSecrets(
    name: string,
    tags: Record<string, string>
) {
    const config = new pulumi.Config();
    
    // Create secret for broker private key
    const brokerPrivateKey = new aws.secretsmanager.Secret(`${name}-broker-private-key`, {
        name: `${name}/broker/private-key`,
        description: "Private key for broker wallet",
        tags: {
            ...tags,
            Name: `${name}-broker-private-key`,
        },
    });

    // Set the actual secret value (you'll need to update this after creation)
    const brokerPrivateKeyVersion = new aws.secretsmanager.SecretVersion(`${name}-broker-private-key-version`, {
        secretId: brokerPrivateKey.id,
        secretString: config.getSecret("brokerPrivateKey") || "PLACEHOLDER_UPDATE_ME",
    });

    // Create secret for RPC URL
    const rpcUrl = new aws.secretsmanager.Secret(`${name}-rpc-url`, {
        name: `${name}/broker/rpc-url`,
        description: "RPC URL for blockchain access",
        tags: {
            ...tags,
            Name: `${name}-rpc-url`,
        },
    });

    const rpcUrlVersion = new aws.secretsmanager.SecretVersion(`${name}-rpc-url-version`, {
        secretId: rpcUrl.id,
        secretString: config.getSecret("rpcUrl") || "https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY",
    });

    // Create secret for order stream URL
    const orderStreamUrl = new aws.secretsmanager.Secret(`${name}-order-stream-url`, {
        name: `${name}/broker/order-stream-url`,
        description: "Order stream WebSocket URL",
        tags: {
            ...tags,
            Name: `${name}-order-stream-url`,
        },
    });

    const orderStreamUrlVersion = new aws.secretsmanager.SecretVersion(`${name}-order-stream-url-version`, {
        secretId: orderStreamUrl.id,
        secretString: config.getSecret("orderStreamUrl") || "wss://order-stream.example.com",
    });

    // S3 credentials for Bento (using IAM roles instead)
    // We'll use IAM instance profiles for S3 access

    return {
        brokerPrivateKey: brokerPrivateKey.arn,
        rpcUrl: rpcUrl.arn,
        orderStreamUrl: orderStreamUrl.arn,
    };
}