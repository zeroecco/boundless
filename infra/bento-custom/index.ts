import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import { setupNetwork } from "./components/network";
import { setupDatabase } from "./components/database";
import { setupStorage } from "./components/storage";
import { setupCache } from "./components/cache";
import { setupEcsCluster } from "./components/ecs-cluster";
import { setupExecAgents } from "./components/exec-agents";
import { setupSnarkAgent } from "./components/snark-agent";
import { setupGpuProvers } from "./components/gpu-provers";
import { setupAuxAgent } from "./components/aux-agent";
import { setupEC2Broker } from "./components/ec2-broker";
import { setupBentoAPI } from "./components/bento-api";
import { setupSecrets } from "./components/secrets";
import { setupMonitoring } from "./components/monitoring";

const config = new pulumi.Config();
const environment = config.get("environment") || "custom";
const region = aws.getRegion().then(r => r.name);

// Create tags for all resources
const commonTags = {
    Environment: environment,
    Project: "bento-custom",
    ManagedBy: "pulumi",
};

// Main infrastructure setup
async function main() {
    const network = await setupNetwork("bento-custom", commonTags);

    const secrets = await setupSecrets("bento-custom", commonTags);

    const database = await setupDatabase("bento-custom", network, commonTags);

    const storage = await setupStorage("bento-custom", commonTags);

    // Main ECS cluster for exec/gpu/snark workers
    const cluster = await setupEcsCluster("bento-custom", network, commonTags);

    // Setup cache with GPU-compatible subnets for co-location
    const cache = await setupCache("bento-custom", network, commonTags, cluster.gpuCompatibleSubnets);

    const execAgents = await setupExecAgents("bento-custom", network, cluster, database, cache, storage, secrets, commonTags);
    const snarkAgent = await setupSnarkAgent("bento-custom", network, cluster, database, cache, storage, secrets, commonTags);
    const gpuProvers = await setupGpuProvers("bento-custom", network, cluster, database, cache, storage, secrets, commonTags);

    // Aux-agent creates its own Fargate cluster which Bento-API will reuse
    const auxAgent = await setupAuxAgent("bento-custom", network, database, cache, storage, secrets, commonTags);

    const bentoAPI = await setupBentoAPI("bento-custom", network, auxAgent.cluster, database, cache, storage, secrets, commonTags);

    const ec2Broker = await setupEC2Broker("bento-custom", network, storage, secrets, commonTags, bentoAPI.bentoApiUrl);

    // Setup monitoring and alerts
    const monitoring = await setupMonitoring(
        "bento-custom",
        { execAgents, snarkAgent, gpuProvers, auxAgent, ec2Broker, bentoAPI },
        database,
        cache,
        commonTags
    );

    // Export important values
    return {
        vpcId: network.vpc.vpcId,
        // ECS cluster
        ecsClusterName: cluster.cluster.name,
        ecsClusterArn: cluster.cluster.arn,
        // ECS services
        execAgentsServiceArn: execAgents.service.id,
        snarkAgentServiceArn: snarkAgent.service.id,
        gpuProversServiceArn: gpuProvers.service.id,
        brokerInstanceArn: ec2Broker.instance.arn,
        bentoAPIServiceArn: bentoAPI.service.id,
        bentoAPIUrl: bentoAPI.bentoApiUrl,
        auxAgentServiceArn: auxAgent.service.id,
        // Database endpoints (private)
        databaseEndpoint: database.instance.endpoint,
        databaseProxyEndpoint: database.proxy.endpoint,
        redisEndpoint: cache.cluster.cacheNodes[0].address,
        s3BucketName: storage.bucket.id,
        // Monitoring
        alertsTopicArn: monitoring.alertsTopicArn,
        dashboardUrl: pulumi.interpolate`https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#dashboards:name=${monitoring.dashboard.dashboardName}`,
    };
}

// Export the main outputs
export const outputs = main();