import * as aws from '@pulumi/aws';
import * as awsx from '@pulumi/awsx';
import * as docker_build from '@pulumi/docker-build';
import * as pulumi from '@pulumi/pulumi';
import { getEnvVar, getServiceNameV1 } from '../util';
import { OrderGenerator } from './components/order-generator';

require('dotenv').config();

export = () => {
    const stackName = pulumi.getStack();
    const isDev = stackName === "dev";

    const baseConfig = new pulumi.Config("kailua-order-generator-base");
    const chainId = baseConfig.require('CHAIN_ID');
    const pinataJWT = baseConfig.requireSecret('PINATA_JWT');
    const ethRpcUrl = baseConfig.requireSecret('ETH_RPC_URL');
    const boundlessOrderStreamUrl = baseConfig.getSecret('BOUNDLESS_ORDER_STREAM_URL') || pulumi.output("none");
    const boundlessWalletKey = baseConfig.requireSecret('BOUNDLESS_WALLET_KEY');
    const boundlessRpcUrl = baseConfig.requireSecret('BOUNDLESS_RPC_URL');
    const githubTokenSecret = baseConfig.getSecret('GH_TOKEN_SECRET');
    const logLevel = baseConfig.require('LOG_LEVEL');
    const dockerDir = baseConfig.require('DOCKER_DIR');
    const dockerTag = baseConfig.require('DOCKER_TAG');
    const dockerRemoteBuilder = isDev ? process.env.DOCKER_REMOTE_BUILDER : undefined;
    const setVerifierAddr = baseConfig.require('SET_VERIFIER_ADDR');
    const boundlessMarketAddr = baseConfig.require('BOUNDLESS_MARKET_ADDR');
    const ipfsGateway = baseConfig.require('IPFS_GATEWAY_URL');
    const baseStackName = baseConfig.require('BASE_STACK');
    const baseStack = new pulumi.StackReference(baseStackName);
    const vpcId = baseStack.getOutput('VPC_ID') as pulumi.Output<string>;
    const privateSubnetIds = baseStack.getOutput('PRIVATE_SUBNET_IDS') as pulumi.Output<string[]>;
    const boundlessAlertsTopicArn = baseConfig.get('SLACK_ALERTS_TOPIC_ARN');
    const boundlessPagerdutyTopicArn = baseConfig.get('PAGERDUTY_ALERTS_TOPIC_ARN');
    const alertsTopicArns = [boundlessAlertsTopicArn, boundlessPagerdutyTopicArn].filter(Boolean) as string[];
    const interval = baseConfig.require('INTERVAL');
    const lockStakeRaw = baseConfig.require('LOCK_STAKE_RAW');
    const minPricePerMCycle = baseConfig.require('MIN_PRICE_PER_MCYCLE');
    const maxPricePerMCycle = baseConfig.require('MAX_PRICE_PER_MCYCLE');
    const txTimeout = baseConfig.require('TX_TIMEOUT');

    // Kailua-specific configuration
    const kailuaDevnetUrl = baseConfig.get('KAILUA_DEVNET_URL');
    const l1Url = baseConfig.get('KAILUA_L1_URL');
    const l2Url = baseConfig.get('KAILUA_L2_URL');
    const dataDir = baseConfig.get('KAILUA_DATA_DIR');
    const release = baseConfig.get('KAILUA_RELEASE');
    const numConcurrentProvers = baseConfig.get('NUM_CONCURRENT_PROVERS');
    const numConcurrentProofs = baseConfig.get('NUM_CONCURRENT_PROOFS');
    const skipAwaitProof = baseConfig.get('SKIP_AWAIT_PROOF');
    const skipDerivationProof = baseConfig.get('SKIP_DERIVATION_PROOF');
    const nthProofToProcess = baseConfig.get('NTH_PROOF_TO_PROCESS');
    const enableExperimentalWitnessEndpoint = baseConfig.get('ENABLE_EXPERIMENTAL_WITNESS_ENDPOINT');
    const lookBack = baseConfig.get('BOUNDLESS_LOOK_BACK');
    const orderBidDelayFactor = baseConfig.get('BOUNDLESS_ORDER_BID_DELAY_FACTOR');
    const orderRampUpFactor = baseConfig.get('BOUNDLESS_ORDER_RAMP_UP_FACTOR');
    const orderLockTimeoutFactor = baseConfig.get('BOUNDLESS_ORDER_LOCK_TIMEOUT_FACTOR');
    const orderExpiryFactor = baseConfig.get('BOUNDLESS_ORDER_EXPIRY_FACTOR');
    const megaCycleStake = baseConfig.get('BOUNDLESS_MEGA_CYCLE_STAKE');
    const cycleMaxWei = baseConfig.get('BOUNDLESS_CYCLE_MAX_WEI');
    const rustBacktrace = baseConfig.get('RUST_BACKTRACE');
    const risc0Info = baseConfig.get('RISC0_INFO');
    const storageProvider = baseConfig.get('STORAGE_PROVIDER');

    const imageName = getServiceNameV1(stackName, 'kailua-order-generator');
    const repo = new awsx.ecr.Repository(`${imageName}-repo`, {
        forceDelete: true,
        lifecyclePolicy: {
            rules: [
                {
                    description: 'Delete untagged images after N days',
                    tagStatus: 'untagged',
                    maximumAgeLimit: 7,
                },
            ],
        },
    });

    const authToken = aws.ecr.getAuthorizationTokenOutput({
        registryId: repo.repository.registryId,
    });

    let buildSecrets = {};
    if (githubTokenSecret !== undefined) {
        buildSecrets = {
            ...buildSecrets,
            githubTokenSecret
        }
    }

    const dockerTagPath = pulumi.interpolate`${repo.repository.repositoryUrl}:${dockerTag}`;

    const image = new docker_build.Image(`${imageName}-image`, {
        tags: [dockerTagPath],
        context: {
            location: dockerDir,
        },
        builder: dockerRemoteBuilder ? {
            name: dockerRemoteBuilder,
        } : undefined,
        platforms: ['linux/amd64'],
        push: true,
        dockerfile: {
            location: `${dockerDir}/dockerfiles/kailua-cli.dockerfile`,
        },
        secrets: buildSecrets,
        cacheFrom: [
            {
                registry: {
                    ref: pulumi.interpolate`${repo.repository.repositoryUrl}:cache`,
                },
            },
        ],
        cacheTo: [
            {
                registry: {
                    mode: docker_build.CacheMode.Max,
                    imageManifest: true,
                    ociMediaTypes: true,
                    ref: pulumi.interpolate`${repo.repository.repositoryUrl}:cache`,
                },
            },
        ],
        registries: [
            {
                address: repo.repository.repositoryUrl,
                password: authToken.password,
                username: authToken.userName,
            },
        ],
    });

    const offchainConfig = new pulumi.Config("kailua-order-generator-offchain");
    const autoDeposit = offchainConfig.require('AUTO_DEPOSIT');
    const offchainWarnBalanceBelow = offchainConfig.get('WARN_BALANCE_BELOW');
    const offchainErrorBalanceBelow = offchainConfig.get('ERROR_BALANCE_BELOW');
    const offchainInputMaxMCycles = offchainConfig.get('INPUT_MAX_MCYCLES');
    const offchainRampUp = offchainConfig.get('RAMP_UP');
    const offchainLockTimeout = offchainConfig.get('LOCK_TIMEOUT');
    const offchainTimeout = offchainConfig.get('TIMEOUT');
    const offchainSecondsPerMCycle = offchainConfig.get('SECONDS_PER_MCYCLE');
    const offchainInterval = offchainConfig.get('INTERVAL');

    new OrderGenerator('optimism', {
        chainId,
        stackName,
        privateKey: boundlessWalletKey.apply(key => key),
        pinataJWT: pinataJWT.apply(jwt => jwt),
        ethRpcUrl: ethRpcUrl.apply(url => url),
        boundlessRpcUrl: boundlessRpcUrl.apply(url => url),
        warnBalanceBelow: offchainWarnBalanceBelow,
        errorBalanceBelow: offchainErrorBalanceBelow,
        offchainConfig: {
            autoDeposit,
            orderStreamUrl: boundlessOrderStreamUrl,
        },
        image,
        logLevel,
        setVerifierAddr,
        boundlessMarketAddr,
        ipfsGateway,
        interval: offchainInterval ?? interval,
        lockStakeRaw,
        minPricePerMCycle,
        maxPricePerMCycle,
        vpcId,
        privateSubnetIds,
        boundlessAlertsTopicArns: alertsTopicArns,
        txTimeout,
        inputMaxMCycles: offchainInputMaxMCycles,
        rampUp: offchainRampUp,
        lockTimeout: offchainLockTimeout,
        timeout: offchainTimeout,
        secondsPerMCycle: offchainSecondsPerMCycle,
        // Kailua-specific configuration
        kailuaDevnetUrl,
        l1Url,
        l2Url,
        dataDir,
        release,
        numConcurrentProvers,
        numConcurrentProofs,
        skipAwaitProof,
        skipDerivationProof,
        nthProofToProcess,
        enableExperimentalWitnessEndpoint,
        lookBack,
        orderBidDelayFactor,
        orderRampUpFactor,
        orderLockTimeoutFactor,
        orderExpiryFactor,
        megaCycleStake,
        cycleMaxWei,
        rustBacktrace,
        risc0Info,
        storageProvider,
    });

    // Add unichain service
    const unichainConfig = new pulumi.Config("kailua-order-generator-unichain");
    const unichainL1Url = unichainConfig.get('KAILUA_L1_URL');
    const unichainL2Url = unichainConfig.get('KAILUA_L2_URL');
    const unichainDataDir = unichainConfig.get('KAILUA_DATA_DIR');
    const unichainNthProofToProcess = unichainConfig.get('NTH_PROOF_TO_PROCESS');
    const unichainNumConcurrentProvers = unichainConfig.get('NUM_CONCURRENT_PROVERS');
    const unichainNumConcurrentProofs = unichainConfig.get('NUM_CONCURRENT_PROOFS');
    const unichainSkipAwaitProof = unichainConfig.get('SKIP_AWAIT_PROOF');
    const unichainSkipDerivationProof = unichainConfig.get('SKIP_DERIVATION_PROOF');
    const unichainEnableExperimentalWitnessEndpoint = unichainConfig.get('ENABLE_EXPERIMENTAL_WITNESS_ENDPOINT');
    const unichainStorageProvider = unichainConfig.get('STORAGE_PROVIDER');
    const unichainLookBack = unichainConfig.get('BOUNDLESS_LOOK_BACK');
    const unichainOrderBidDelayFactor = unichainConfig.get('BOUNDLESS_ORDER_BID_DELAY_FACTOR');
    const unichainOrderRampUpFactor = unichainConfig.get('BOUNDLESS_ORDER_RAMP_UP_FACTOR');
    const unichainOrderLockTimeoutFactor = unichainConfig.get('BOUNDLESS_ORDER_LOCK_TIMEOUT_FACTOR');
    const unichainOrderExpiryFactor = unichainConfig.get('BOUNDLESS_ORDER_EXPIRY_FACTOR');
    const unichainMegaCycleStake = unichainConfig.get('BOUNDLESS_MEGA_CYCLE_STAKE');
    const unichainCycleMaxWei = unichainConfig.get('BOUNDLESS_CYCLE_MAX_WEI');
    const unichainRustBacktrace = unichainConfig.get('RUST_BACKTRACE');
    const unichainRisc0Info = unichainConfig.get('RISC0_INFO');
    const unichainPinataJWT = unichainConfig.requireSecret('PINATA_JWT');
    const unichainEthRpcUrl = unichainConfig.requireSecret('ETH_RPC_URL');
    const unichainOrderStreamUrl = unichainConfig.getSecret('ORDER_STREAM_URL') || pulumi.output("none");
    const unichainBoundlessWalletKey = unichainConfig.requireSecret('BOUNDLESS_WALLET_KEY');
    const unichainBoundlessRpcUrl = unichainConfig.requireSecret('BOUNDLESS_RPC_URL');
    const unichainBoundlessOrderStreamUrl = unichainConfig.getSecret('BOUNDLESS_ORDER_STREAM_URL') || pulumi.output("none");

    new OrderGenerator('unichain', {
        chainId,
        stackName,
        privateKey: unichainBoundlessWalletKey.apply(key => key),
        pinataJWT: unichainPinataJWT.apply(jwt => jwt),
        ethRpcUrl: unichainEthRpcUrl.apply(url => url),
        boundlessRpcUrl: unichainBoundlessRpcUrl.apply(url => url),
        warnBalanceBelow: offchainWarnBalanceBelow,
        errorBalanceBelow: offchainErrorBalanceBelow,
        offchainConfig: {
            autoDeposit,
            orderStreamUrl: unichainBoundlessOrderStreamUrl,
        },
        image,
        logLevel,
        setVerifierAddr,
        boundlessMarketAddr,
        ipfsGateway,
        interval: offchainInterval ?? interval,
        lockStakeRaw,
        minPricePerMCycle,
        maxPricePerMCycle,
        vpcId,
        privateSubnetIds,
        boundlessAlertsTopicArns: alertsTopicArns,
        txTimeout,
        inputMaxMCycles: offchainInputMaxMCycles,
        rampUp: offchainRampUp,
        lockTimeout: offchainLockTimeout,
        timeout: offchainTimeout,
        secondsPerMCycle: offchainSecondsPerMCycle,
        // Kailua-specific configuration for unichain
        kailuaDevnetUrl,
        l1Url: unichainL1Url,
        l2Url: unichainL2Url,
        dataDir: unichainDataDir,
        release,
        numConcurrentProvers: unichainNumConcurrentProvers,
        numConcurrentProofs: unichainNumConcurrentProofs,
        skipAwaitProof: unichainSkipAwaitProof,
        skipDerivationProof: unichainSkipDerivationProof,
        nthProofToProcess: unichainNthProofToProcess,
        enableExperimentalWitnessEndpoint: unichainEnableExperimentalWitnessEndpoint,
        lookBack: unichainLookBack,
        orderBidDelayFactor: unichainOrderBidDelayFactor,
        orderRampUpFactor: unichainOrderRampUpFactor,
        orderLockTimeoutFactor: unichainOrderLockTimeoutFactor,
        orderExpiryFactor: unichainOrderExpiryFactor,
        megaCycleStake: unichainMegaCycleStake,
        cycleMaxWei: unichainCycleMaxWei,
        rustBacktrace: unichainRustBacktrace,
        risc0Info: unichainRisc0Info,
        storageProvider: unichainStorageProvider,
    });
};
