import * as crypto from 'crypto';
import * as aws from '@pulumi/aws';
import * as awsx from '@pulumi/awsx';
import type { Image } from '@pulumi/docker-build';
import * as pulumi from '@pulumi/pulumi';
import { Severity, getServiceNameV1 } from '../../util';

interface OrderGeneratorArgs {
  chainId: string;
  stackName: string;
  privateKey: pulumi.Output<string>;
  pinataJWT: pulumi.Output<string>;
  ethRpcUrl: pulumi.Output<string>;
  boundlessRpcUrl: pulumi.Output<string>;
  image: Image;
  logLevel: string;
  setVerifierAddr: string;
  boundlessMarketAddr: string;
  ipfsGateway: string;
  interval: string;
  lockStakeRaw: string;
  rampUp?: string;
  minPricePerMCycle: string;
  maxPricePerMCycle: string;
  secondsPerMCycle?: string;
  inputMaxMCycles?: string;
  vpcId: pulumi.Output<string>;
  privateSubnetIds: pulumi.Output<string[]>;
  boundlessAlertsTopicArns?: string[];
  offchainConfig?: {
    autoDeposit: string;
    orderStreamUrl: pulumi.Output<string>;
  };
  warnBalanceBelow?: string;
  errorBalanceBelow?: string;
  txTimeout: string;
  lockTimeout?: string;
  timeout?: string;
  // Kailua-specific configuration (passed as command-line arguments)
  kailuaDevnetUrl?: string;
  l1Url?: string;
  l2Url?: string;
  dataDir?: string;
  release?: string;
  numBlocksPerProof?: string;
  numConcurrentProvers?: string;
  numConcurrentProofs?: string;
  skipAwaitProof?: string;
  skipDerivationProof?: string;
  nthProofToProcess?: string;
  enableExperimentalWitnessEndpoint?: string;
  lookBack?: string;
  orderBidDelayFactor?: string;
  orderRampUpFactor?: string;
  orderLockTimeoutFactor?: string;
  orderExpiryFactor?: string;
  megaCycleStake?: string;
  cycleMaxWei?: string;
  rustBacktrace?: string;
  risc0Info?: string;
  storageProvider?: string;
}

export class OrderGenerator extends pulumi.ComponentResource {
  constructor(name: string, args: OrderGeneratorArgs, opts?: pulumi.ComponentResourceOptions) {
    super(`boundless:kailua-order-generator:${name}`, name, args, opts);

    const serviceName = getServiceNameV1(args.stackName, `kailua-og-${name}`, args.chainId);
    const isStaging = args.stackName.includes('staging');

    const offchainConfig = args.offchainConfig;

    const privateKeySecret = new aws.secretsmanager.Secret(`${serviceName}-private-key`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-private-key-v1`, {
      secretId: privateKeySecret.id,
      secretString: args.privateKey,
    });

    const pinataJwtSecret = new aws.secretsmanager.Secret(`${serviceName}-pinata-jwt`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-pinata-jwt-v1`, {
      secretId: pinataJwtSecret.id,
      secretString: args.pinataJWT,
    });

    const rpcUrlSecret = new aws.secretsmanager.Secret(`${serviceName}-rpc-url`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-rpc-url`, {
      secretId: rpcUrlSecret.id,
      secretString: args.ethRpcUrl,
    });

    const orderStreamUrlSecret = new aws.secretsmanager.Secret(`${serviceName}-order-stream-url`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-order-stream-url`, {
      secretId: orderStreamUrlSecret.id,
      secretString: offchainConfig?.orderStreamUrl ?? 'none',
    });

    const boundlessWalletKeySecret = new aws.secretsmanager.Secret(`${serviceName}-boundless-wallet-key`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-boundless-wallet-key-v1`, {
      secretId: boundlessWalletKeySecret.id,
      secretString: args.privateKey,
    });

    const boundlessRpcUrlSecret = new aws.secretsmanager.Secret(`${serviceName}-boundless-rpc-url`);
    new aws.secretsmanager.SecretVersion(`${serviceName}-boundless-rpc-url-v1`, {
      secretId: boundlessRpcUrlSecret.id,
      secretString: args.boundlessRpcUrl,
    });

    const secretHash = pulumi
      .all([args.ethRpcUrl, args.privateKey, offchainConfig?.orderStreamUrl])
      .apply(([_ethRpcUrl, _privateKey, _orderStreamUrl]: [string, string, string | undefined]) => {
        const hash = crypto.createHash("sha1");
        hash.update(_ethRpcUrl);
        hash.update(_privateKey);
        hash.update(_orderStreamUrl ?? '');
        return hash.digest("hex");
      });

    const securityGroup = new aws.ec2.SecurityGroup(`${serviceName}-security-group`, {
      name: serviceName,
      vpcId: args.vpcId,
      egress: [
        {
          fromPort: 0,
          toPort: 0,
          protocol: '-1',
          cidrBlocks: ['0.0.0.0/0'],
          ipv6CidrBlocks: ['::/0'],
        },
      ],
    });

    const execRole = new aws.iam.Role(`${serviceName}-exec`, {
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: 'ecs-tasks.amazonaws.com',
      }),
      managedPolicyArns: [aws.iam.ManagedPolicy.AmazonECSTaskExecutionRolePolicy],
    });

    const execRolePolicy = new aws.iam.RolePolicy(`${serviceName}-exec`, {
      role: execRole.id,
      policy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['secretsmanager:GetSecretValue', 'ssm:GetParameters'],
            Resource: [privateKeySecret.arn, pinataJwtSecret.arn, rpcUrlSecret.arn, orderStreamUrlSecret.arn, boundlessWalletKeySecret.arn, boundlessRpcUrlSecret.arn],
          },
        ],
      },
    });

    // Helper function to build Boundless environment variables
    const buildBoundlessEnvironment = (args: OrderGeneratorArgs) => [
      { name: 'BOUNDLESS_LOOK_BACK', value: args.lookBack || 'true' },
      { name: 'BOUNDLESS_ORDER_BID_DELAY_FACTOR', value: args.orderBidDelayFactor || '0.1' },
      { name: 'BOUNDLESS_ORDER_RAMP_UP_FACTOR', value: args.orderRampUpFactor || '0.2' },
      { name: 'BOUNDLESS_ORDER_LOCK_TIMEOUT_FACTOR', value: args.orderLockTimeoutFactor || '0.2' },
      { name: 'BOUNDLESS_ORDER_EXPIRY_FACTOR', value: args.orderExpiryFactor || '1' },
      { name: 'BOUNDLESS_MEGA_CYCLE_STAKE', value: args.megaCycleStake || '1500' },
      { name: 'BOUNDLESS_CYCLE_MAX_WEI', value: args.cycleMaxWei || '65000' },
    ];

    const environment = [
      {
        name: 'RUST_LOG',
        value: args.logLevel,
      },
      { name: 'NO_COLOR', value: '1' },
      { name: 'SECRET_HASH', value: secretHash },
      // Performance and proving configuration
      { name: 'NUM_CONCURRENT_PROVERS', value: args.numConcurrentProvers || '8' },
      { name: 'NUM_CONCURRENT_PROOFS', value: args.numConcurrentProofs || '1' },
      { name: 'SKIP_AWAIT_PROOF', value: args.skipAwaitProof || 'true' },
      { name: 'SKIP_DERIVATION_PROOF', value: args.skipDerivationProof || 'true' },
      { name: 'NTH_PROOF_TO_PROCESS', value: args.nthProofToProcess || '10' },
      { name: 'ENABLE_EXPERIMENTAL_WITNESS_ENDPOINT', value: args.enableExperimentalWitnessEndpoint || 'true' },
      // Debug and logging configuration
      { name: 'RUST_BACKTRACE', value: args.rustBacktrace || 'full' },
      { name: 'RISC0_INFO', value: args.risc0Info || '1' },
      // Storage provider configuration
      { name: 'STORAGE_PROVIDER', value: args.storageProvider || 'pinata' },
      // Boundless market configuration (using helper function)
      ...buildBoundlessEnvironment(args),
    ]

    const secrets = [
      {
        name: 'RPC_URL',
        valueFrom: rpcUrlSecret.arn,
      },
      {
        name: 'PRIVATE_KEY',
        valueFrom: privateKeySecret.arn,
      },
      {
        name: 'PINATA_JWT',
        valueFrom: pinataJwtSecret.arn,
      },
      {
        name: 'BOUNDLESS_WALLET_KEY',
        valueFrom: boundlessWalletKeySecret.arn,
      },
      {
        name: 'BOUNDLESS_RPC_URL',
        valueFrom: boundlessRpcUrlSecret.arn,
      },
      {
        name: 'BOUNDLESS_ORDER_STREAM_URL',
        valueFrom: orderStreamUrlSecret.arn,
      },
    ];

    // Add kailua-specific configuration if needed
    if (offchainConfig) {
      environment.push({
        name: 'KAILUA_VALIDATOR_MODE',
        value: 'true',
      });
    }

    const cluster = new aws.ecs.Cluster(`${serviceName}-cluster`, { name: serviceName });

    const kailuaArgs = [
      'demo',
      '--eth-rpc-url', args.l1Url,
      '--beacon-rpc-url', args.l1Url,
      '--op-geth-url', args.l2Url,
      '--op-node-url', args.l2Url,
      '--data-dir', args.dataDir,
      '--num-blocks-per-proof', args.numBlocksPerProof || '25',
    ];

    const service = new awsx.ecs.FargateService(
      `${serviceName}-service`,
      {
        name: serviceName,
        cluster: cluster.arn,
        networkConfiguration: {
          securityGroups: [securityGroup.id],
          subnets: args.privateSubnetIds,
        },
        taskDefinitionArgs: {
          logGroup: {
            args: { name: serviceName, retentionInDays: 0 },
          },
          executionRole: {
            roleArn: execRole.arn,
          },
          container: {
            name: serviceName,
            image: args.image.ref,
            cpu: 2048,
            memory: 4096,
            essential: true,
            entryPoint: ['/bin/sh', '-c'],
            command: [
              `/app/kailua-cli ${kailuaArgs.join(' ')}`,
            ],
            environment,
            secrets,
          },
        },
      },
      { dependsOn: [execRole, execRolePolicy] }
    );

    // ECS Service Alarms
    const alarmActions = args.boundlessAlertsTopicArns ?? [];

    // Container restart alarm - SEV2 if 2 restarts in 5 minutes
    new aws.cloudwatch.MetricAlarm(`${serviceName}-container-restart-alarm-${Severity.SEV2}`, {
      name: `${serviceName}-container-restart-${Severity.SEV2}`,
      metricQueries: [
        {
          id: 'm1',
          metric: {
            namespace: 'AWS/ECS',
            metricName: 'RunningTaskCount',
            dimensions: {
              ServiceName: serviceName,
              ClusterName: serviceName,
            },
            period: 60,
            stat: 'Average',
          },
          returnData: true,
        },
      ],
      threshold: 0,
      comparisonOperator: 'LessThanThreshold',
      evaluationPeriods: 5,
      datapointsToAlarm: 2,
      treatMissingData: 'notBreaching',
      alarmDescription: `${serviceName} container restarted 2 times within 5 minutes`,
      actionsEnabled: true,
      alarmActions,
    });

    // Memory utilization alarm - SEV2 if >80% for 5 minutes
    new aws.cloudwatch.MetricAlarm(`${serviceName}-memory-utilization-alarm-${Severity.SEV2}`, {
      name: `${serviceName}-memory-utilization-${Severity.SEV2}`,
      metricQueries: [
        {
          id: 'm1',
          metric: {
            namespace: 'AWS/ECS',
            metricName: 'MemoryUtilization',
            dimensions: {
              ServiceName: serviceName,
              ClusterName: serviceName,
            },
            period: 60,
            stat: 'Average',
          },
          returnData: true,
        },
      ],
      threshold: 80,
      comparisonOperator: 'GreaterThanThreshold',
      evaluationPeriods: 5,
      datapointsToAlarm: 3,
      treatMissingData: 'notBreaching',
      alarmDescription: `${serviceName} memory utilization >80% for 5 minutes`,
      actionsEnabled: true,
      alarmActions,
    });

    // CPU utilization alarm - SEV2 if >90% for 5 minutes
    new aws.cloudwatch.MetricAlarm(`${serviceName}-cpu-utilization-alarm-${Severity.SEV2}`, {
      name: `${serviceName}-cpu-utilization-${Severity.SEV2}`,
      metricQueries: [
        {
          id: 'm1',
          metric: {
            namespace: 'AWS/ECS',
            metricName: 'CPUUtilization',
            dimensions: {
              ServiceName: serviceName,
              ClusterName: serviceName,
            },
            period: 60,
            stat: 'Average',
          },
          returnData: true,
        },
      ],
      threshold: 90,
      comparisonOperator: 'GreaterThanThreshold',
      evaluationPeriods: 5,
      datapointsToAlarm: 3,
      treatMissingData: 'notBreaching',
      alarmDescription: `${serviceName} CPU utilization >90% for 5 minutes`,
      actionsEnabled: true,
      alarmActions,
    });

    // Service unavailable alarm - SEV1 if no running tasks for 2 minutes
    if (!isStaging) {
      new aws.cloudwatch.MetricAlarm(`${serviceName}-service-unavailable-alarm-${Severity.SEV1}`, {
        name: `${serviceName}-service-unavailable-${Severity.SEV1}`,
        metricQueries: [
          {
            id: 'm1',
            metric: {
              namespace: 'AWS/ECS',
              metricName: 'RunningTaskCount',
              dimensions: {
                ServiceName: serviceName,
                ClusterName: serviceName,
              },
              period: 60,
              stat: 'Average',
            },
            returnData: true,
          },
        ],
        threshold: 0,
        comparisonOperator: 'LessThanOrEqualToThreshold',
        evaluationPeriods: 2,
        datapointsToAlarm: 2,
        treatMissingData: 'notBreaching',
        alarmDescription: `${serviceName} service unavailable (no running tasks)`,
        actionsEnabled: true,
        alarmActions,
      });
    }

    // Memory utilization critical alarm - SEV1 if >95% for 3 minutes
    if (!isStaging) {
      new aws.cloudwatch.MetricAlarm(`${serviceName}-memory-critical-alarm-${Severity.SEV1}`, {
        name: `${serviceName}-memory-critical-${Severity.SEV1}`,
        metricQueries: [
          {
            id: 'm1',
            metric: {
              namespace: 'AWS/ECS',
              metricName: 'MemoryUtilization',
              dimensions: {
                ServiceName: serviceName,
                ClusterName: serviceName,
              },
              period: 60,
              stat: 'Average',
            },
            returnData: true,
          },
        ],
        threshold: 95,
        comparisonOperator: 'GreaterThanThreshold',
        evaluationPeriods: 3,
        datapointsToAlarm: 3,
        treatMissingData: 'notBreaching',
        alarmDescription: `${serviceName} memory utilization >95% for 3 minutes`,
        actionsEnabled: true,
        alarmActions,
      });
    }

    // CPU utilization critical alarm - SEV1 if >95% for 3 minutes
    if (!isStaging) {
      new aws.cloudwatch.MetricAlarm(`${serviceName}-cpu-critical-alarm-${Severity.SEV1}`, {
        name: `${serviceName}-cpu-critical-${Severity.SEV1}`,
        metricQueries: [
          {
            id: 'm1',
            metric: {
              namespace: 'AWS/ECS',
              metricName: 'CPUUtilization',
              dimensions: {
                ServiceName: serviceName,
                ClusterName: serviceName,
              },
              period: 60,
              stat: 'Average',
            },
            returnData: true,
          },
        ],
        threshold: 95,
        comparisonOperator: 'GreaterThanThreshold',
        evaluationPeriods: 3,
        datapointsToAlarm: 3,
        treatMissingData: 'notBreaching',
        alarmDescription: `${serviceName} CPU utilization >95% for 3 minutes`,
        actionsEnabled: true,
        alarmActions,
      });
    }

    // Network errors alarm - SEV2 if network errors detected
    new aws.cloudwatch.MetricAlarm(`${serviceName}-network-errors-alarm-${Severity.SEV2}`, {
      name: `${serviceName}-network-errors-${Severity.SEV2}`,
      metricQueries: [
        {
          id: 'm1',
          metric: {
            namespace: 'AWS/ECS',
            metricName: 'NetworkRxDropped',
            dimensions: {
              ServiceName: serviceName,
              ClusterName: serviceName,
            },
            period: 60,
            stat: 'Sum',
          },
          returnData: true,
        },
      ],
      threshold: 1,
      comparisonOperator: 'GreaterThanThreshold',
      evaluationPeriods: 3,
      datapointsToAlarm: 2,
      treatMissingData: 'notBreaching',
      alarmDescription: `${serviceName} network errors detected`,
      actionsEnabled: true,
      alarmActions,
    });
  }
}
