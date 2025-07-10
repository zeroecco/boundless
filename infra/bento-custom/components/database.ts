import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export async function setupDatabase(
    name: string,
    network: any,
    tags: Record<string, string>
) {
    // Create subnet group for RDS
    const dbSubnetGroup = new aws.rds.SubnetGroup(`${name}-db-subnet-group`, {
        subnetIds: network.privateSubnetIds,
        description: "Subnet group for Bento PostgreSQL",
        tags: {
            ...tags,
            Name: `${name}-db-subnet-group`,
        },
    });

    // Create PostgreSQL instance
    const database = new aws.rds.Instance(`${name}-postgres`, {
        identifier: `${name}-postgres`,
        engine: "postgres",
        engineVersion: "15.13",
        instanceClass: "db.t4g.micro",
        allocatedStorage: 20,
        storageType: "gp3",
        storageEncrypted: true,

        dbName: "taskdb",
        username: "worker",
        manageMasterUserPassword: true,

        vpcSecurityGroupIds: [network.databaseSecurityGroup.id],
        dbSubnetGroupName: dbSubnetGroup.name,

        skipFinalSnapshot: true, // Set to false in production
        deletionProtection: false, // Set to true in production

        backupRetentionPeriod: 7,
        backupWindow: "03:00-04:00",
        maintenanceWindow: "sun:04:00-sun:05:00",

        enabledCloudwatchLogsExports: ["postgresql"],

        tags: {
            ...tags,
            Name: `${name}-postgres`,
        },
    });

    // Create RDS Proxy for better connection management
    const rdsProxy = new aws.rds.Proxy(`${name}-rds-proxy`, {
        name: `${name}-rds-proxy`,
        engineFamily: "POSTGRESQL",
        roleArn: network.rdsProxyRole.arn,
        vpcSubnetIds: network.privateSubnetIds,
        vpcSecurityGroupIds: [network.rdsProxySecurityGroup.id],

        // Authentication will be set up via target group
        auths: [{
            authScheme: "SECRETS",
            // Use the master user password from RDS
            secretArn: database.masterUserSecrets.apply((secrets: any) => secrets[0].secretArn),
        }],

        // Don't require TLS for internal communication
        requireTls: false,

        tags: {
            ...tags,
            Name: `${name}-rds-proxy`,
        },
    });

    // Create proxy target group
    const proxyTargetGroup = new aws.rds.ProxyDefaultTargetGroup(`${name}-proxy-target-group`, {
        dbProxyName: rdsProxy.name,
        connectionPoolConfig: {
            maxConnectionsPercent: 100,
            maxIdleConnectionsPercent: 10,
            connectionBorrowTimeout: 120,
        },
    });

    // Add the database instance as a target
    const proxyTarget = new aws.rds.ProxyTarget(`${name}-proxy-target`, {
        dbProxyName: rdsProxy.name,
        targetGroupName: proxyTargetGroup.name,
        dbInstanceIdentifier: database.identifier,
    });

    // Get the database password from AWS Secrets Manager
    const dbSecret = database.masterUserSecrets.apply((secrets: any) => secrets[0].secretArn);
    const secretValue = dbSecret.apply(async (arn: string) => {
        const secret = await aws.secretsmanager.getSecretVersion({
            secretId: arn,
        });
        return JSON.parse(secret.secretString);
    });

    return {
        instance: database,
        proxy: rdsProxy,
        endpoint: database.endpoint,
        proxyEndpoint: rdsProxy.endpoint,
        // Use RDS proxy connection with password from secrets
        connectionUrl: pulumi.all([secretValue, rdsProxy.endpoint]).apply(([secret, endpoint]) => {
            // URL encode the password to handle special characters
            const encodedPassword = encodeURIComponent(secret.password);
            // Ensure endpoint includes port - proxy endpoints might not include :5432
            const host = endpoint.includes(':') ? endpoint : `${endpoint}:5432`;
            return `postgresql://worker:${encodedPassword}@${host}/taskdb`;
        }),
    };
}