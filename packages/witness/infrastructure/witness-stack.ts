import { type App, CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { HttpApi, HttpRoute, HttpRouteKey } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { AttributeType, Table } from "aws-cdk-lib/aws-dynamodb";
import { LoggingFormat, Runtime } from "aws-cdk-lib/aws-lambda";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";

export class WitnessStack extends Stack {
  constructor(scope: App, id: string, props: StackProps) {
    super(scope, id, props);

    const table = new Table(this, "Events", {
      tableName: "events",
      partitionKey: { name: "PK", type: AttributeType.STRING },
      sortKey: { name: "SK", type: AttributeType.STRING },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const api = new HttpApi(this, "Api", {});
    const logGroup = new LogGroup(this, "LogGroup", {
      retention: RetentionDays.ONE_WEEK,
    });

    const fn = new NodejsFunction(this, "Function", {
      entry: "scripts/lambda.ts",
      runtime: Runtime.NODEJS_22_X,
      loggingFormat: LoggingFormat.JSON,
      logGroup,
      environment: {
        DYNAMODB_TABLE_NAME: table.tableName,
        WITNESS_URL: api.apiEndpoint,
      },
    });

    table.grantReadWriteData(fn);

    const integration = new HttpLambdaIntegration("Integration", fn, {});

    new HttpRoute(this, "DefaultRoute", {
      httpApi: api,
      integration,
      routeKey: HttpRouteKey.DEFAULT,
    });

    new CfnOutput(this, "ApiUrl", { value: api.apiEndpoint });
  }
}
