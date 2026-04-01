import { App } from "aws-cdk-lib";
import { WitnessStack } from "./witness-stack.ts";

const app = new App();

new WitnessStack(app, "keri-witness-dev", {});
