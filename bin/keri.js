#!/usr/bin/env node
import { register } from "tsx/esm/api";
register();
await import("../src/keri.ts");
