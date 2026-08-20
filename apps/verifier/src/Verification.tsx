import { Alert } from "@mantine/core";
import type { CredentialVerification } from "keri";
import { collect, verify as verifyStream } from "keri";
import { useCallback, useState } from "react";
import { CredentialResult } from "./CredentialResult.tsx";

export type VerificationState =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "done"; results: CredentialVerification[] };

export interface Verification {
  state: VerificationState;
  verify: (input: Uint8Array | string) => Promise<void>;
  /** Drops the current verdict, so the next input never renders under the previous one's result. */
  reset: () => void;
}

/**
 * One verification and its result. Each way of bringing a credential in holds its own, so a verdict
 * never outlives the input that produced it or turns up under a different one.
 */
export function useVerification(): Verification {
  const [state, setState] = useState<VerificationState>({ kind: "idle" });

  const verify = useCallback(async (input: Uint8Array | string) => {
    try {
      setState({ kind: "done", results: verifyStream(await collect(input)).credentials });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }, []);

  const reset = useCallback(() => {
    setState({ kind: "idle" });
  }, []);

  return { state, verify, reset };
}

export function VerificationResult({ state, viewer }: { state: VerificationState; viewer?: string }) {
  if (state.kind === "error") {
    return <Alert>Could not read the stream: {state.message}</Alert>;
  }

  if (state.kind === "idle") {
    return null;
  }

  if (state.results.length === 0) {
    return <Alert>No credential found in that stream.</Alert>;
  }

  return state.results.map((result) => <CredentialResult key={result.said} result={result} viewer={viewer} />);
}
