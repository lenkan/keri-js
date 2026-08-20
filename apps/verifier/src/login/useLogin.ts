import { useCallback, useEffect, useRef, useState } from "react";

const POLL_MS = 2000;
const STORAGE_KEY = "keri-login-token";

export interface Identity {
  aid: string;
  sequenceNumber: number;
  signingKeys: string[];
  signingThreshold: string | string[];
  witnesses: string[];
  lastEstablishment: { s: string; d: string };
  authenticatedAt: string;
}

export type LoginPhase =
  | { kind: "resuming"; token: string }
  | { kind: "error"; message: string }
  | { kind: "supply-kel"; token: string }
  | { kind: "challenged"; token: string; aid: string; words: string[]; lastError?: string }
  | { kind: "authenticated"; identity: Identity };

interface LoginStatus {
  phase: "challenged" | "authenticated";
  aid?: string;
  words?: string[];
  error?: string;
  identity?: Identity;
}

export interface Login {
  phase: LoginPhase;
  /** Logs out / starts over: forgets the stored session and mints a fresh one. */
  restart: () => void;
  /** Submits an OOBI URL for the pull path; resolves to an error message, or null on success. */
  submitOobi: (url: string) => Promise<string | null>;
}

/**
 * The login lifecycle, from minting a session to holding an authenticated
 * identity. The token lives in sessionStorage so a reload resumes where the
 * wizard left off — per tab, and no longer than the server's session TTL.
 */
export function useLogin(): Login {
  const [phase, setPhase] = useState<LoginPhase>(() => {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    return stored ? { kind: "resuming", token: stored } : { kind: "resuming", token: "" };
  });
  const started = useRef(false);

  const start = useCallback(async () => {
    sessionStorage.removeItem(STORAGE_KEY);

    try {
      const response = await fetch("/api/login/sessions", { method: "POST" });
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      const { token } = (await response.json()) as { token: string };
      sessionStorage.setItem(STORAGE_KEY, token);
      setPhase({ kind: "supply-kel", token });
    } catch (cause) {
      setPhase({ kind: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }, []);

  useEffect(() => {
    if (started.current) {
      return;
    }
    started.current = true;

    if (phase.kind === "resuming" && !phase.token) {
      void start();
    }
  }, [phase, start]);

  const token =
    phase.kind === "supply-kel" || phase.kind === "challenged" || (phase.kind === "resuming" && phase.token)
      ? phase.token
      : null;

  useEffect(() => {
    if (!token) {
      return;
    }

    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const response = await fetch(`/api/login/sessions/${token}`, { signal: controller.signal });

        if (response.status === 200) {
          const status = (await response.json()) as LoginStatus;

          if (status.phase === "authenticated" && status.identity) {
            setPhase({ kind: "authenticated", identity: status.identity });
            return;
          }

          if (status.phase === "challenged" && status.aid && status.words) {
            const { aid, words, error } = status;
            // Keep polling, but only re-render when the server actually moved.
            setPhase((current) =>
              current.kind === "challenged" &&
              current.aid === aid &&
              current.words.join(" ") === words.join(" ") &&
              current.lastError === error
                ? current
                : { kind: "challenged", token: token as string, aid, words, lastError: error },
            );
          }
        } else if (response.status === 204) {
          // Nothing submitted yet — a resumed token lands here when its record
          // expired, and the token itself is still fine to reuse.
          setPhase((current) =>
            current.kind === "resuming" ? { kind: "supply-kel", token: token as string } : current,
          );
        } else {
          setPhase({ kind: "error", message: `Server returned ${response.status}` });
          return;
        }
      } catch (cause) {
        if (controller.signal.aborted) {
          return;
        }
        setPhase({ kind: "error", message: cause instanceof Error ? cause.message : String(cause) });
        return;
      }

      timer = setTimeout(poll, POLL_MS);
    }

    void poll();

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token]);

  const submitOobi = useCallback(
    async (url: string): Promise<string | null> => {
      if (!token) {
        return "No session";
      }

      try {
        const response = await fetch(`/api/login/sessions/${token}/oobi`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
        const body = (await response.json()) as { aid?: string; words?: string[]; error?: string };

        if (!response.ok || !body.aid || !body.words) {
          return body.error ?? `Server returned ${response.status}`;
        }

        setPhase({ kind: "challenged", token, aid: body.aid, words: body.words });
        return null;
      } catch (cause) {
        return cause instanceof Error ? cause.message : String(cause);
      }
    },
    [token],
  );

  return { phase, restart: () => void start(), submitOobi };
}
