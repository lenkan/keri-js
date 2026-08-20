import type { KeyEventStore, StoredKeyEvent } from "./login.ts";
import type { SessionStore } from "./verifier.ts";

/** In-memory stores shared by the tests in this submodule. */
export function makeSessions(): SessionStore & { size: () => number } {
  const entries = new Map<string, string>();
  return {
    get: async (token) => entries.get(token) ?? null,
    put: async (token, cesr) => {
      entries.set(token, cesr);
    },
    size: () => entries.size,
  };
}

export function makeKeyEvents(): KeyEventStore {
  const events = new Map<string, StoredKeyEvent>();
  return {
    getEvent: async (aid, sn) => events.get(`${aid}:${sn}`) ?? null,
    putEvent: async (aid, sn, event) => {
      events.set(`${aid}:${sn}`, event);
    },
  };
}
