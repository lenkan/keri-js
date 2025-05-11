import type { KeyValueStorage } from "../events/event-store.ts";

export interface Storage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export class WebStorage implements KeyValueStorage {
  #storage: Storage;

  constructor(storage: Storage) {
    this.#storage = storage;
  }

  async get(key: string): Promise<string | null> {
    return this.#storage.getItem(key);
  }

  async set(key: string, value: string): Promise<void> {
    this.#storage.setItem(key, value);
  }
}

export class MapStore implements KeyValueStorage {
  #map: Map<string, string>;

  constructor() {
    this.#map = new Map();
  }

  clear() {
    this.#map.clear();
  }

  async get(key: string): Promise<string | null> {
    const result = this.#map.get(key);
    return result ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.#map.set(key, value);
  }
}
