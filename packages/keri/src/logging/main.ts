export interface Logger {
  error(msg: string, meta?: object): void;
  warn(msg: string, meta?: object): void;
  info(msg: string, meta?: object): void;
  debug(msg: string, meta?: object): void;
}

const noop: Logger = { error() {}, warn() {}, info() {}, debug() {} };

export class KeriLogger implements Logger {
  readonly #logger: Logger;
  readonly #context: object;

  constructor(logger?: Logger, context: object = {}) {
    this.#logger = logger ?? noop;
    this.#context = context;
  }

  error(msg: string, meta?: object): void {
    this.#logger.error(msg, { ...this.#context, ...meta });
  }

  warn(msg: string, meta?: object): void {
    this.#logger.warn(msg, { ...this.#context, ...meta });
  }

  info(msg: string, meta?: object): void {
    this.#logger.info(msg, { ...this.#context, ...meta });
  }

  debug(msg: string, meta?: object): void {
    this.#logger.debug(msg, { ...this.#context, ...meta });
  }

  extend(context: object): KeriLogger {
    return new KeriLogger(this.#logger, { ...this.#context, ...context });
  }
}
