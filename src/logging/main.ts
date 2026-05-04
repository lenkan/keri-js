export interface Logger {
  error(msg: string, meta?: object): void;
  warn(msg: string, meta?: object): void;
  info(msg: string, meta?: object): void;
  debug(msg: string, meta?: object): void;
}

export type PartialLogger = Partial<Logger>;

const noop = (): void => {};

export const noopLogger: Logger = {
  error: noop,
  warn: noop,
  info: noop,
  debug: noop,
};

export function normalizeLogger(logger?: PartialLogger): Logger {
  if (!logger) {
    return noopLogger;
  }
  return {
    error: logger.error?.bind(logger) ?? noop,
    warn: logger.warn?.bind(logger) ?? noop,
    info: logger.info?.bind(logger) ?? noop,
    debug: logger.debug?.bind(logger) ?? noop,
  };
}
