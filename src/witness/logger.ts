export interface Logger {
  trace(msg: string, meta?: object): void;
  debug(msg: string, meta?: object): void;
  info(msg: string, meta?: object): void;
  warn(msg: string, meta?: object): void;
  error(msg: string, meta?: object): void;
}

export const noopLogger: Logger = {
  trace: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
