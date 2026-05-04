export interface Logger {
  error(msg: string, meta?: object): void;
  warn(msg: string, meta?: object): void;
  info(msg: string, meta?: object): void;
  debug(msg: string, meta?: object): void;
}
