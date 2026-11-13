export class LedgerError extends Error {
  readonly status: number;
  readonly code: string;
  readonly extra: Record<string, unknown> | undefined;

  constructor(
    status: number,
    code: string,
    message: string,
    extra?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'LedgerError';
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export function notFound(message: string): LedgerError {
  return new LedgerError(404, 'NOT_FOUND', message);
}

export function conflict(message: string): LedgerError {
  return new LedgerError(409, 'CONFLICT', message);
}

export function invalid(message: string): LedgerError {
  return new LedgerError(422, 'INVALID', message);
}
