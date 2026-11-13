/** One writer, one serial queue (SPEC §6.2). Id allocation runs on the same
 *  queue as the write that consumes the id — that is what makes 50 parallel
 *  `ledger add` calls come out unique and without gaps. */
export class SerialQueue {
  private tail: Promise<unknown> = Promise.resolve();
  private depth = 0;

  get pending(): number {
    return this.depth;
  }

  run<T>(fn: () => Promise<T>): Promise<T> {
    this.depth += 1;
    const next = this.tail.then(() => fn());
    // Keep the chain alive even when a job rejects.
    this.tail = next.then(
      () => undefined,
      () => undefined,
    );
    return next.finally(() => {
      this.depth -= 1;
    });
  }

  /** Resolves when everything queued so far has settled. */
  async drain(): Promise<void> {
    await this.tail;
  }
}
