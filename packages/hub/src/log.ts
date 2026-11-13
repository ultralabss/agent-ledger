/**
 * The one place that stamps a hub log line.
 *
 * `hub.log` is the only record of what the launchd hub did, and until now not a
 * single line carried a time: a stall, a wake, a blocked commit and a restart
 * were indistinguishable in order of minutes. Every sink the hub writes through
 * (`startHub`'s default, `bin.ts`'s own startup/shutdown lines, the Ledger log)
 * goes through `timestamped()`, so the prefix exists in exactly one function.
 */

export type LogSink = (line: string) => void;

/** Raw stderr sink — launchd redirects it into `<ledger>/.hub/hub.log`. */
export const stderrSink: LogSink = (line: string) => {
  process.stderr.write(`${line}\n`);
};

/**
 * Prefix every line with `new Date().toISOString()` + one space.
 *
 * A multi-line message (a git stderr tail, a stack) gets the prefix on each of
 * its lines: a reader greping for a timestamp range must not lose the tail of
 * a message, and a continuation line without a prefix is how log parsers end up
 * attributing it to the wrong minute.
 */
export function timestamped(sink: LogSink = stderrSink, now: () => Date = () => new Date()): LogSink {
  return (line: string) => {
    const at = now().toISOString();
    const text = String(line).replace(/\n+$/, '');
    for (const part of text.split('\n')) sink(`${at} ${part}`);
  };
}

/** Process-wide hub sink. `bin.ts` and `startHub` share it so a shutdown line
 *  and the last job line are stamped by the same clock. */
export const hubLog: LogSink = timestamped();
