/** Test-only helpers (subpath `@agent-ledger/shared/testing`, not part of the
 *  runtime barrel). */

/** `node:test` `skip` option: an explicit, visible reason on win32, `false`
 *  elsewhere. Use for tests that assume POSIX semantics (symlinks without
 *  privilege, chmod/mode bits, uid, `#!/bin/sh` stubs, `/tmp`, `/usr/bin/*`):
 *
 *      test('name', { skip: skipOnWin32('POSIX mode bits') }, async (t) => { … });
 */
export function skipOnWin32(reason: string, platform: NodeJS.Platform = process.platform): string | false {
  return platform === 'win32' ? `skipped on win32: ${reason}` : false;
}
