// CI only (windows-latest), loaded with `node --import`: temp dirs made by tests get the same
// protected DACL ({me, SYSTEM}, inheritance off) that the product's ensurePrivateDir requires.
// On POSIX, mkdtemp yields 0700 for free; on Windows it inherits the parent's ACL, which the
// product (correctly) refuses ("DACL is not protected"). No effect outside win32.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';

if (process.platform === 'win32') {
  const sys = process.env.SystemRoot ?? 'C:\\Windows';
  const icacls = `${sys}\\System32\\icacls.exe`;
  const whoami = `${sys}\\System32\\whoami.exe`;
  const csv = execFileSync(whoami, ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
  const sid = /"(S-1-[\d-]+)"\s*$/.exec(csv.trim())?.[1];
  if (!sid) throw new Error('ci-win-preload: cannot read own SID');
  const protect = (dir) => {
    execFileSync(icacls, [dir, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F'], {
      windowsHide: true,
      stdio: 'ignore',
    });
    return dir;
  };
  const origP = fsp.mkdtemp;
  fsp.mkdtemp = async (...a) => protect(await origP.apply(fsp, a));
  const origS = fs.mkdtempSync;
  fs.mkdtempSync = (...a) => protect(origS.apply(fs, a));
  const origC = fs.mkdtemp;
  fs.mkdtemp = (...a) => {
    const cb = a.pop();
    origC.apply(fs, [...a, (err, dir) => {
      if (err) return cb(err);
      try { cb(null, protect(dir)); } catch (e) { cb(e); }
    }]);
  };
}
