/** SDDL parser + trust evaluator: pure fixtures, no OS access. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { ANCESTOR_MASK, evaluateSddl, normalizeSid, parseSddl, SddlError, WRITE_MASK, type SddlKind } from './sddl.ts';

const ME = 'S-1-5-21-1111111111-2222222222-3333333333-1001';
const GRP = 'S-1-5-21-1111111111-2222222222-3333333333-513';
const TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';

function verdict(sddl: string, kind: SddlKind) {
  return evaluateSddl(sddl, kind, { mySid: ME });
}
function assertRefused(sddl: string, kind: SddlKind, code: 'OWNER' | 'ACL' | 'CHAIN', why?: RegExp) {
  const v = verdict(sddl, kind);
  assert.equal(v.ok, false, `expected refusal for ${kind}: ${sddl}`);
  assert.equal(v.code, code, v.reason);
  if (why !== undefined) assert.match(v.reason ?? '', why);
}
function assertOk(sddl: string, kind: SddlKind) {
  const v = verdict(sddl, kind);
  assert.deepEqual(v, { ok: true }, `${kind}: ${v.reason ?? ''}`);
}

// ---- fixtures (shapes follow what Get-Acl(...).Sddl prints on stock Windows) -------------

const C_ROOT =
  'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;WD)';
const C_USERS =
  'O:SYG:SYD:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;WD)(A;OICIIO;GR;;;WD)';
const PROFILE = `O:${ME}G:${GRP}D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`;
const LOCAL_APPDATA = `O:${ME}G:DUD:(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`;
const GIT_DIR = `O:${TI}G:SYD:PAI(A;;FA;;;${TI})(A;CIIO;GA;;;${TI})(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)`;
const GIT_EXE = `O:${TI}G:${TI}D:PAI(A;;FA;;;${TI})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)`;
// A child of C:\ created by us: inherits Authenticated Users:Modify (0x1301bf).
const AU_CHILD = `O:${ME}G:DUD:AI(A;OICIID;0x1301bf;;;AU)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;${ME})`;
// What ensurePrivateDir leaves behind: `icacls /inheritance:r /grant:r *<me>:(OI)(CI)F *S-1-5-18:(OI)(CI)F`.
const PRIVATE_DIR = `O:${ME}G:${GRP}D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)`;
const TOKEN_OK = `O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FA;;;SY)`;

test('normalizeSid: aliases, case, unknown aliases never collide with trusted SIDs, junk throws', () => {
  assert.equal(normalizeSid('SY'), 'S-1-5-18');
  assert.equal(normalizeSid('ba'), 'S-1-5-32-544');
  assert.equal(normalizeSid('s-1-5-18'), 'S-1-5-18');
  assert.equal(normalizeSid('ZZ'), 'alias:ZZ');
  assert.throws(() => normalizeSid('not a sid'), SddlError);
});

test('parseSddl: owner, group, protected flag, ACE fields, numeric and token rights', () => {
  const p = parseSddl(PRIVATE_DIR);
  assert.equal(p.owner, ME);
  assert.equal(p.group, GRP);
  assert.equal(p.dacl.present, true);
  assert.equal(p.dacl.protected, true);
  assert.equal(p.dacl.aces.length, 2);
  const a = p.dacl.aces[0];
  assert.equal(a?.type, 'A');
  assert.equal(a?.sid, ME);
  assert.equal(a?.inheritable, true);
  assert.equal(a?.rights, 0x1f01ff);
  assert.deepEqual(a?.tokens, ['FA']);
  const hex = parseSddl(`O:SYG:SYD:(A;;0x1301bf;;;AU)`).dacl.aces[0];
  assert.equal(hex?.rights, 0x1301bf);
  assert.deepEqual(hex?.tokens, []);
  assert.equal(parseSddl('O:SYG:SYD:(A;;GR;;;WD)').dacl.aces[0]?.rights, 0x80000000, 'GENERIC_READ stays unsigned');
  assert.equal(parseSddl('O:SYG:SYD:(A;OICIIO;GA;;;CO)').dacl.aces[0]?.inheritOnly, true);
  assert.equal(parseSddl(LOCAL_APPDATA).dacl.protected, false);
  assert.equal(parseSddl(LOCAL_APPDATA).dacl.aces[0]?.inherited, true);
});

test('parseSddl: SACL section and NULL DACL forms', () => {
  assert.equal(parseSddl(`O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(ML;;NW;;;LW)`).dacl.aces.length, 1);
  assert.equal(parseSddl('O:SYG:SY').dacl.present, false, 'no D: section = NULL DACL');
  assert.equal(parseSddl('O:SYG:SYD:NO_ACCESS_CONTROL').dacl.present, false);
});

test('parseSddl: malformed input throws SddlError (unbalanced, flags, tokens, fields, junk)', () => {
  const bad = [
    '',
    'garbage',
    'O:SYG:SYD:P(A;;FA;;;SY',
    'O:SYG:SYD:P(A;;FA;;;SY))',
    'O:SYG:SYD:P(A;;FA;;;SY)junk',
    'O:SYG:SYD:PX(A;;FA;;;SY)',
    'O:SYG:SYD:(A;;FA;;)',
    'O:SYG:SYD:(A;ZZ;FA;;;SY)',
    'O:SYG:SYD:(A;;QQ;;;SY)',
    'O:SYG:SYD:(A;;0x1ffffffff;;;SY)',
    'O:SYG:SYD:(A;;FA;;;not-a-sid)',
    'O:SYG:SYD:(A;;FA;;;SY;(@User.x==1))',
    'O:SYG:SYD:(A;;FA;aaaa;;SY)',
    'O:SYO:SY',
    'O:SYO:BA',
    'X:SY',
    'junkO:SY',
  ];
  for (const s of bad) assert.throws(() => parseSddl(s), SddlError, s);
  assert.throws(() => parseSddl('x'.repeat(70 * 1024)), SddlError);
});

test('private-dir: accepts exactly what ensurePrivateDir produces', () => {
  assertOk(PRIVATE_DIR, 'private-dir');
});

test('private-dir: NOT protected (inherits from parent) is refused even when every ACE is ours', () => {
  assertRefused(`O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)`, 'private-dir', 'ACL', /not protected/);
});

test('private-dir: child of C:\\ with inherited Authenticated Users:Modify is refused (T1)', () => {
  assertRefused(AU_CHILD, 'private-dir', 'ACL');
  // protected but still handing AU write/read: refused on the ACE, not on the flag
  assertRefused(`O:${ME}G:DUD:PAI(A;OICI;0x1301bf;;;AU)(A;OICI;FA;;;${ME})`, 'private-dir', 'ACL', /write access/);
});

test('private-dir: other SIDs may not READ either (spec: read on private dirs => refuse)', () => {
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICI;0x1200a9;;;BU)`, 'private-dir', 'ACL', /read access/);
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICIIO;GR;;;WD)`, 'private-dir', 'ACL', /read access/);
});

test('private-dir: inherit-only ACEs are evaluated (children inherit them)', () => {
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICIIO;GW;;;AU)`, 'private-dir', 'ACL');
});

test('private-dir: traverse/attribute/READ_CONTROL-only grants to others are not "read"', () => {
  // 0x120080 = READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES
  assertOk(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;;0x120080;;;BU)`, 'private-dir');
});

test('private-dir: owner other than us is OWNER even with a perfect DACL', () => {
  assertRefused(`O:BAG:BAD:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)`, 'private-dir', 'OWNER');
  assertRefused(`G:SYD:PAI(A;OICI;FA;;;${ME})`, 'private-dir', 'OWNER', /no owner/);
});

test('private-dir: SYSTEM, Administrators, owner-rights and inherit-only creator-owner are trusted', () => {
  assertOk(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FA;;;OW)(A;OICIIO;FA;;;CO)`, 'private-dir');
});

test('private-dir: creator-owner that is NOT inherit-only is not trusted', () => {
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICI;FA;;;CO)`, 'private-dir', 'ACL');
});

test('private-dir: TrustedInstaller is not accepted inside our private paths', () => {
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICI;FA;;;${TI})`, 'private-dir', 'ACL');
});

test('DENY ACEs are ignored: they neither rescue a dangerous allow nor fail a clean descriptor', () => {
  assertRefused(`O:${ME}G:DUD:P(D;;FA;;;WD)(A;OICI;FA;;;WD)(A;OICI;FA;;;${ME})`, 'private-dir', 'ACL');
  assertOk(`O:${ME}G:DUD:P(D;;FA;;;WD)(A;OICI;FA;;;${ME})`, 'private-dir');
});

test('NULL DACL, absent D:, NO_ACCESS_CONTROL are refused on every kind (T1)', () => {
  const nulls = [`O:${ME}G:DU`, `O:${ME}G:DUD:NO_ACCESS_CONTROL`];
  for (const s of nulls) {
    for (const k of ['private-dir', 'private-file', 'secret-file', 'executable'] as const) assertRefused(s, k, 'ACL', /NULL/);
    for (const k of ['ancestor', 'exec-ancestor', 'parent-of-new'] as const) {
      assertRefused(s.replace(`O:${ME}`, 'O:SY'), k, 'CHAIN', /NULL/);
    }
  }
});

test('conditional / callback / object ACEs are refused, not skipped (T1)', () => {
  const cond = `O:${ME}G:DUD:P(XA;;FA;;;WD;(@User.Title=="PM"))(A;OICI;FA;;;${ME})`;
  assertRefused(cond, 'private-dir', 'ACL', /unsupported ACE type XA/);
  assertRefused(`O:${ME}G:DUD:P(OA;;CC;bf967aba-0de6-11d0-a285-00aa003049f2;;WD)(A;OICI;FA;;;${ME})`, 'private-dir', 'ACL', /OA/);
  assertRefused(`O:${ME}G:DUD:P(ZA;;FA;;;WD)(A;OICI;FA;;;${ME})`, 'private-dir', 'ACL', /ZA/);
  assertRefused(cond.replace(`O:${ME}`, 'O:SY'), 'ancestor', 'CHAIN');
});

test('unparseable descriptor is a refusal on every kind (never a pass)', () => {
  for (const k of ['private-dir', 'private-file', 'secret-file', 'executable'] as const) {
    assertRefused('O:SYG:SYD:P(A;;FA;;;', k, 'ACL', /unparseable/);
    assertRefused('', k, 'ACL', /unparseable/);
  }
  assertRefused('nonsense', 'ancestor', 'CHAIN', /unparseable/);
  const v = evaluateSddl(PRIVATE_DIR, 'private-dir', { mySid: 'not-a-sid' });
  assert.equal(v.ok, false, 'an invalid own SID must not make everything "foreign" or "trusted"');
});

test('secret-file: Everyone:Read on the token => refuse (so the caller rotates) (T1/T3)', () => {
  assertOk(TOKEN_OK, 'secret-file');
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FA;;;SY)(A;ID;FR;;;WD)`, 'secret-file', 'ACL', /read access/);
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;0x1200a9;;;BU)`, 'secret-file', 'ACL', /read access/);
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;GR;;;AU)`, 'secret-file', 'ACL', /read access/);
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;;0x1;;;S-1-5-32-545)`, 'secret-file', 'ACL', /read access/);
  assertRefused(`O:BAG:DUD:(A;ID;FA;;;${ME})`, 'secret-file', 'OWNER');
});

test('private-file (non-secret): others may read but never write', () => {
  const readable = `O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FA;;;SY)(A;ID;FR;;;WD)`;
  assertOk(readable, 'private-file');
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FW;;;BU)`, 'private-file', 'ACL', /write access/);
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;0x2;;;WD)`, 'private-file', 'ACL', /write access/);
});

test('every WRITE_MASK bit and generic write/all is detected as write', () => {
  const bits = [0x100, 0x40, 0x10, 0x04, 0x02, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000];
  for (const b of bits) {
    assert.ok((WRITE_MASK | 0x40000000 | 0x10000000) !== 0 && b !== 0);
    const hex = `0x${b.toString(16)}`;
    assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;${hex};;;WD)`, 'private-file', 'ACL', /write/);
  }
  // CC / DC tokens are treated as write (spec lists them)
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;CC;;;WD)`, 'private-file', 'ACL', /write/);
});

test('ancestor: stock C:\\, C:\\Users, profile, LocalAppData pass (T1)', () => {
  assertOk(C_ROOT, 'ancestor');
  assertOk(C_USERS, 'ancestor');
  assertOk(PROFILE, 'ancestor');
  assertOk(LOCAL_APPDATA, 'ancestor');
});

test('ancestor: C:\\ is fine as an ancestor but NOT as the direct parent of a new dir (children inherit AU Modify)', () => {
  assertOk(C_ROOT, 'ancestor');
  assertRefused(C_ROOT, 'parent-of-new', 'CHAIN', /inherit/);
});

test('parent-of-new: Users, profile and LocalAppData are acceptable parents', () => {
  assertOk(C_USERS, 'parent-of-new');
  assertOk(PROFILE, 'parent-of-new');
  assertOk(LOCAL_APPDATA, 'parent-of-new');
});

test('parent-of-new: inheritable write for an untrusted SID is refused, effective ones too', () => {
  assertRefused(`O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICIIO;GW;;;BU)`, 'parent-of-new', 'CHAIN', /inherit/);
  assertRefused(`O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;;0x1301bf;;;BU)`, 'parent-of-new', 'CHAIN');
  // read-only inheritance is what stock C:\Users hands out; icacls strips it right after mkdir
  assertOk(`O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;BU)`, 'parent-of-new');
});

test('ancestor: Authenticated Users with Modify (no DELETE_CHILD/WRITE_DAC) is still refused through DELETE', () => {
  assert.equal(0x1301bf & (0x40 | 0x40000 | 0x80000), 0, 'Modify has none of the spec-listed bits');
  assert.notEqual(0x1301bf & ANCESTOR_MASK, 0);
  assertRefused(AU_CHILD.replace(`O:${ME}`, 'O:SY'), 'ancestor', 'CHAIN', /can modify/);
});

test('ancestor: each of DELETE_CHILD / WRITE_DAC / WRITE_OWNER / DELETE / GA / GW for a stranger is refused', () => {
  for (const hex of ['0x40', '0x40000', '0x80000', '0x10000', '0x10000000', '0x40000000']) {
    assertRefused(`O:SYG:SYD:PAI(A;;FA;;;SY)(A;;${hex};;;BU)`, 'ancestor', 'CHAIN', /can modify/);
  }
  // create-only grants do not let anyone replace our directory
  assertOk(`O:SYG:SYD:PAI(A;;FA;;;SY)(A;;0x6;;;BU)`, 'ancestor');
});

test('ancestor: inherit-only ACEs do not apply to the directory itself', () => {
  assertOk(`O:SYG:SYD:PAI(A;;FA;;;SY)(A;OICIIO;0x1301bf;;;AU)`, 'ancestor');
});

test('ancestor: owner must be me / SYSTEM / Administrators / TrustedInstaller', () => {
  assertOk(`O:BAG:BAD:PAI(A;;FA;;;SY)`, 'ancestor');
  assertRefused(`O:S-1-5-21-9-9-9-1500G:BAD:PAI(A;;FA;;;SY)`, 'ancestor', 'CHAIN', /owner/);
  assertRefused(`G:BAD:PAI(A;;FA;;;SY)`, 'ancestor', 'CHAIN', /no owner/);
});

test('exec-ancestor / executable: Git under Program Files passes (TrustedInstaller accepted)', () => {
  assertOk(GIT_DIR, 'exec-ancestor');
  assertOk(GIT_EXE, 'executable');
});

test('TrustedInstaller is NOT trusted on a private file or a secret', () => {
  assertRefused(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FA;;;${TI})`, 'secret-file', 'ACL');
});

test('executable: writable by Users, owned by a stranger, or world-writable parent dir is refused', () => {
  assertRefused(`O:${TI}G:${TI}D:PAI(A;;FA;;;${TI})(A;;FW;;;BU)`, 'executable', 'ACL', /write access/);
  assertRefused(`O:S-1-5-21-9-9-9-1500G:SYD:PAI(A;;FA;;;SY)`, 'executable', 'OWNER');
  assertRefused(`O:${TI}G:SYD:PAI(A;;FA;;;${TI})(A;;0x1301bf;;;BU)`, 'exec-ancestor', 'CHAIN');
  assertRefused(`O:${TI}G:SYD:PAI(A;;FA;;;${TI})(A;;FA;;;WD)`, 'exec-ancestor', 'CHAIN');
});

test('unknown account aliases are untrusted', () => {
  assertRefused(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(A;OICI;FA;;;LA)`, 'private-dir', 'ACL');
  assertOk(`O:${ME}G:DUD:P(A;OICI;FA;;;${ME})(D;OICI;FA;;;LA)`, 'private-dir');
});
