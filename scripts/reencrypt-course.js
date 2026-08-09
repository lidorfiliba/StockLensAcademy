#!/usr/bin/env node
'use strict';

/**
 * Re-encrypts the course payload inside index.html under a new key.
 *
 *   node scripts/reencrypt-course.js <OLD_KEY> <NEW_KEY> [--file <path>] [--dry-run]
 *
 * Keys are read from argv only. Nothing in this script writes a key to disk,
 * to a log line, or to any other file — and no key may ever be committed.
 *
 * What it does, in order:
 *   1. Extracts window._enc from the file.
 *   2. Decrypts it with OLD_KEY  (base64 -> XOR -> gunzip).
 *   3. Re-encrypts that exact plaintext with NEW_KEY (gzip -> XOR -> base64).
 *   4. Decrypts its own output with NEW_KEY and asserts the result is
 *      byte-identical to the plaintext from step 2. Any mismatch aborts.
 *   5. Backs the original file up, then splices the new blob in so every other
 *      byte of the file is untouched.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const ENC_RE = /window\._enc="([^"]+)"/;

function die(message) {
  console.error('\n  ABORTED: ' + message + '\n');
  process.exit(1);
}

function usage() {
  console.error('\n  Usage: node scripts/reencrypt-course.js <OLD_KEY> <NEW_KEY> [--file <path>] [--dry-run]\n');
  process.exit(1);
}

/** XOR against the UTF-8 bytes of the key, cycling — same as the browser side. */
function xorBytes(buf, key) {
  const kb = Buffer.from(key, 'utf8');
  const out = Buffer.allocUnsafe(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ kb[i % kb.length];
  return out;
}

function decryptBlob(b64, key) {
  return zlib.gunzipSync(xorBytes(Buffer.from(b64, 'base64'), key));
}

function encryptBlob(plaintext, key) {
  return xorBytes(zlib.gzipSync(plaintext, { level: 9 }), key).toString('base64');
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function main() {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes('--dry-run');

  const fileFlag = argv.indexOf('--file');
  let target = path.resolve(__dirname, '..', 'index.html');
  if (fileFlag !== -1) {
    if (!argv[fileFlag + 1]) usage();
    target = path.resolve(argv[fileFlag + 1]);
  }

  const positional = argv.filter(function (a, i) {
    if (a === '--dry-run') return false;
    if (a === '--file') return false;
    if (fileFlag !== -1 && i === fileFlag + 1) return false;
    return true;
  });

  const oldKey = positional[0];
  const newKey = positional[1];

  if (!oldKey || !newKey) usage();
  if (oldKey === newKey) die('OLD_KEY and NEW_KEY are identical — nothing to do.');
  if (newKey.length < 16) die('NEW_KEY looks too short (' + newKey.length + ' chars). Use a long random key.');

  if (!fs.existsSync(target)) die('file not found: ' + target);

  // latin1 keeps a 1:1 char-to-byte mapping, so regex offsets are byte offsets
  // and every byte outside the blob survives untouched.
  const original = fs.readFileSync(target);
  const text = original.toString('latin1');

  const match = ENC_RE.exec(text);
  if (!match) {
    die('window._enc not found in ' + target + '\n           This is not the encrypted course file.');
  }

  const oldBlob = match[1];
  const blobStart = match.index + match[0].indexOf('"') + 1;

  console.log('  file        : ' + target);
  console.log('  file bytes  : ' + original.length);
  console.log('  old blob    : ' + oldBlob.length + ' base64 chars');

  // ── 1. Decrypt with the old key ──
  let plaintext;
  try {
    plaintext = decryptBlob(oldBlob, oldKey);
  } catch (e) {
    die('could not decrypt with OLD_KEY (' + e.message + ').\n           Wrong key, or this file is not the one that key belongs to.');
  }

  const plainHash = sha256(plaintext);
  console.log('  plaintext   : ' + plaintext.length + ' bytes, sha256 ' + plainHash.slice(0, 16) + '...');

  // A sane decrypt should look like course HTML, not random bytes.
  const head = plaintext.slice(0, 2048).toString('utf8');
  if (!/<[a-zA-Z]/.test(head)) {
    die('decrypted output does not look like HTML — refusing to continue.');
  }

  // ── 2. Re-encrypt with the new key ──
  const newBlob = encryptBlob(plaintext, newKey);
  console.log('  new blob    : ' + newBlob.length + ' base64 chars');

  // ── 3. Verify the round trip before touching anything ──
  let verified;
  try {
    verified = decryptBlob(newBlob, newKey);
  } catch (e) {
    die('verification failed — new blob will not decrypt (' + e.message + '). File unchanged.');
  }

  if (!verified.equals(plaintext)) {
    die('verification failed — round-trip output differs from the original plaintext. File unchanged.');
  }
  console.log('  verify      : OK (round-trip is byte-identical)');

  if (dryRun) {
    console.log('\n  --dry-run: file NOT modified.\n');
    return;
  }

  // ── 4. Back up, then splice the blob in ──
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  const backupDir = path.join(path.dirname(target), 'backups');
  fs.mkdirSync(backupDir, { recursive: true });
  const backupPath = path.join(backupDir, path.basename(target) + '.' + stamp + '.bak');
  fs.writeFileSync(backupPath, original);
  console.log('  backup      : ' + backupPath);

  const updated = Buffer.concat([
    original.slice(0, blobStart),
    Buffer.from(newBlob, 'ascii'),
    original.slice(blobStart + oldBlob.length),
  ]);

  fs.writeFileSync(target, updated);

  // ── 5. Re-read from disk and confirm what actually landed ──
  const check = fs.readFileSync(target);
  const checkMatch = ENC_RE.exec(check.toString('latin1'));
  if (!checkMatch || checkMatch[1] !== newBlob) {
    die('post-write check failed. Restore from ' + backupPath);
  }
  if (sha256(decryptBlob(checkMatch[1], newKey)) !== plainHash) {
    die('post-write decrypt mismatch. Restore from ' + backupPath);
  }

  const untouchedBefore = original.slice(0, blobStart).equals(check.slice(0, blobStart));
  const untouchedAfter = original
    .slice(blobStart + oldBlob.length)
    .equals(check.slice(blobStart + newBlob.length));
  if (!untouchedBefore || !untouchedAfter) {
    die('surrounding bytes changed. Restore from ' + backupPath);
  }

  console.log('  written     : ' + check.length + ' bytes, rest of file byte-identical');
  console.log('\n  Done. Set COURSE_KEY to the NEW key, then commit and push index.html.\n');
}

main();
