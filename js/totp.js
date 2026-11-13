/**
 * Time-based one-time codes (RFC 6238: HMAC-SHA1, 30 seconds, 6 digits), the
 * kind authenticator apps (Google Authenticator, Microsoft Authenticator,
 * Authy…) show. Used as a second step for unattended access.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_STEP = 30;

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('bad base32');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function isTotpSecret(text) {
  return /^[A-Z2-7]{16,64}$/.test(String(text || ''));
}

/** A new random secret (160 bits) in the base32 form the apps take. */
export function generateTotpSecret() {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

/** The 6-digit code for a 30-second time step. */
export async function totpCode(secret, counter) {
  const key = await crypto.subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setUint32(0, Math.floor(counter / 2 ** 32));
  new DataView(msg.buffer).setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = mac[19] & 15;
  const n = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(n % 1_000_000).padStart(6, '0');
}

export function totpCounter(now = Date.now()) {
  return Math.floor(now / 1000 / TOTP_STEP);
}

/**
 * Checks a code against the current step and one step either side (clock
 * drift). Returns the matched step, or -1. A step at or before `notAfter`
 * (already used) is refused, so a code cannot be replayed.
 */
export async function verifyTotp(secret, code, { now = Date.now(), notAfter = -1 } = {}) {
  const digits = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(digits) || !isTotpSecret(secret)) return -1;
  const current = totpCounter(now);
  for (const counter of [current, current - 1, current + 1]) {
    if (counter <= notAfter) continue;
    if ((await totpCode(secret, counter)) === digits) return counter;
  }
  return -1;
}

/** The link authenticator apps read from a QR code. */
export function otpauthUri(secret, account, issuer = 'Xenon Remote') {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${TOTP_STEP}`;
}
