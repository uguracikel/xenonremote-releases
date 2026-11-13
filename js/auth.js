// Password, nonce and proof helpers shared by host and viewer.
//
// The host never sends its password anywhere. Instead it sends a random nonce
// and the viewer answers with PBKDF2(password, nonce). The signaling server
// only ever sees the nonce and the derived proof.

const PASSWORD_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

function randomIndex(max) {
  // Rejection sampling to avoid modulo bias.
  const limit = 256 - (256 % max);
  const buf = new Uint8Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % max;
}

export function generatePassword(length = 10) {
  let out = '';
  for (let i = 0; i < length; i++) out += PASSWORD_ALPHABET[randomIndex(PASSWORD_ALPHABET.length)];
  return out;
}

/** Random 9 digit device ID (first digit never 0), kept on the device. */
export function generateDeviceId() {
  const buf = crypto.getRandomValues(new Uint32Array(2));
  const first = 1 + (buf[0] % 9);
  const rest = String(buf[1] % 100000000).padStart(8, '0');
  return `${first}${rest}`;
}

export function generateNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const PBKDF2_ITERATIONS = 210000;

/**
 * The device secret: PBKDF2-SHA256(password, device ID). Both the LAN
 * challenge/response and the internet (Nostr) encryption key use it, so a
 * permanent password can be stored as this secret instead of in clear text.
 */
export async function deriveSecret(id, password) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(`xenon-remote:v1:key:${id}`), iterations: PBKDF2_ITERATIONS },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export function secretToHex(secret) {
  return Array.from(secret, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToSecret(hex) {
  if (!/^[0-9a-f]{64}$/.test(String(hex))) return null;
  return new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
}

/** Proof for the LAN challenge: HMAC-SHA256(secret, nonce). */
export async function computeProof(secret, nonce) {
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`xenon-remote:v1:proof:${nonce}`));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** "123456789" -> "123 456 789" */
export function formatId(id) {
  return String(id || '').replace(/\D/g, '').replace(/(\d{3})(?=\d)/g, '$1 ');
}

/** Strips everything but digits from user input. */
export function normalizeId(value) {
  return String(value || '').replace(/\D/g, '');
}
