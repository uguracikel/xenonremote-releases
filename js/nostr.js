// Serverless internet signaling over public Nostr relays.
//
// Relays only ever see opaque data: every message is end-to-end encrypted
// with AES-256-GCM using a key derived from the target device's ID and
// password (PBKDF2-SHA256). Without the password a relay or any other party
// can neither read nor forge messages. Each message carries a timestamp and
// a random nonce (replay protection) and is bound to its recipient topic via
// AES-GCM additional data (no redirection/reflection). Nostr signing keys are
// random per app run and carry no identity.

import { schnorr, sha256, bytesToHex, hexToBytes } from '../vendor/noble.js';
import { Emitter } from './emitter.js';
import { deriveSecret } from './auth.js';

export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://relay.nostr.band',
  'wss://nostr.mom',
];

const KIND = 25050; // ephemeral event kind: relays forward but do not store
const MAX_AGE_MS = 60000;
const enc = (s) => new TextEncoder().encode(s);

function toB64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomHex(bytes) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Public, unlinkable-to-content routing tag for a device or session. */
export function topicFor(name) {
  return bytesToHex(sha256(enc(`xenon-remote:v1:topic:${name}`)));
}

export function keyFromSecret(secret) {
  return crypto.subtle.importKey('raw', secret, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function deriveKey(id, password) {
  return keyFromSecret(await deriveSecret(id, password));
}

export async function seal(key, obj, topic) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc(topic) }, key, enc(JSON.stringify(obj)));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return toB64(out);
}

export async function unseal(key, content, topic) {
  try {
    const raw = fromB64(content);
    if (raw.length < 29) return null;
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: enc(topic) }, key, raw.slice(12));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch {
    return null; // wrong key, tampered or foreign data
  }
}

/** Builds and signs a NIP-01 event. */
export function signEvent(secretKey, { kind, tags, content, created_at = Math.floor(Date.now() / 1000) }) {
  const pubkey = bytesToHex(schnorr.getPublicKey(secretKey));
  const id = bytesToHex(sha256(enc(JSON.stringify([0, pubkey, created_at, kind, tags, content]))));
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey));
  return { id, pubkey, created_at, kind, tags, content, sig };
}

export function verifyEvent(ev) {
  try {
    if (!ev || typeof ev.content !== 'string' || !Array.isArray(ev.tags)) return false;
    const id = bytesToHex(sha256(enc(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
    return id === ev.id && schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch {
    return false;
  }
}

/** Connections to several relays; publishes to all, de-duplicates incoming events. */
class RelayPool extends Emitter {
  constructor(urls, WebSocketImpl) {
    super();
    this.urls = urls;
    this.WebSocketImpl = WebSocketImpl;
    this.sockets = new Map(); // url -> { ws, retry, timer }
    this.subs = new Map(); // subId -> filter
    this.seen = new Set();
    this.closed = false;
  }

  get connected() {
    let n = 0;
    for (const { ws } of this.sockets.values()) if (ws && ws.readyState === 1) n += 1;
    return n;
  }

  connectedUrls() {
    const out = [];
    for (const [url, { ws }] of this.sockets) if (ws && ws.readyState === 1) out.push(url);
    return out;
  }

  start() {
    this.closed = false;
    for (const url of this.urls) this.open(url);
  }

  open(url) {
    const entry = this.sockets.get(url) || { ws: null, retry: 0, timer: null };
    this.sockets.set(url, entry);
    let ws;
    try {
      ws = new this.WebSocketImpl(url);
    } catch {
      this.retryLater(url);
      return;
    }
    entry.ws = ws;
    ws.onopen = () => {
      entry.retry = 0;
      for (const [id, filter] of this.subs) ws.send(JSON.stringify(['REQ', id, filter]));
      this.emit('status', this.connected);
    };
    ws.onmessage = (msg) => this.onMessage(msg.data);
    ws.onclose = () => {
      if (entry.ws !== ws) return;
      entry.ws = null;
      this.emit('status', this.connected);
      if (!this.closed) this.retryLater(url);
    };
    ws.onerror = () => {};
  }

  retryLater(url) {
    const entry = this.sockets.get(url);
    clearTimeout(entry.timer);
    const delay = Math.min(30000, 1000 * 2 ** entry.retry);
    entry.retry += 1;
    entry.timer = setTimeout(() => this.open(url), delay);
  }

  onMessage(data) {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (!Array.isArray(msg) || msg[0] !== 'EVENT' || !this.subs.has(msg[1])) return;
    const ev = msg[2];
    if (!ev || this.seen.has(ev.id) || ev.kind !== KIND || !verifyEvent(ev)) return;
    this.seen.add(ev.id);
    if (this.seen.size > 2000) this.seen = new Set([...this.seen].slice(-1000));
    this.emit('event', ev);
  }

  subscribe(id, filter) {
    this.subs.set(id, filter);
    this.broadcast(['REQ', id, filter]);
  }

  unsubscribe(id) {
    if (!this.subs.delete(id)) return;
    this.broadcast(['CLOSE', id]);
  }

  publish(event) {
    return this.broadcast(['EVENT', event]);
  }

  broadcast(message) {
    const text = JSON.stringify(message);
    let sent = 0;
    for (const { ws } of this.sockets.values()) {
      if (ws && ws.readyState === 1) {
        ws.send(text);
        sent += 1;
      }
    }
    return sent;
  }

  close() {
    this.closed = true;
    for (const entry of this.sockets.values()) {
      clearTimeout(entry.timer);
      if (entry.ws) entry.ws.close();
      entry.ws = null;
    }
    this.emit('status', 0);
  }
}

/**
 * Signaling transport over Nostr. Peer IDs look like "nostr:<session>".
 *
 * Host side:   listen(id, secrets)       -> receives authenticated requests
 *              (secrets: derived device secrets or passwords; several are
 *              accepted, e.g. the session password and the permanent one)
 * Viewer side: openSession(id, password) -> returns the peer ID to send to
 *
 * Events: status('online'|'offline'), relay(from, payload, meta)
 */
export class NostrSignaling extends Emitter {
  constructor({ relays = DEFAULT_RELAYS, WebSocketImpl = globalThis.WebSocket } = {}) {
    super();
    this.pool = new RelayPool(relays, WebSocketImpl);
    this.secretKey = schnorr.utils.randomSecretKey();
    this.host = null; // { topic, key }
    this.sessions = new Map(); // sid -> { key, sendTopic, recvTopic }
    this.seenNonces = new Map(); // nonce -> expiry
    this.state = 'offline';
    this.pool.on('status', (n) => {
      const state = n > 0 ? 'online' : 'offline';
      if (state !== this.state) {
        this.state = state;
        this.emit('status', state);
      }
    });
    this.pool.on('event', (ev) => this.onEvent(ev).catch((err) => console.warn('[xenon] nostr event error', err)));
  }

  get relayCount() {
    return this.pool.connected;
  }

  /** Hostnames of the relays we are currently connected to (the "servers"). */
  connectedRelayHosts() {
    return this.pool.connectedUrls().map((u) => {
      try {
        return new URL(u).hostname;
      } catch {
        return u;
      }
    });
  }

  start() {
    this.pool.start();
  }

  since() {
    return Math.floor((Date.now() - MAX_AGE_MS) / 1000);
  }

  /**
   * `secrets`: passwords, derived secrets (Uint8Array) or { secret, label }
   * entries; the label of the key a request used is passed on (meta.label),
   * e.g. to recognise a trusted device.
   */
  async listen(id, secrets) {
    const topic = topicFor(`host:${id}`);
    const list = (Array.isArray(secrets) ? secrets : [secrets]).filter(Boolean)
      .map((s) => (s instanceof Uint8Array || typeof s === 'string' ? { secret: s, label: null } : s)).filter((s) => s.secret);
    const keys = await Promise.all(list.map(async ({ secret, label }) => ({
      key: typeof secret === 'string' ? await deriveKey(id, secret) : await keyFromSecret(secret),
      label: label || null,
    })));
    if (!keys.length) {
      this.stopListening();
      return;
    }
    this.host = { topic, keys };
    this.pool.subscribe('xenon-host', { kinds: [KIND], '#t': [topic], since: this.since() });
  }

  stopListening() {
    this.host = null;
    this.pool.unsubscribe('xenon-host');
  }

  /** `password`: the host's password, or a secret (Uint8Array) such as a trusted-device key. */
  async openSession(id, password) {
    const sid = randomHex(16);
    const key = password instanceof Uint8Array ? await keyFromSecret(password) : await deriveKey(id, password);
    const recvTopic = topicFor(`peer:${sid}`);
    this.sessions.set(sid, { key, sendTopic: topicFor(`host:${id}`), recvTopic, role: 'viewer' });
    this.pool.subscribe(`xenon-${sid.slice(0, 12)}`, { kinds: [KIND], '#t': [recvTopic], since: this.since() });
    return `nostr:${sid}`;
  }

  closeSession(peerId) {
    const sid = String(peerId).replace(/^nostr:/, '');
    const session = this.sessions.get(sid);
    if (!session) return;
    this.sessions.delete(sid);
    if (session.role === 'viewer') this.pool.unsubscribe(`xenon-${sid.slice(0, 12)}`);
  }

  async send(peerId, payload) {
    const sid = String(peerId).replace(/^nostr:/, '');
    const session = this.sessions.get(sid);
    if (!session) return false;
    const body = { v: 1, sid, ts: Date.now(), n: randomHex(12), dir: session.role === 'viewer' ? 'v2h' : 'h2v', payload };
    const content = await seal(session.key, body, session.sendTopic);
    const event = signEvent(this.secretKey, { kind: KIND, tags: [['t', session.sendTopic]], content });
    return this.pool.publish(event) > 0;
  }

  freshAndNew(body) {
    const now = Date.now();
    for (const [n, exp] of this.seenNonces) if (exp < now) this.seenNonces.delete(n);
    if (typeof body.ts !== 'number' || Math.abs(now - body.ts) > MAX_AGE_MS) return false;
    if (typeof body.n !== 'string' || this.seenNonces.has(body.n)) return false;
    this.seenNonces.set(body.n, now + 2 * MAX_AGE_MS);
    return true;
  }

  async onEvent(ev) {
    const topic = (ev.tags.find((t) => t[0] === 't') || [])[1];
    if (!topic) return;

    if (this.host && topic === this.host.topic) {
      let body = null;
      let key = null;
      let label = null;
      for (const candidate of this.host.keys) {
        body = await unseal(candidate.key, ev.content, topic);
        if (body) {
          ({ key, label } = candidate);
          break;
        }
      }
      if (!body || body.v !== 1 || body.dir !== 'v2h' || !/^[0-9a-f]{32}$/.test(body.sid) || !this.freshAndNew(body)) return;
      if (!this.sessions.has(body.sid)) {
        // Reply with the key the viewer used (session or permanent password).
        this.sessions.set(body.sid, { key, label, sendTopic: topicFor(`peer:${body.sid}`), recvTopic: null, role: 'host' });
      }
      const session = this.sessions.get(body.sid);
      this.emit('relay', `nostr:${body.sid}`, body.payload || {}, { authenticated: true, transport: 'nostr', label: session.label || null });
      return;
    }

    for (const [sid, session] of this.sessions) {
      if (session.role !== 'viewer' || session.recvTopic !== topic) continue;
      const body = await unseal(session.key, ev.content, topic);
      if (!body || body.v !== 1 || body.dir !== 'h2v' || body.sid !== sid || !this.freshAndNew(body)) return;
      this.emit('relay', `nostr:${sid}`, body.payload || {}, { authenticated: true, transport: 'nostr' });
      return;
    }
  }

  close() {
    this.pool.close();
    this.sessions.clear();
    this.host = null;
  }
}
