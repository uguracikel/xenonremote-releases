import { Emitter } from './emitter.js';
import { Sha256 } from './sha256.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 4 * 1024 ** 3;
const MAX_CLIP_IMAGE_BYTES = 16 * 1024 * 1024;

/**
 * Transfer speed, smoothed so the shown number and remaining time do not
 * jump around with every chunk.
 */
export class RateMeter {
  constructor(now = Date.now()) {
    this.lastAt = now;
    this.lastBytes = 0;
    this.rate = 0; // bytes per second
  }

  /** Returns { rate, eta } after `done` of `size` bytes. */
  update(done, size, now = Date.now()) {
    const dt = now - this.lastAt;
    if (dt >= 500) {
      const current = ((done - this.lastBytes) * 1000) / dt;
      this.rate = this.rate ? this.rate * 0.6 + current * 0.4 : current;
      this.lastAt = now;
      this.lastBytes = done;
    }
    const eta = this.rate > 0 ? Math.max(0, Math.ceil((size - done) / this.rate)) : null;
    return { rate: Math.round(this.rate), eta };
  }
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * A file on this computer, given by path (remote file browser, pasted files):
 * read through the bridge in chunks, like a File.
 */
export class PathFile {
  constructor(bridge, { path, rel, size }) {
    this.bridge = bridge;
    this.path = path;
    this.name = rel || path.split(/[\\/]/).pop();
    this.size = size;
    this.token = null;
  }

  slice(start, end) {
    return {
      arrayBuffer: async () => {
        if (!this.token) this.token = (await this.bridge.fileOpen(this.path)).token;
        const bytes = await this.bridge.fileRead(this.token, start, end - start);
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      },
    };
  }

  close() {
    if (this.token) this.bridge.fileClose?.(this.token).catch(() => {});
    this.token = null;
  }
}

/**
 * File transfer over a dedicated, ordered RTCDataChannel ("file").
 * Control messages are JSON strings, file data is sent as binary chunks
 * between {t:'begin'} and {t:'end'}. One file at a time in each direction.
 *
 * A name may contain folders ("Klasör/alt/a.txt"): the receiver recreates
 * them. `dir` asks the receiver to save into one of its folders (remote file
 * browser) and `kind: 'clip-image'` carries a clipboard picture, which is
 * kept in memory instead of being saved.
 *
 * Each file's SHA-256 travels with its end message: the receiver checks it
 * and throws the file away when it does not match (older peers skip this).
 *
 * Events: progress({direction, name, done, size, rate, eta}),
 *         sent({name, verified}), received({name, path, verified}), rejected({name}), error(message),
 *         done({sent, failed}) when the send queue is empty, clip-image(bytes)
 */
export class FileTransfer extends Emitter {
  constructor({ channel, bridge, canReceive = () => true, canReceiveClip = () => false }) {
    super();
    this.channel = channel;
    this.bridge = bridge;
    this.canReceive = canReceive;
    this.canReceiveClip = canReceiveClip;
    this.counts = { sent: 0, failed: 0 };
    this.queue = [];
    this.sending = false;
    this.incoming = null; // { id, name, size, received, token, writes }
    this.waiters = new Map(); // id -> resolve(answer)
    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = CHUNK * 4;
    channel.onmessage = (event) => this.onMessage(event.data);
  }

  /**
   * Queues files. A File from a folder pick keeps its folder
   * (webkitRelativePath); `options.dir` is a folder on the other side.
   */
  send(files, options = {}) {
    for (const file of files) {
      const name = file.relativeName || file.webkitRelativePath || file.name;
      if (file.size > MAX_FILE_BYTES) this.emit('error', `${name} çok büyük (en fazla 4 GB).`);
      else this.queue.push({ file, name, dir: options.dir || null, kind: options.kind || null });
    }
    if (!this.sending) this.pump();
  }

  /** Sends a clipboard picture (PNG bytes). */
  sendClipImage(png) {
    if (png.length > MAX_CLIP_IMAGE_BYTES) return;
    // Only the newest picture matters: drop older ones still waiting.
    this.queue = this.queue.filter((item) => item.kind !== 'clip-image');
    const blob = new Blob([png], { type: 'image/png' });
    blob.relativeName = 'pano.png';
    this.send([blob], { kind: 'clip-image' });
  }

  async pump() {
    this.sending = true;
    while (this.queue.length && this.channel.readyState === 'open') {
      const item = this.queue.shift();
      try {
        const ok = await this.sendOne(item);
        if (item.kind !== 'clip-image') this.counts[ok ? 'sent' : 'failed'] += 1;
      } catch (err) {
        this.counts.failed += 1;
        this.emit('error', `${item.name} gönderilemedi.`);
        console.warn('[xenon] file send failed', err);
      } finally {
        item.file.close?.();
      }
    }
    this.sending = false;
    if (this.counts.sent || this.counts.failed) this.emit('done', { ...this.counts });
    this.counts = { sent: 0, failed: 0 };
  }

  async sendOne({ file, name, dir, kind }) {
    const id = Math.random().toString(36).slice(2, 10);
    // Clipboard pictures are silent; files and print jobs report progress and results.
    const answer = new Promise((resolve) => this.waiters.set(id, resolve));
    const begin = { t: 'begin', id, name, size: file.size };
    if (dir) begin.dir = dir;
    if (kind) begin.kind = kind;
    this.channel.send(JSON.stringify(begin));
    if ((await answer) !== 'accept') {
      if (kind !== 'clip-image') this.emit('rejected', { name });
      return false;
    }
    let sent = 0;
    const hash = kind === 'clip-image' ? null : new Sha256();
    const meter = new RateMeter();
    while (sent < file.size) {
      if (this.channel.readyState !== 'open') throw new Error('channel closed');
      if (this.channel.bufferedAmount > HIGH_WATER) {
        await new Promise((resolve) => {
          this.channel.onbufferedamountlow = () => {
            this.channel.onbufferedamountlow = null;
            resolve();
          };
        });
      }
      const chunk = await file.slice(sent, sent + CHUNK).arrayBuffer();
      this.channel.send(chunk);
      hash?.update(chunk);
      sent += chunk.byteLength;
      if (kind !== 'clip-image') this.emit('progress', { direction: 'out', name, done: sent, size: file.size, ...meter.update(sent, file.size) });
    }
    const done = new Promise((resolve) => this.waiters.set(`${id}:done`, resolve));
    const end = { t: 'end', id };
    if (hash) end.sha256 = hash.hex();
    this.channel.send(JSON.stringify(end));
    const result = await done;
    if (result.ok) {
      if (kind !== 'clip-image') this.emit('sent', { name, verified: result.verified });
      return true;
    }
    if (kind !== 'clip-image') this.emit('error', result.reason === 'hash' ? `${name} karşı tarafa bozuk ulaştı (doğrulama başarısız), kaydedilmedi.` : `${name} karşı tarafta kaydedilemedi.`);
    return false;
  }

  async onMessage(data) {
    if (typeof data !== 'string') {
      this.onChunk(data);
      return;
    }
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (msg.t === 'accept' || msg.t === 'reject') this.waiters.get(msg.id)?.(msg.t);
    else if (msg.t === 'saved' || msg.t === 'failed') this.waiters.get(`${msg.id}:done`)?.({ ok: msg.t === 'saved', verified: Boolean(msg.verified), reason: msg.reason || null });
    else if (msg.t === 'begin') await this.onBegin(msg);
    else if (msg.t === 'end') await this.onEnd(msg);
  }

  reply(msg) {
    if (this.channel.readyState === 'open') this.channel.send(JSON.stringify(msg));
  }

  async onBegin(msg) {
    const size = Number(msg.size);
    const name = String(msg.name || 'dosya').slice(0, 400);
    if (msg.kind === 'clip-image') {
      // A clipboard picture: kept in memory and put on the clipboard.
      if (this.incoming || !this.canReceiveClip() || !Number.isFinite(size) || size < 0 || size > MAX_CLIP_IMAGE_BYTES) {
        this.reply({ t: 'reject', id: msg.id });
        return;
      }
      this.incoming = { id: msg.id, name, size, received: 0, parts: [], clip: true };
      this.reply({ t: 'accept', id: msg.id });
      return;
    }
    if (this.incoming || !this.canReceive() || !Number.isFinite(size) || size < 0 || size > MAX_FILE_BYTES) {
      this.reply({ t: 'reject', id: msg.id });
      if (!this.canReceive()) this.emit('blocked', { name });
      return;
    }
    try {
      const options = typeof msg.dir === 'string' && msg.dir ? { dir: msg.dir.slice(0, 1000) } : undefined;
      const token = await this.bridge.fileBegin(name, size, options);
      this.incoming = { id: msg.id, name, size, received: 0, token, writes: Promise.resolve(), failed: false, hash: new Sha256(), meter: new RateMeter(), kind: msg.kind === 'print' ? 'print' : null };
      this.reply({ t: 'accept', id: msg.id });
    } catch (err) {
      console.warn('[xenon] cannot receive file', err);
      this.reply({ t: 'reject', id: msg.id });
    }
  }

  onChunk(buffer) {
    const file = this.incoming;
    if (!file) return;
    file.received += buffer.byteLength;
    const chunk = new Uint8Array(buffer);
    if (file.clip) {
      if (file.received <= file.size) file.parts.push(chunk);
      return;
    }
    file.hash.update(chunk);
    file.writes = file.writes.then(() => this.bridge.fileWrite(file.token, chunk)).catch(() => { file.failed = true; });
    this.emit('progress', { direction: 'in', name: file.name, done: file.received, size: file.size, ...file.meter.update(file.received, file.size) });
  }

  async onEnd(msg) {
    const file = this.incoming;
    if (!file || file.id !== msg.id) return;
    this.incoming = null;
    if (file.clip) {
      const ok = file.received === file.size;
      this.reply({ t: ok ? 'saved' : 'failed', id: msg.id });
      if (ok) {
        const bytes = new Uint8Array(file.size);
        let o = 0;
        for (const p of file.parts) { bytes.set(p, o); o += p.length; }
        this.emit('clip-image', bytes);
      }
      return;
    }
    await file.writes;
    const expected = typeof msg.sha256 === 'string' && HEX64.test(msg.sha256) ? msg.sha256 : null;
    const corrupt = Boolean(expected) && file.hash.hex() !== expected;
    const ok = !file.failed && !corrupt && file.received === file.size;
    const path = await this.bridge.fileEnd(file.token, ok).catch(() => null);
    if (ok && path) {
      this.reply({ t: 'saved', id: msg.id, verified: Boolean(expected) });
      this.emit('received', { name: file.name, path, verified: Boolean(expected), kind: file.kind });
    } else {
      this.reply({ t: 'failed', id: msg.id, reason: corrupt ? 'hash' : 'write' });
      this.emit('error', corrupt ? `${file.name} bozuk geldi (doğrulama başarısız), kaydedilmedi.` : `${file.name} alınamadı.`);
    }
  }

  close() {
    if (this.incoming && !this.incoming.clip) this.bridge.fileEnd(this.incoming.token, false).catch(() => {});
    this.incoming = null;
    for (const item of this.queue) item.file.close?.();
    this.queue = [];
    for (const [key, resolve] of this.waiters) resolve(key.endsWith(':done') ? { ok: false } : 'reject');
    this.waiters.clear();
  }
}
