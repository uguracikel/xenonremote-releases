// Session extras: clipboard sync, special key combos and screenshots.

/**
 * Keeps the text clipboard in sync with the peer while `isEnabled()` is true.
 * Polls the local clipboard (Electron only) and applies remote changes.
 */
export class ClipboardSync {
  constructor({ bridge, send, sendImage = null, isEnabled }) {
    this.bridge = bridge;
    this.send = send;
    this.sendImage = sendImage;
    this.isEnabled = isEnabled;
    this.timer = null;
    this.last = null;
    this.lastImage = null; // hash of the clipboard picture already shared
    this.ticks = 0;
  }

  get supported() {
    return typeof this.bridge.readClipboard === 'function' && typeof this.bridge.writeClipboard === 'function';
  }

  /** Pictures (screenshots, copied images) are shared too where the bridge can read them. */
  get imageSupported() {
    return typeof this.bridge.readClipboardImage === 'function' && typeof this.bridge.writeClipboardImage === 'function';
  }

  async start() {
    if (!this.supported) return;
    this.stop();
    this.last = await this.bridge.readClipboard().catch(() => null); // only share new copies
    if (this.imageSupported) this.lastImage = (await this.bridge.readClipboardImage(null).catch(() => null))?.hash || null;
    this.timer = setInterval(() => this.poll(), 1000);
  }

  async poll() {
    if (!this.isEnabled()) return;
    this.ticks += 1;
    const text = await this.bridge.readClipboard().catch(() => null);
    if (typeof text === 'string' && text !== this.last && text && text.length <= 100000) {
      this.last = text;
      this.send(text);
    }
    // Pictures are checked every other second (hashing a big image costs more).
    if (this.ticks % 2 || !this.imageSupported || !this.sendImage) return;
    const image = await this.bridge.readClipboardImage(this.lastImage).catch(() => null);
    if (!image || image.hash === this.lastImage) return;
    this.lastImage = image.hash;
    if (image.png) this.sendImage(image.png);
  }

  async apply(text) {
    if (!this.supported || !this.isEnabled()) return;
    this.last = text;
    await this.bridge.writeClipboard(text).catch(() => {});
  }

  async applyImage(png) {
    if (!this.imageSupported || !this.isEnabled()) return;
    const hash = await this.bridge.writeClipboardImage(png).catch(() => null);
    if (hash) this.lastImage = hash;
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }
}

/** "ControlLeft+ShiftLeft+Escape" -> key down in order, key up in reverse. */
export function comboEvents(spec) {
  const codes = String(spec).split('+').filter(Boolean);
  return [...codes.map((code) => ({ t: 'kd', code })), ...codes.reverse().map((code) => ({ t: 'ku', code }))];
}

/** Captures the current video frame as PNG bytes. */
export async function captureFrame(video) {
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  return new Uint8Array(await blob.arrayBuffer());
}

export function timestampName(prefix, ext) {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${prefix}-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${ext}`;
}

/** Saves bytes through the bridge file API; returns the saved path/name. */
export async function saveBytes(bridge, name, bytes) {
  const token = await bridge.fileBegin(name, bytes.length);
  const CHUNK = 256 * 1024;
  for (let i = 0; i < bytes.length; i += CHUNK) await bridge.fileWrite(token, bytes.subarray(i, i + CHUNK));
  return bridge.fileEnd(token, true);
}
