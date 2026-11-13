import { Emitter } from './emitter.js';
import { computeProof, generateNonce, safeEqual, secretToHex } from './auth.js';
import { FileTransfer, PathFile } from './transfer.js';
import { NativeHostSession, nativeScreenShareAvailable } from './native-host.js';
import { ALL_SCREENS, captureAllScreens } from './composite.js';
import { verifyTotp } from './totp.js';
import { ipAllowed, remoteAddress } from './ip-allow.js';

const MAX_FAILED_ATTEMPTS = 5;
/** How long a viewer has to type the authenticator code. */
const TOTP_WAIT_MS = 2 * 60 * 1000;
/** Label of the permanent (unattended access) password among the accepted secrets. */
export const UNATTENDED_LABEL = 'unattended';
/** Label of the one-time key a viewer gives when it asks to swap sides. */
export const SWITCH_LABEL = 'switch';
const LOCKOUT_MS = 60 * 1000;

// Bitrates are ceilings: WebRTC's bandwidth estimation adapts below them.
export const QUALITY_PRESETS = {
  auto: { maxBitrate: 6_000_000, maxFramerate: 30, scaleResolutionDownBy: 1 },
  high: { maxBitrate: 10_000_000, maxFramerate: 30, scaleResolutionDownBy: 1 },
  balanced: { maxBitrate: 2_500_000, maxFramerate: 24, scaleResolutionDownBy: 1 },
  low: { maxBitrate: 800_000, maxFramerate: 15, scaleResolutionDownBy: 2 },
};
/** Larger screens (e.g. 4K) are encoded at most this wide; full size overloads the encoder. */
const MAX_ENCODE_WIDTH = 1920;
/** "All monitors" side by side may be wider. */
const MAX_ENCODE_WIDTH_ALL = 3840;
/** Viewers are warned this long before an idle session is closed. */
const IDLE_WARNING_MS = 60 * 1000;
/** Folder listings are sent in pages (data channel messages have a size limit). */
const FS_PAGE = 250;

/** Sessions that may watch this device at the same time (like AnyDesk). */
export const MAX_SESSIONS = 5;
/** A connection that stays "disconnected" this long is considered dead. */
const DISCONNECT_GRACE_MS = 10000;

/**
 * What a connected viewer may use besides watching. Remote control (mouse and
 * keyboard) is the master switch; the others narrow it down further, and
 * anything that writes to this computer (files, clipboard) also
 * needs control.
 */
export const DEFAULT_PERMISSIONS = { clipboard: true, files: true, audio: true, draw: true, terminal: true, system: true, power: true };

/** Power actions a viewer may run now; the timed ones may also be scheduled. */
export const POWER_NOW = ['lock', 'sleep', 'hibernate', 'restart', 'shutdown'];
export const POWER_TIMED = ['sleep', 'hibernate', 'restart', 'shutdown'];
/** A scheduled power action: at least a minute, at most a day ahead. */
const POWER_DELAY_MIN = 60;
const POWER_DELAY_MAX = 24 * 60 * 60;

/** Terminal output is split into messages of at most this many characters. */
const TERM_CHUNK = 32000;

/** "trusted:123456789" -> "123456789" (the key a trusted device connected with). */
export function trustedDeviceOf(label) {
  const m = /^trusted:(\d{9})$/.exec(String(label || ''));
  return m ? m[1] : null;
}

/** Permissions that do not need remote control (they write nothing here). */
const WITHOUT_CONTROL = new Set(['audio', 'draw']);

/** Average brightness (0..255) of a picture, from a tiny copy of it. */
function brightnessOf(bitmap) {
  try {
    const c = typeof OffscreenCanvas === 'function' ? new OffscreenCanvas(16, 9) : Object.assign(document.createElement('canvas'), { width: 16, height: 9 });
    const ctx = c.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, 16, 9);
    const px = ctx.getImageData(0, 0, 16, 9).data;
    let sum = 0;
    for (let i = 0; i < px.length; i += 4) sum += (px[i] + px[i + 1] + px[i + 2]) / 3;
    return Math.round(sum / (px.length / 4));
  } catch {
    return null;
  }
}

/** On Linux, system sound is a PulseAudio/PipeWire "Monitor of …" input. */
async function linuxSystemAudio() {
  const devices = await navigator.mediaDevices.enumerateDevices();
  const monitor = devices.find((d) => d.kind === 'audioinput' && /monitor/i.test(d.label));
  if (!monitor) return null;
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { deviceId: { exact: monitor.deviceId }, echoCancellation: false, noiseSuppression: false, autoGainControl: false },
  });
  return stream.getAudioTracks()[0] || null;
}

/**
 * Host side: answers incoming connection requests, verifies the password (or
 * asks the local user), streams the screen over WebRTC and forwards permitted
 * remote input to the main process.
 *
 * Several viewers may be connected at once: they share one screen capture
 * and each has its own peer connection, data channels and control right.
 * A viewer that reconnects (same device ID) replaces its own old session,
 * and a connection that drops is cleaned up automatically.
 *
 * Events: request({peerId, name, respond(accepted, allowControl)}),
 * request-cancelled(peerId), started({peerId, name, via}), ended({peerId, name, reason}),
 * sessions([{peerId, name, via, control}]), chat({peerId, name, text}), control(allowed),
 * privacy(on), files(transfer), clip(text), clip-image(bytes), voice({peerId, stream}),
 * recording({peerId, name, on}), error(message)
 */
export class HostController extends Emitter {
  constructor({
    signaling, nostr = null, bridge, getSecrets, getScreenSourceId, getDeviceName, isBusy = () => false,
    getPermissions = () => DEFAULT_PERMISSIONS, getIdleMs = () => 0, platform = '', getHelloExtras = async () => ({}),
    getAccess = () => ({ mode: 'all', blocked: [] }), onTrust = async () => false,
    getTrustedPerms = () => null, getTotp = async () => null, getAllowedIps = () => [],
    getSecureState = () => null,
  }) {
    super();
    this.getSecureState = getSecureState; // why the lock screen service is not usable here (told to viewers)
    this.getTotp = getTotp; // the authenticator secret when the permanent password needs a code too
    this.getAllowedIps = getAllowedIps; // IP allow list (empty: any address)
    this.totpUsed = -1; // last accepted time step (a code works once)
    this.getTrustedPerms = getTrustedPerms; // deviceId -> { control, clipboard, … } or null (defaults)
    this.getAccess = getAccess; // { mode: all | trusted, blocked: [device IDs] }
    this.onTrust = onTrust; // async ({ deviceId, name, secret }) => stored?
    this.terminals = new Map(); // terminal id -> session
    bridge?.onTerm?.((id, text) => this.onTermData(id, text), (id, code) => this.onTermExit(id, code));
    this.getIdleMs = getIdleMs; // idle sessions are closed after this long (0 = never)
    this.platform = platform; // 'linux' etc.: picks the system sound source
    this.getHelloExtras = getHelloExtras; // e.g. MAC addresses for Wake-on-LAN
    this.mic = null; // this side's microphone track (voice chat)
    this.voiceStream = new MediaStream();
    this.idleTimer = null;
    this.signaling = signaling;
    this.nostr = nostr;
    this.bridge = bridge;
    this.getSecrets = getSecrets; // async () => [Uint8Array] accepted device secrets
    this.getPermissions = getPermissions; // defaults for new sessions (Settings)
    this.getScreenSourceId = getScreenSourceId;
    this.nativeScreen = nativeScreenShareAvailable(); // Android phone-as-host
    this.getDeviceName = getDeviceName;
    this.isBusy = isBusy;
    this.pending = null; // { peerId, name, deviceId, nonce, awaitingApproval }
    this.sessions = new Map(); // peerId -> session
    this.capture = null; // shared screen capture { stream, track, sourceId }
    this.failures = [];
    this.privacy = false;
    this.locked = false; // this computer's session is locked
    this.starting = false;
    this.powerPlan = null; // { action, at, name, timer } scheduled by a viewer
    this.hostRecording = false; // this computer records incoming sessions (viewers are told)
    this.inputBlocked = false; // the local mouse/keyboard is blocked for a viewer (Windows)
    bridge?.onBlockEnded?.(() => this.setInputBlocked(false, true));
    // Windows lock screen / UAC prompts through the Xenon Remote Service.
    this.secure = { desktop: 'Default', connected: false, on: false, canvas: null, writer: null, track: null, drawing: false, frames: 0, brightness: null, usingCapture: false };
    bridge?.onSecure?.((m) => this.onSecure(m));
  }

  onSecure(m) {
    if (!m || typeof m.t !== 'string') return;
    if (m.t === 'secure-desktop') {
      const wasAvailable = this.secure.connected;
      this.secure.connected = Boolean(m.connected);
      this.secure.desktop = String(m.name || 'Default');
      this.updateSecure(wasAvailable !== this.secure.connected);
    } else if (m.t === 'secure-frame' && this.secure.on) {
      this.drawSecureFrame(m.data);
    }
  }

  /**
   * While the lock screen (or a UAC prompt) has the input, viewers get the
   * service's pictures of it instead of the normal capture, which shows
   * nothing then; when the normal desktop is back, the capture returns.
   */
  updateSecure(availabilityChanged = false) {
    const want = this.sessions.size > 0 && this.secure.connected && this.secure.desktop !== 'Default' && !this.nativeScreen;
    if (want !== this.secure.on) {
      this.secure.on = want;
      this.bridge.secureStream?.(want);
      const track = want ? this.ensureSecureTrack() : this.capture?.track;
      for (const session of this.sessions.values()) if (session.sender && track && !session.ipCheck) session.sender.replaceTrack(track).catch(() => {});
      clearTimeout(this.secure.checkTimer);
      this.secure.frames = 0;
      this.secure.brightness = null;
      this.secure.usingCapture = false;
      if (want) this.secure.checkTimer = setTimeout(() => this.checkSecurePictures(), 4000);
    } else if (!availabilityChanged) {
      return;
    }
    this.sendData(this.secureMessage());
    this.sendData({ t: 'locked', on: this.locked && !this.secure.on });
    this.emit('secure', { on: this.secure.on, available: this.secure.connected });
  }

  /** The shared monitor's resolution (needs control): list or set; put back when everyone left. */
  async onResolution(session, msg) {
    if (!session.control || !this.bridge.displayModes) {
      this.reply(session, msg, { error: 'denied' });
      return;
    }
    try {
      if (msg.op === 'list') {
        this.reply(session, msg, { display: await this.bridge.displayModes() });
      } else if (msg.op === 'set') {
        await this.bridge.displaySet(String(msg.mode || ''));
        this.resolutionChanged = true;
        this.reply(session, msg, { ok: true });
      } else if (msg.op === 'restore') {
        await this.bridge.displayRestore();
        this.resolutionChanged = false;
        this.reply(session, msg, { ok: true });
      } else {
        this.reply(session, msg, { error: 'unknown' });
      }
    } catch (err) {
      this.reply(session, msg, { error: String(err?.message || err).slice(0, 200) });
    }
  }

  /** Blocks (or frees) this computer's own mouse and keyboard while viewers work. */
  async blockInput(on) {
    const active = on && this.controlAllowed ? Boolean(await this.bridge.blockInput?.(true).catch(() => false)) : false;
    if (!on || !active) await Promise.resolve(this.bridge.blockInput?.(false)).catch(() => {});
    this.setInputBlocked(active);
  }

  /** `byLocal`: the person here ended it (Ctrl+Alt+Del › Lock). */
  setInputBlocked(on, byLocal = false) {
    this.inputBlocked = Boolean(on);
    this.sendData({ t: 'input-blocked', on: this.inputBlocked, byLocal });
    this.emit('input-blocked', { on: this.inputBlocked, byLocal });
  }

  /** A print job of the "Xenon Remote Yazıcı": sent to the viewers allowed to receive files. */
  sendPrintJob({ path, size }) {
    const name = String(path).split(/[\\/]/).pop();
    let sent = 0;
    for (const session of this.sessions.values()) {
      if (!session.files || !session.perms.files) continue;
      session.files.send([new PathFile(this.bridge, { path, rel: `Yazdırılanlar/${name}`, size })], { kind: 'print' });
      sent += 1;
    }
    return sent;
  }

  /** This computer records the session (Settings): every viewer is told. */
  setHostRecording(on) {
    this.hostRecording = Boolean(on);
    this.sendData({ t: 'host-recording', on: this.hostRecording });
  }

  secureMessage() {
    // `state`: not-installed | needs-admin | waiting | error, so the viewer can say what is missing.
    return { t: 'secure', on: this.secure.on, available: this.secure.connected, state: this.secure.connected ? 'connected' : this.getSecureState() || null };
  }

  /**
   * The track that carries the service's pictures. A track generator takes
   * each picture as a video frame directly; a canvas stream (older engines)
   * only produces frames while the page is drawn, which stops while Windows
   * is locked, so viewers would see black.
   */
  ensureSecureTrack() {
    if (this.secure.track && this.secure.track.readyState === 'live') return this.secure.track;
    let track;
    if (typeof MediaStreamTrackGenerator === 'function' && typeof VideoFrame === 'function') {
      track = new MediaStreamTrackGenerator({ kind: 'video' });
      this.secure.writer = track.writable.getWriter();
      this.secure.canvas = null;
    } else {
      const canvas = document.createElement('canvas');
      canvas.width = 1280;
      canvas.height = 720;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      [track] = canvas.captureStream(15).getVideoTracks();
      this.secure.canvas = canvas;
      this.secure.writer = null;
    }
    if ('contentHint' in track) track.contentHint = 'detail';
    this.secure.track = track;
    return track;
  }

  async drawSecureFrame(data) {
    if ((!this.secure.writer && !this.secure.canvas) || this.secure.drawing) return; // busy with the previous picture: skip this one
    this.secure.drawing = true;
    try {
      const bitmap = await createImageBitmap(new Blob([data], { type: 'image/jpeg' }));
      this.secure.frames += 1;
      if (this.secure.frames % 5 === 1) this.secure.brightness = brightnessOf(bitmap);
      if (this.secure.writer) {
        const frame = new VideoFrame(bitmap, { timestamp: Math.round(performance.now() * 1000) });
        bitmap.close?.();
        try {
          await this.secure.writer.write(frame);
        } finally {
          frame.close();
        }
      } else {
        const canvas = this.secure.canvas;
        if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
        }
        canvas.getContext('2d').drawImage(bitmap, 0, 0);
        bitmap.close?.();
      }
    } catch { /* a damaged picture: wait for the next one */ } finally {
      this.secure.drawing = false;
    }
  }

  /**
   * A few seconds after the lock screen took over: if the service sent no
   * picture, or only black ones (some graphics cards hide the secure desktop
   * from it), viewers get the normal screen capture back when there is one
   * (it shows the lock screen on recent Windows); input still goes through
   * the service. Viewers are told what was seen, for troubleshooting.
   */
  checkSecurePictures() {
    if (!this.secure.on) return;
    const { frames, brightness } = this.secure;
    const unusable = frames === 0 || (brightness !== null && brightness < 4);
    const capture = this.capture?.track;
    const fallback = unusable && capture && capture.readyState === 'live' && capture !== this.secure.track;
    if (fallback) {
      this.secure.usingCapture = true;
      for (const session of this.sessions.values()) if (session.sender && !session.ipCheck) session.sender.replaceTrack(capture).catch(() => {});
    }
    this.sendData({ t: 'secure-info', frames, brightness, fallback: Boolean(fallback) });
  }

  /** The OS session got locked/unlocked: viewers show why the screen is unusable. */
  setLocked(locked) {
    this.locked = Boolean(locked);
    this.sendData({ t: 'locked', on: this.locked && !this.secure.on });
  }

  get active() {
    return this.sessions.size > 0;
  }

  /** What this host offers besides the screen (older viewers ignore it). */
  get features() {
    if (this.nativeScreen) return [];
    const list = ['voice', 'clip-image'];
    if (this.bridge.fsList) list.push('fs');
    if (this.bridge.drawStroke) list.push('draw');
    if (this.bridge.termOpen) list.push('terminal');
    if (this.bridge.systemInfo) list.push('system');
    if (this.bridge.power) list.push('power', 'power-plan');
    if (this.bridge.setTrusted) list.push('trust');
    list.push('switch');
    if (this.bridge.blockInput && this.platform === 'win32') list.push('block-input');
    if (this.bridge.displayModes && ['win32', 'linux'].includes(this.platform)) list.push('resolution');
    return list;
  }

  async sendHello(session, extra = {}) {
    const extras = await this.getHelloExtras().catch(() => ({}));
    this.sendTo(session, { t: 'hello', name: this.getDeviceName(), control: session.control, features: this.features, ...extras, ...extra });
  }

  /** The (first) active session; kept for single-session callers. */
  get session() {
    return this.sessions.values().next().value || null;
  }

  /** True while any connected viewer may control this device. */
  get controlAllowed() {
    for (const s of this.sessions.values()) if (s.control) return true;
    return false;
  }

  isLockedOut() {
    const now = Date.now();
    this.failures = this.failures.filter((t) => now - t < LOCKOUT_MS);
    return this.failures.length >= MAX_FAILED_ATTEMPTS;
  }

  send(peerId, payload) {
    if (String(peerId).startsWith('nostr:')) this.nostr?.send(peerId, payload);
    else this.signaling.send(peerId, payload);
  }

  /** `meta.authenticated` means the transport already proved the password. */
  async handleRelay(from, payload, meta = {}) {
    switch (payload.type) {
      case 'connect-request':
        return this.onConnectRequest(from, payload, meta);
      case 'auth':
        return this.onAuth(from, payload);
      case 'totp':
        return this.onTotp(from, payload);
      case 'signal':
        return this.onSignal(from, payload);
      case 'hangup':
        if (this.pending?.peerId === from) {
          if (this.pending.awaitingApproval) this.emit('request-cancelled', from);
          this.pending = null;
        }
        if (this.sessions.has(from)) this.endSession(from, 'remote-hangup', false);
        return undefined;
      default:
        return undefined;
    }
  }

  /** An older session of the same viewer device (it reconnected after a drop). */
  staleSessionOf(deviceId) {
    if (!deviceId) return null;
    for (const s of this.sessions.values()) if (s.deviceId === deviceId) return s;
    return null;
  }

  onConnectRequest(from, payload, meta = {}) {
    const deviceId = /^\d{9}$/.test(String(payload.deviceId || '')) ? String(payload.deviceId) : null;
    const replacing = this.staleSessionOf(deviceId);
    const full = this.nativeScreen ? this.sessions.size >= 1 : this.sessions.size >= MAX_SESSIONS;
    if (this.sessions.has(from) || this.pending || this.starting || this.isBusy() || (full && !replacing)) {
      this.send(from, { type: 'rejected', reason: 'busy' });
      return;
    }
    const name = String(payload.name || '').slice(0, 64);
    const access = this.getAccess() || {};
    if (deviceId && (access.blocked || []).includes(deviceId)) {
      this.send(from, { type: 'rejected', reason: 'blocked' });
      this.emit('refused', { peerId: from, name, reason: 'blocked' });
      return;
    }
    if (meta.authenticated) {
      // Internet request: decrypting it already proved knowledge of the password
      // (or of a trusted device's key, given by meta.label).
      const trusted = trustedDeviceOf(meta.label);
      if (meta.label === SWITCH_LABEL) {
        // The other side asked us to take control of it (swap sides): its own one-time key.
        this.emit('switch-used');
        this.accept({ peerId: from, name, deviceId, via: 'internet', trusted: null }, true);
        return;
      }
      if (access.mode === 'trusted' && !trusted) {
        this.send(from, { type: 'rejected', reason: 'not-trusted' });
        this.emit('refused', { peerId: from, name, reason: 'not-trusted' });
        return;
      }
      const info = { peerId: from, name, deviceId: trusted || deviceId, via: 'internet', trusted };
      if (meta.label === UNATTENDED_LABEL) this.secondStep(info);
      else this.accept(info, true);
      return;
    }
    if (this.isLockedOut()) {
      this.send(from, { type: 'rejected', reason: 'locked' });
      this.emit('refused', { peerId: from, name, reason: 'locked' });
      return;
    }
    this.pending = { peerId: from, name, deviceId, nonce: generateNonce(), awaitingApproval: false };
    this.send(from, { type: 'challenge', nonce: this.pending.nonce });
    // Drop requests that never finish the handshake.
    const pending = this.pending;
    setTimeout(() => {
      if (this.pending === pending && !pending.awaitingApproval) this.pending = null;
    }, 30000);
  }

  async onAuth(from, payload) {
    const pending = this.pending;
    if (!pending || pending.peerId !== from || pending.awaitingApproval) return;

    const access = this.getAccess() || {};
    if (payload.proof) {
      // Accepted secrets: plain (one-time / permanent password) or { secret, label }.
      const secrets = (await this.getSecrets()).map((s) => (s instanceof Uint8Array ? { secret: s, label: null } : s));
      const expected = await Promise.all(secrets.map(({ secret }) => computeProof(secret, pending.nonce)));
      if (this.pending !== pending) return;
      const index = expected.findIndex((proof) => safeEqual(payload.proof, proof));
      const trusted = index >= 0 ? trustedDeviceOf(secrets[index].label) : null;
      if (index >= 0 && secrets[index].label === SWITCH_LABEL) {
        this.pending = null;
        this.emit('switch-used');
        await this.accept({ ...pending, trusted: null }, true);
      } else if (index >= 0 && access.mode === 'trusted' && !trusted) {
        this.pending = null;
        this.send(from, { type: 'rejected', reason: 'not-trusted' });
        this.emit('refused', { peerId: from, name: pending.name, reason: 'not-trusted' });
      } else if (index >= 0) {
        this.pending = null;
        const info = { ...pending, deviceId: trusted || pending.deviceId, trusted };
        if (secrets[index].label === UNATTENDED_LABEL) await this.secondStep(info);
        else await this.accept(info, true);
      } else {
        this.failures.push(Date.now());
        this.pending = null;
        this.send(from, { type: 'rejected', reason: 'bad-password' });
        this.emit('refused', { peerId: from, name: pending.name, reason: 'bad-password' });
      }
      return;
    }

    // Only trusted devices may connect: no asking.
    if (access.mode === 'trusted') {
      this.pending = null;
      this.send(from, { type: 'rejected', reason: 'not-trusted' });
      this.emit('refused', { peerId: from, name: pending.name, reason: 'not-trusted' });
      return;
    }
    // No password: the person at this computer decides.
    pending.awaitingApproval = true;
    this.bridge.attention('Gelen bağlantı isteği', `${pending.name || from} ekranınıza bağlanmak istiyor.`);
    this.emit('request', {
      peerId: from,
      name: pending.name,
      respond: (accepted, allowControl) => {
        if (this.pending !== pending) return;
        this.pending = null;
        if (accepted) this.accept(pending, allowControl);
        else {
          this.send(from, { type: 'rejected', reason: 'declined' });
          this.emit('refused', { peerId: from, name: pending.name, reason: 'declined' });
        }
      },
    });
  }

  /**
   * The permanent password was right. With two-step verification on, the
   * viewer must also send the code from the authenticator app.
   */
  async secondStep(info) {
    const secret = await this.getTotp().catch(() => null);
    if (!secret) {
      await this.accept(info, true);
      return;
    }
    if (this.pending || this.isLockedOut()) {
      this.send(info.peerId, { type: 'rejected', reason: this.pending ? 'busy' : 'locked' });
      return;
    }
    const pending = { peerId: info.peerId, name: info.name, deviceId: info.deviceId, info, awaitingTotp: true };
    this.pending = pending;
    this.send(info.peerId, { type: 'totp-required' });
    setTimeout(() => {
      if (this.pending === pending) this.pending = null;
    }, TOTP_WAIT_MS);
  }

  async onTotp(from, payload) {
    const pending = this.pending;
    if (!pending || pending.peerId !== from || !pending.awaitingTotp) return;
    this.pending = null;
    const secret = await this.getTotp().catch(() => null);
    const step = secret ? await verifyTotp(secret, payload.code, { notAfter: this.totpUsed }) : -1;
    if (step < 0) {
      this.failures.push(Date.now());
      this.send(from, { type: 'rejected', reason: 'bad-totp' });
      this.emit('refused', { peerId: from, name: pending.name, reason: 'bad-totp' });
      return;
    }
    this.totpUsed = step;
    await this.accept(pending.info, true);
  }

  /** Ends the old session of a reconnecting device before its new one starts. */
  replaceStale(deviceId) {
    const old = this.staleSessionOf(deviceId);
    if (old) this.endSession(old.peerId, 'replaced', true);
  }

  /** IP allow list: lets the session go on only when the peer's address is on it. */
  async checkPeerIp(session) {
    let addr = null;
    try {
      addr = await remoteAddress(session.pc);
    } catch { /* no statistics: refused below */ }
    if (this.sessions.get(session.peerId) !== session || !session.ipCheck) return;
    if (addr?.ip && ipAllowed(addr.ip, this.getAllowedIps() || [])) {
      session.ipCheck = false;
      const track = this.secure.on ? this.secure.track : this.capture?.track;
      if (track) session.sender.replaceTrack(track).catch(() => {});
      if (session.perms.audio && session.audioSender) session.audioSender.replaceTrack(this.capture?.audioTrack || null).catch(() => {});
      return;
    }
    this.emit('refused', { peerId: session.peerId, name: session.name, reason: 'ip-blocked', ip: addr?.ip || '' });
    this.endSession(session.peerId, 'ip-blocked', true);
  }

  /** Watches a peer connection state; a drop that does not recover ends the session. */
  watchConnection(session, state) {
    if (this.sessions.get(session.peerId) !== session) return;
    if (state === 'connected') {
      clearTimeout(session.dropTimer);
      session.dropTimer = null;
      if (session.ipCheck) this.checkPeerIp(session);
    } else if (state === 'disconnected') {
      if (!session.dropTimer) {
        session.dropTimer = setTimeout(() => this.endSession(session.peerId, 'connection-lost', true), DISCONNECT_GRACE_MS);
      }
    } else if (state === 'failed' || state === 'closed') {
      this.endSession(session.peerId, 'connection-lost', true);
    }
  }

  addSession(session) {
    this.sessions.set(session.peerId, session);
    if (this.secure.on && session.sender && this.secure.track && !session.ipCheck && !this.secure.usingCapture) session.sender.replaceTrack(this.secure.track).catch(() => {});
    this.startIdleTimer();
    this.emit('files', session.files, session.peerId);
    this.emitSessions();
    this.updateSecure();
  }

  emitSessions() {
    this.emit('sessions', [...this.sessions.values()].map(({ peerId, name, via, control, perms, recording, trusted, deviceId, terms }) => ({
      peerId, name, via, control, deviceId, trusted, recording: Boolean(recording), terminal: Boolean(terms?.size), perms: { ...perms },
    })));
  }

  /** Android host: share the phone screen via the native MediaProjection peer. */
  async acceptNative({ peerId, name, deviceId, via, trusted = null }, allowControl) {
    if (this.starting) return;
    this.replaceStale(deviceId);
    if (this.sessions.size) {
      this.send(peerId, { type: 'rejected', reason: 'busy' });
      return;
    }
    this.starting = true;
    let session = null;
    const native = new NativeHostSession({
      iceServers: this.signaling?.iceServers,
      send: (payload) => this.send(peerId, payload),
      onEnded: (reason) => { if (session && this.sessions.get(peerId) === session) this.endSession(peerId, reason, true); },
      onState: (state) => { if (session) this.watchConnection(session, state.toLowerCase()); },
    });
    try {
      const offer = await native.startAndOffer();
      const dc = native.channel('control');
      const own = trusted ? this.getTrustedPerms(trusted) : null;
      if (own && 'control' in own) allowControl = allowControl && Boolean(own.control);
      session = { peerId, name, deviceId, via, native, dc, trusted, control: false, perms: this.newPermissions(own), lastActivity: Date.now(), terms: new Set() };
      session.files = new FileTransfer({
        channel: native.channel('file'),
        bridge: this.bridge,
        canReceive: () => this.allows(session, 'files'),
      });
      dc.onopen = () => {
        this.sendHello(session, { platform: 'android' });
        this.sendPerms(session);
        this.sendScreens(session);
      };
      dc.onmessage = (event) => this.onData(session, event.data);
      this.addSession(session);
      this.send(peerId, { type: 'accepted', name: this.getDeviceName() });
      this.send(peerId, { type: 'signal', description: offer });
      native.flush();
      // Control needs the accessibility service; without it the PC only watches.
      const inputReady = await this.bridge.inputAvailable().catch(() => false);
      this.setSessionControl(session, allowControl && inputReady);
      this.emit('started', { peerId, name, via });
    } catch (err) {
      console.error('[xenon] native screen share failed', err);
      await native.close();
      if (session) this.sessions.delete(peerId);
      const denied = String(err?.message || '').includes('permission-denied');
      this.send(peerId, { type: 'rejected', reason: denied ? 'declined' : 'capture-failed' });
      this.emit('error', denied ? 'Ekran paylaşımı reddedildi.' : `Ekran paylaşımı başlatılamadı: ${err?.message || err}`);
    } finally {
      this.starting = false;
    }
  }

  async captureScreen() {
    if (this.getScreenSourceId() === ALL_SCREENS) return this.captureAll();
    const selected = await this.bridge.selectScreen(this.getScreenSourceId());
    if (String(this.getScreenSourceId()).startsWith('window:') && !selected) {
      const e = new Error('window-gone');
      e.xenonReason = 'Paylaşılacak pencere kapatılmış. Ekran seçiminden başka bir ekran veya pencere seçin.';
      throw e;
    }
    if (!navigator.mediaDevices?.getDisplayMedia) {
      const e = new Error('no-display-media');
      e.xenonReason = 'Bu cihaz ekran paylaşımını desteklemiyor. (Android\'de "Android System WebView" ve Chrome\'u Play Store\'dan güncelleyin.)';
      throw e;
    }
    try {
      return await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: { ideal: 30, max: 30 } },
        audio: true, // system sound where the platform provides it (Windows)
      });
    } catch (err) {
      if (!selected?.sourceId) throw err;
      // Fallback for Electron builds where getDisplayMedia is unavailable.
      return navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { mandatory: { chromeMediaSource: 'desktop', chromeMediaSourceId: selected.sourceId, maxFrameRate: 30 } },
      });
    }
  }

  /** Every monitor in one picture; the sound comes from a normal capture of the main screen. */
  async captureAll() {
    let audioTrack = null;
    if (this.platform !== 'linux') {
      try {
        const base = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
        base.getVideoTracks().forEach((t) => t.stop());
        audioTrack = base.getAudioTracks()[0] || null;
      } catch { /* picture without sound */ }
    }
    const all = await captureAllScreens(this.bridge);
    if (audioTrack) all.stream.addTrack(audioTrack);
    this.compositeStop = all.stop;
    return all.stream;
  }

  /** The shared screen capture, started with the first viewer. */
  async ensureCapture() {
    if (this.capture) return this.capture;
    let stream;
    try {
      stream = await this.captureScreen();
    } catch (err) {
      // Sign-in / lock screen without a picture of the normal desktop: the
      // Windows service's pictures of the secure desktop stand in for it.
      if (!this.secure.connected) throw err;
      console.warn('[xenon] screen capture failed; using the lock screen service', err);
      stream = new MediaStream([this.ensureSecureTrack()]);
    }
    const [track] = stream.getVideoTracks();
    if ('contentHint' in track) track.contentHint = 'detail';
    let audioTrack = stream.getAudioTracks()[0] || null;
    // Linux: no loopback with the screen; use the sound card's monitor input.
    if (!audioTrack && this.platform === 'linux') audioTrack = await linuxSystemAudio().catch(() => null);
    const capture = { stream, track, audioTrack, sourceId: this.getScreenSourceId(), stop: this.compositeStop || null };
    this.compositeStop = null;
    track.onended = () => {
      if (this.capture === capture) this.end('capture-ended');
    };
    this.capture = capture;
    return capture;
  }

  stopCapture() {
    const capture = this.capture;
    this.capture = null;
    if (!capture) return;
    capture.track.onended = null;
    capture.stop?.();
    capture.stream.getTracks().forEach((t) => t.stop());
    capture.audioTrack?.stop();
  }

  async accept({ peerId, name, deviceId = null, via = 'lan', trusted = null }, allowControl) {
    if (this.nativeScreen) return this.acceptNative({ peerId, name, deviceId, via, trusted }, allowControl);
    this.replaceStale(deviceId);
    let capture;
    this.starting = true;
    try {
      capture = await this.ensureCapture();
    } catch (err) {
      console.error('[xenon] screen capture failed', err);
      this.send(peerId, { type: 'rejected', reason: 'capture-failed' });
      this.emit('error', err?.xenonReason || 'Ekran yakalanamadı. Ekran kaydı iznini kontrol edin.');
      return;
    } finally {
      this.starting = false;
    }

    const pc = new RTCPeerConnection({ iceServers: this.signaling.iceServers });
    const sender = pc.addTrack(capture.track, capture.stream);
    // Voice chat: an audio line of its own (before the system sound, which
    // older viewers expect last), open both ways so either side can switch a
    // microphone on later without renegotiating.
    const voice = pc.addTransceiver('audio', { direction: 'sendrecv', streams: [this.voiceStream] });
    if (this.mic) voice.sender.replaceTrack(this.mic).catch(() => {});
    const dc = pc.createDataChannel('control', { ordered: true });
    const own = trusted ? this.getTrustedPerms(trusted) : null;
    if (own && 'control' in own) allowControl = allowControl && Boolean(own.control);
    const session = { peerId, name, deviceId, via, pc, dc, sender, voice, trusted, control: false, perms: this.newPermissions(own), lastActivity: Date.now(), terms: new Set() };
    pc.ontrack = (event) => {
      if (event.track.kind === 'audio' && event.transceiver === voice) this.emit('voice', { peerId, stream: new MediaStream([event.track]) });
    };
    if (capture.audioTrack) {
      // addTransceiver, not addTrack: addTrack would reuse the (still empty) voice line.
      session.audioSender = pc.addTransceiver(capture.audioTrack, { direction: 'sendonly', streams: [capture.stream] }).sender;
      if (!session.perms.audio) session.audioSender.replaceTrack(null);
    }
    session.files = new FileTransfer({
      channel: pc.createDataChannel('file', { ordered: true }),
      bridge: this.bridge,
      // Files from a viewer need both remote control and the file permission.
      canReceive: () => this.allows(session, 'files'),
      canReceiveClip: () => this.allows(session, 'clipboard'),
    });
    session.files.on('clip-image', (bytes) => this.emit('clip-image', bytes));
    // IP allow list: nothing is shown or accepted until the peer's address is checked.
    const allowed = this.getAllowedIps() || [];
    if (allowed.length) {
      session.ipCheck = true;
      sender.replaceTrack(null).catch(() => {});
      session.audioSender?.replaceTrack(null).catch(() => {});
    }
    this.addSession(session);

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) this.send(peerId, { type: 'signal', candidate: candidate.toJSON() });
    };
    pc.onconnectionstatechange = () => this.watchConnection(session, pc.connectionState);

    dc.onopen = () => {
      this.sendHello(session, this.mic ? { voice: true } : {});
      this.sendPerms(session);
      this.sendScreens(session);
      if (this.locked && !this.secure.on) this.sendTo(session, { t: 'locked', on: true });
      if (this.powerPlan) this.sendTo(session, this.powerPlanMessage());
      this.sendTo(session, this.secureMessage());
      if (this.hostRecording) this.sendTo(session, { t: 'host-recording', on: true });
    };
    dc.onmessage = (event) => this.onData(session, event.data);

    this.send(peerId, { type: 'accepted', name: this.getDeviceName() });
    // Without a working input module the viewer must see "view only", not a dead control.
    const inputReady = allowControl ? await this.bridge.inputAvailable().catch(() => false) : false;
    this.setSessionControl(session, allowControl && inputReady);
    await this.applyQuality(session, 'auto');

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this.send(peerId, { type: 'signal', description: pc.localDescription.toJSON() });
    this.emit('started', { peerId, name, via, trusted });
  }

  /** True while only one window is shared: viewers may not switch to a whole screen. */
  get windowOnly() {
    return String(this.capture?.sourceId || this.getScreenSourceId() || '').startsWith('window:');
  }

  async sendScreens(session) {
    const current = this.capture?.sourceId || this.getScreenSourceId();
    let list;
    if (this.windowOnly) {
      list = [{ sourceId: current, name: 'Paylaşılan pencere', primary: false }];
    } else {
      const screens = await this.bridge.listScreens().catch(() => []);
      list = screens.map((s, i) => ({ sourceId: s.sourceId, name: s.primary ? 'Ana ekran' : `Ekran ${i + 1}`, primary: Boolean(s.primary) }));
      if (list.length > 1 && !this.nativeScreen) list.push({ sourceId: ALL_SCREENS, name: 'Tüm ekranlar', primary: false });
    }
    const msg = { t: 'screens', current, list };
    if (session) this.sendTo(session, msg);
    else this.sendData(msg);
  }

  /** Shows another monitor to all viewers without reconnecting. */
  async switchScreen(sourceId) {
    const capture = this.capture;
    if (!capture) return;
    let stream;
    let stopComposite = null;
    try {
      let selected;
      if (sourceId === ALL_SCREENS) {
        const all = await captureAllScreens(this.bridge);
        stream = all.stream;
        stopComposite = all.stop;
        selected = { sourceId: ALL_SCREENS };
      } else {
        selected = await this.bridge.selectScreen(sourceId);
        if (!selected) return;
        stream = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 30, max: 30 } }, audio: false }); // sound keeps flowing
      }
      if (this.capture !== capture) {
        stopComposite?.();
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      const [track] = stream.getVideoTracks();
      if ('contentHint' in track) track.contentHint = 'detail';
      // While the lock screen is shown, viewers keep its pictures; the new screen comes after.
      if (!this.secure.on) await Promise.all([...this.sessions.values()].filter((s) => s.sender && !s.ipCheck).map((s) => s.sender.replaceTrack(track)));
      capture.track.onended = null;
      capture.stop?.();
      capture.stream.getVideoTracks().forEach((t) => t.stop());
      capture.stream = stream;
      capture.track = track;
      capture.stop = stopComposite;
      capture.sourceId = selected.sourceId;
      for (const session of this.sessions.values()) this.applyQuality(session, session.quality || 'auto');
      track.onended = () => {
        if (this.capture === capture && capture.track === track) this.end('capture-ended');
      };
      this.sendScreens();
    } catch (err) {
      console.warn('[xenon] screen switch failed', err);
      stopComposite?.();
      stream?.getTracks().forEach((t) => t.stop());
    }
  }

  async onSignal(from, payload) {
    const session = this.sessions.get(from);
    if (!session) return;
    if (session.native) {
      try {
        await session.native.onSignal(payload);
      } catch (err) {
        console.warn('[xenon] native signal error', err);
      }
      return;
    }
    try {
      if (payload.description) await session.pc.setRemoteDescription(payload.description);
      else if (payload.candidate) await session.pc.addIceCandidate(payload.candidate);
    } catch (err) {
      console.warn('[xenon] host signal error', err);
    }
  }

  onData(session, raw) {
    if (this.sessions.get(session.peerId) !== session) return;
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (!msg || typeof msg.t !== 'string' || session.ipCheck) return;
    session.lastActivity = Date.now();
    session.idleWarned = false;
    if (msg.t === 'fs') {
      this.onFs(session, msg);
    } else if (msg.t === 'term') {
      this.onTerm(session, msg);
    } else if (msg.t === 'sys') {
      this.onSys(session, msg);
    } else if (msg.t === 'power') {
      this.onPower(session, msg);
    } else if (msg.t === 'draw') {
      if (this.allows(session, 'draw') && Array.isArray(msg.pts)) {
        this.bridge.drawStroke?.({ id: `${session.peerId}:${msg.id}`, pts: msg.pts.slice(0, 500), color: msg.color, done: Boolean(msg.done) });
      }
    } else if (msg.t === 'draw-clear') {
      if (this.allows(session, 'draw')) this.bridge.drawClear?.();
    } else if (msg.t === 'recording') {
      session.recording = Boolean(msg.on);
      this.emit('recording', { peerId: session.peerId, name: session.name, on: session.recording });
      this.emitSessions();
    } else if (msg.t === 'voice') {
      this.emit('voice-state', { peerId: session.peerId, name: session.name, on: Boolean(msg.on) });
    } else if (msg.t === 'chat') {
      this.emit('chat', { peerId: session.peerId, name: session.name, text: String(msg.text || '').slice(0, 2000) });
    } else if (msg.t === 'clip') {
      if (this.allows(session, 'clipboard') && typeof msg.text === 'string') this.emit('clip', msg.text.slice(0, 100000));
    } else if (msg.t === 'switch-sides') {
      // The viewer wants to be controlled by this computer instead.
      const id = String(msg.id || '');
      const key = String(msg.key || '');
      if (/^\d{9}$/.test(id) && /^[0-9a-f]{64}$/.test(key)) {
        this.endSession(session.peerId, 'switched', true);
        this.emit('switch-sides', { id, key, name: session.name });
      }
    } else if (msg.t === 'res') {
      this.onResolution(session, msg);
    } else if (msg.t === 'block-input') {
      if (session.control || !msg.on) this.blockInput(Boolean(msg.on));
    } else if (msg.t === 'sas') {
      // Ctrl+Alt+Del (lock screen, sign-in): only through the Windows service.
      if (session.control && this.secure.connected) this.bridge.secureSas?.();
    } else if (msg.t === 'switch-screen') {
      // The person here chose to share one window only: viewers cannot widen that.
      const target = String(msg.sourceId || '');
      if (session.control && !this.windowOnly && !target.startsWith('window:')) this.switchScreen(target);
    } else if (msg.t === 'privacy') {
      if (session.control || !msg.on) this.setPrivacy(Boolean(msg.on));
    } else if (msg.t === 'quality') {
      if (QUALITY_PRESETS[msg.value]) session.quality = msg.value;
      this.applyQuality(session, msg.value);
    } else if (session.control && ['mm', 'md', 'mu', 'wh', 'kd', 'ku', 'tx', 'nav'].includes(msg.t)) {
      this.bridge.sendInput(msg);
    }
  }

  sendTo(session, msg) {
    const dc = session?.dc;
    if (dc && dc.readyState === 'open') dc.send(JSON.stringify(msg));
  }

  /** Sends a message to every connected viewer. */
  sendData(msg) {
    for (const session of this.sessions.values()) this.sendTo(session, msg);
  }

  /** A new session's permissions: the Settings defaults, or a trusted device's own. */
  newPermissions(own = null) {
    const defaults = { ...DEFAULT_PERMISSIONS, ...(this.getPermissions() || {}), ...(own || {}) };
    return Object.fromEntries(Object.keys(DEFAULT_PERMISSIONS).map((k) => [k, Boolean(defaults[k])]));
  }

  /** Whether a session may use a feature. Writing features also need remote control. */
  allows(session, name) {
    if (!session?.perms?.[name]) return false;
    return WITHOUT_CONTROL.has(name) ? true : session.control;
  }

  sendPerms(session) {
    this.sendTo(session, { t: 'perms', perms: { ...session.perms, control: session.control } });
  }

  /** The host's permission toggles: applied to every connected viewer. */
  setPermission(name, on) {
    if (!(name in DEFAULT_PERMISSIONS)) return;
    for (const session of this.sessions.values()) {
      session.perms[name] = Boolean(on);
      if (name === 'audio' && session.audioSender && !session.ipCheck) session.audioSender.replaceTrack(on ? this.capture?.audioTrack || null : null).catch(() => {});
      this.sendPerms(session);
    }
    for (const [id, session] of this.terminals) if (!this.allows(session, 'terminal')) this.closeTerminal(id);
    this.emit('perms', this.currentPermissions());
    this.emitSessions();
  }

  /** Permissions shown in the host banner (those of the first session). */
  currentPermissions() {
    return { ...(this.session?.perms || this.newPermissions()) };
  }

  /** Shares this computer's clipboard with the viewers allowed to see it. */
  sendClip(text) {
    for (const session of this.sessions.values()) {
      if (session.perms.clipboard) this.sendTo(session, { t: 'clip', text });
    }
  }

  get clipboardShared() {
    for (const s of this.sessions.values()) if (s.perms.clipboard) return true;
    return false;
  }

  /** Shares a clipboard picture with the viewers allowed to see the clipboard. */
  sendClipImage(png) {
    for (const session of this.sessions.values()) {
      if (session.perms.clipboard) session.files.sendClipImage(png);
    }
  }

  sendChat(text) {
    this.sendData({ t: 'chat', text });
  }

  /** Voice chat: this side's microphone on or off for every viewer. */
  async setMicrophone(on) {
    if (on && !this.mic) {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
      this.mic = stream.getAudioTracks()[0];
    } else if (!on && this.mic) {
      this.mic.stop();
      this.mic = null;
    }
    for (const session of this.sessions.values()) {
      session.voice?.sender.replaceTrack(this.mic).catch(() => {});
      this.sendTo(session, { t: 'voice', on: Boolean(this.mic) });
    }
    return Boolean(this.mic);
  }

  /** Remote file browser: folder listings and downloads (needs the file permission). */
  async onFs(session, msg) {
    const id = String(msg.id || '');
    const reply = (data) => this.sendTo(session, { t: 'fs-r', id, ...data });
    if (!this.allows(session, 'files') || !this.bridge.fsList) {
      reply({ error: 'denied' });
      return;
    }
    try {
      if (msg.op === 'roots') {
        reply({ roots: await this.bridge.fsRoots() });
      } else if (msg.op === 'list') {
        const { entries, ...meta } = await this.bridge.fsList(String(msg.path || ''));
        for (let i = 0; i === 0 || i < entries.length; i += FS_PAGE) {
          reply({ list: { ...meta, entries: entries.slice(i, i + FS_PAGE) }, more: i + FS_PAGE < entries.length });
        }
      } else if (msg.op === 'get') {
        const paths = (Array.isArray(msg.paths) ? msg.paths : [msg.path]).slice(0, 200).map(String);
        const items = await this.bridge.fsExpand(paths);
        if (!items.length) {
          reply({ error: 'empty' });
          return;
        }
        reply({ count: items.length, size: items.reduce((n, it) => n + it.size, 0) });
        session.files.send(items.map((it) => new PathFile(this.bridge, it)));
      } else {
        reply({ error: 'unknown' });
      }
    } catch (err) {
      reply({ error: String(err?.message || err).slice(0, 200) });
    }
  }

  /** Replies to a viewer request ({t, id, op}) with `${t}-r`. */
  reply(session, msg, data) {
    this.sendTo(session, { t: `${msg.t}-r`, id: String(msg.id || ''), ...data });
  }

  /** Remote command line (needs control and the "terminal" permission). */
  async onTerm(session, msg) {
    if (msg.op === 'open') {
      if (!this.allows(session, 'terminal') || !this.bridge.termOpen) {
        this.reply(session, msg, { error: 'denied' });
        return;
      }
      try {
        const id = await this.bridge.termOpen();
        if (this.sessions.get(session.peerId) !== session) {
          this.bridge.termClose(id);
          return;
        }
        this.terminals.set(id, session);
        session.terms.add(id);
        this.reply(session, msg, { term: id });
        this.emit('terminal', { peerId: session.peerId, name: session.name, open: true });
        this.emitSessions();
      } catch (err) {
        this.reply(session, msg, { error: String(err?.message || err).slice(0, 200) });
      }
    } else if (msg.op === 'in') {
      if (session.terms.has(msg.term) && this.allows(session, 'terminal')) this.bridge.termWrite(msg.term, String(msg.data || '').slice(0, 10000));
    } else if (msg.op === 'close') {
      if (session.terms.has(msg.term)) this.closeTerminal(msg.term);
    }
  }

  onTermData(id, text) {
    const session = this.terminals.get(id);
    if (!session) return;
    for (let i = 0; i < text.length; i += TERM_CHUNK) this.sendTo(session, { t: 'term-out', term: id, data: text.slice(i, i + TERM_CHUNK) });
  }

  onTermExit(id, code) {
    const session = this.terminals.get(id);
    if (!session) return;
    this.terminals.delete(id);
    session.terms.delete(id);
    this.sendTo(session, { t: 'term-exit', term: id, code });
    this.emitSessions();
  }

  closeTerminal(id) {
    const session = this.terminals.get(id);
    this.terminals.delete(id);
    session?.terms.delete(id);
    this.bridge.termClose?.(id);
    if (session) this.emitSessions();
  }

  /** System information and task manager (needs control and the "system" permission). */
  async onSys(session, msg) {
    if (!this.allows(session, 'system') || !this.bridge.systemInfo) {
      this.reply(session, msg, { error: 'denied' });
      return;
    }
    try {
      if (msg.op === 'info') this.reply(session, msg, { info: await this.bridge.systemInfo() });
      else if (msg.op === 'procs') this.reply(session, msg, { procs: (await this.bridge.processList()).slice(0, 2000) });
      else if (msg.op === 'kill') {
        await this.bridge.processKill(Number(msg.pid));
        this.reply(session, msg, { ok: true });
        this.emit('admin', { peerId: session.peerId, name: session.name, action: 'kill', detail: String(msg.label || msg.pid).slice(0, 80) });
      } else this.reply(session, msg, { error: 'unknown' });
    } catch (err) {
      this.reply(session, msg, { error: String(err?.message || err).slice(0, 200) });
    }
  }

  /**
   * Power menu (needs control and the "power" permission): lock, sleep,
   * hibernate, restart or shut down now, or one of them on a timer that the
   * person at this computer sees counting down and can cancel.
   */
  async onPower(session, msg) {
    const op = String(msg.op || '');
    const known = POWER_NOW.includes(op) || op === 'schedule' || op === 'cancel';
    if (!this.allows(session, 'power') || !this.bridge.power || !known) {
      this.reply(session, msg, { error: 'denied' });
      return;
    }
    if (op === 'cancel') {
      this.cancelPowerPlan(session.name || 'uzak kullanıcı');
      this.reply(session, msg, { ok: true });
      return;
    }
    if (op === 'schedule') {
      const action = String(msg.action || '');
      const delay = Math.round(Number(msg.delay));
      if (!POWER_TIMED.includes(action) || !Number.isFinite(delay) || delay < POWER_DELAY_MIN || delay > POWER_DELAY_MAX) {
        this.reply(session, msg, { error: 'bad-request' });
        return;
      }
      this.schedulePower(action, delay, session.name);
      this.emit('admin', { peerId: session.peerId, name: session.name, action: 'schedule', detail: `${action} ${delay}` });
      this.reply(session, msg, { ok: true });
      return;
    }
    this.emit('admin', { peerId: session.peerId, name: session.name, action: op });
    try {
      if (op === 'sleep' || op === 'hibernate') {
        // The answer must leave before the computer goes to sleep.
        this.reply(session, msg, { ok: true });
        await new Promise((r) => setTimeout(r, 800));
        await this.bridge.power(op);
        return;
      }
      await this.bridge.power(op);
      this.reply(session, msg, { ok: true });
    } catch (err) {
      this.reply(session, msg, { error: String(err?.message || err).slice(0, 200) });
    }
  }

  powerPlanMessage() {
    const plan = this.powerPlan;
    return plan ? { t: 'power-plan', action: plan.action, in: Math.max(0, Math.round((plan.at - Date.now()) / 1000)), name: plan.name } : { t: 'power-plan', action: null };
  }

  /** Runs `action` after `delay` seconds unless cancelled (a new plan replaces the old one). */
  schedulePower(action, delay, name = '') {
    clearTimeout(this.powerPlan?.timer);
    const plan = { action, at: Date.now() + delay * 1000, name: String(name || '').slice(0, 64), timer: null };
    plan.timer = setTimeout(() => {
      if (this.powerPlan !== plan) return;
      this.powerPlan = null;
      this.emit('power-plan', null);
      this.sendData({ t: 'power-plan', action: null });
      this.bridge.power(action).catch((err) => this.emit('error', `Zamanlanmış işlem çalıştırılamadı: ${err?.message || err}`));
    }, delay * 1000);
    this.powerPlan = plan;
    this.emit('power-plan', { action, at: plan.at, name: plan.name });
    this.sendData(this.powerPlanMessage());
  }

  /** Cancels the scheduled power action (by the person here, `local`, or a viewer). */
  cancelPowerPlan(by = '', { local = false } = {}) {
    if (!this.powerPlan) return false;
    clearTimeout(this.powerPlan.timer);
    this.powerPlan = null;
    this.emit('power-plan', null, local ? null : by);
    this.sendData({ t: 'power-plan', action: null, by: String(by || '').slice(0, 64) });
    return true;
  }

  /**
   * Gives a connected device a permanent key of its own: it can then connect
   * without the password (and without asking) until the key is removed here.
   */
  async trustSession(peerId) {
    const session = this.sessions.get(peerId);
    if (!session?.deviceId) return false;
    const secret = secretToHex(crypto.getRandomValues(new Uint8Array(32)));
    const stored = await this.onTrust({ deviceId: session.deviceId, name: session.name, secret });
    if (!stored) return false;
    session.trusted = session.deviceId;
    this.sendTo(session, { t: 'trust', key: secret });
    this.emitSessions();
    return true;
  }

  /** Closes sessions in which nothing happened for the configured time. */
  checkIdle() {
    const limit = this.getIdleMs();
    if (!limit) return;
    const now = Date.now();
    for (const session of [...this.sessions.values()]) {
      const idle = now - (session.lastActivity || now);
      if (idle >= limit) {
        this.endSession(session.peerId, 'idle', true);
      } else if (idle >= limit - IDLE_WARNING_MS && !session.idleWarned) {
        session.idleWarned = true;
        this.sendTo(session, { t: 'idle-warning', seconds: Math.round((limit - idle) / 1000) });
      }
    }
  }

  startIdleTimer() {
    if (!this.idleTimer) this.idleTimer = setInterval(() => this.checkIdle(), 5000);
  }

  setSessionControl(session, allowed) {
    session.control = Boolean(allowed);
    this.sendTo(session, { t: 'control', allowed: session.control });
    this.sendPerms(session);
    this.applyControl();
  }

  /** The host's toggle: allows or forbids control for all connected viewers. */
  setControlAllowed(allowed) {
    for (const session of this.sessions.values()) {
      session.control = Boolean(allowed);
      this.sendTo(session, { t: 'control', allowed: session.control });
      this.sendPerms(session);
    }
    this.applyControl();
  }

  applyControl() {
    // Command lines need remote control: closed when it is taken away.
    for (const [id, session] of this.terminals) if (!this.allows(session, 'terminal')) this.closeTerminal(id);
    const any = this.controlAllowed;
    if (!any && this.inputBlocked) {
      this.bridge.blockInput?.(false)?.catch?.(() => {}); // (the main process also frees it with control)
      this.setInputBlocked(false);
    }
    this.bridge.setControlAllowed(any);
    this.emit('control', any);
    this.emitSessions();
    // Privacy mode requires remote control; it is dropped together with it.
    if (!any && this.privacy) this.setPrivacy(false);
  }

  /** Screen blanking on the host. Only while remote control is allowed. */
  async setPrivacy(on) {
    const want = Boolean(on) && this.controlAllowed;
    const active = Boolean(await this.bridge.setPrivacy?.(want));
    this.privacy = active;
    this.sendData({ t: 'privacy', on: active });
    this.emit('privacy', active);
  }

  async applyQuality(session, name) {
    const preset = QUALITY_PRESETS[name];
    const sender = session?.sender;
    if (!preset || !sender) return;
    const params = sender.getParameters();
    if (!params.encodings || !params.encodings.length) params.encodings = [{}];
    const enc = params.encodings[0];
    Object.assign(enc, preset);
    const width = this.capture?.track.getSettings?.().width || 0;
    const maxWidth = this.capture?.sourceId === ALL_SCREENS ? MAX_ENCODE_WIDTH_ALL : MAX_ENCODE_WIDTH;
    if (width > maxWidth) enc.scaleResolutionDownBy = Math.max(enc.scaleResolutionDownBy, width / maxWidth);
    // Screen content defaults to "keep resolution at any cost", which drops
    // the frame rate to almost nothing on a weak link or busy CPU (freezes).
    params.degradationPreference = 'balanced';
    try {
      await sender.setParameters(params);
    } catch {
      // Older engines reject degradationPreference: apply the rest without it.
      delete params.degradationPreference;
      try {
        await sender.setParameters(params);
      } catch (err) {
        console.warn('[xenon] could not apply quality preset', err);
      }
    }
  }

  /** Ends one viewer's session. `notify` tells that peer to hang up as well. */
  endSession(peerId, reason = 'local-hangup', notify = true) {
    const session = this.sessions.get(peerId);
    if (!session) return;
    this.sessions.delete(peerId);
    clearTimeout(session.dropTimer);
    for (const id of [...(session.terms || [])]) this.closeTerminal(id);
    if (notify) this.send(peerId, { type: 'hangup', reason });
    session.files.close();
    if (session.native) session.native.close();
    else session.pc.close();
    if (String(peerId).startsWith('nostr:')) setTimeout(() => this.nostr?.closeSession(peerId), 2000);
    if (!this.sessions.size) {
      if (this.resolutionChanged) {
        this.resolutionChanged = false;
        this.bridge.displayRestore?.().catch(() => {});
      }
      this.stopCapture();
      this.bridge.drawEnd?.();
      clearInterval(this.idleTimer);
      this.idleTimer = null;
    }
    this.applyControl();
    this.updateSecure();
    this.emit('ended', { peerId, name: session.name, reason, remaining: this.sessions.size });
  }

  /** Ends all sessions. */
  end(reason = 'local-hangup', notify = true) {
    for (const peerId of [...this.sessions.keys()]) this.endSession(peerId, reason, notify);
  }
}
