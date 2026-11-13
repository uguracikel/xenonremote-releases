import { Emitter } from './emitter.js';
import { computeProof, deriveSecret } from './auth.js';
import { FileTransfer } from './transfer.js';

const REQUEST_TIMEOUT_MS = 45000;

export const REJECT_MESSAGES = {
  busy: 'Uzak cihaz şu anda başka bir oturumda.',
  locked: 'Çok fazla hatalı deneme. Lütfen bir dakika sonra tekrar deneyin.',
  'bad-password': 'Şifre hatalı.',
  declined: 'Bağlantı isteği reddedildi.',
  'capture-failed': 'Uzak cihaz ekranını paylaşamadı.',
  offline: 'Uzak cihaz çevrimdışı ya da ID hatalı.',
  timeout: 'Uzak cihaz yanıt vermedi.',
  'no-server': 'Ağa veya internete bağlı değilsiniz.',
  'needs-password': 'Cihaz bu ağda bulunamadı. İnternet üzerinden bağlanmak için şifre gerekli.',
  'internet-timeout': 'İnternet üzerinden yanıt alınamadı: şifre hatalı ya da cihaz çevrimdışı.',
  blocked: 'Bu cihazın bağlanması uzak bilgisayarda engellenmiş.',
  'not-trusted': 'Uzak bilgisayar yalnızca güvenilen cihazların bağlanmasına izin veriyor.',
  'bad-totp': 'Doğrulama kodu hatalı ya da süresi geçmiş.',
};

/** How long the person has to type an authenticator code. */
const TOTP_TIMEOUT_MS = 2 * 60 * 1000;

/** Puts the preferred video codec first (answer side); unknown or missing: unchanged. */
export function orderCodecs(codecs, preferred) {
  if (!preferred || preferred === 'auto') return codecs;
  const want = `video/${preferred}`.toLowerCase();
  const first = codecs.filter((c) => c.mimeType.toLowerCase() === want);
  return first.length ? [...first, ...codecs.filter((c) => c.mimeType.toLowerCase() !== want)] : codecs;
}

/** Connection quality from the measured numbers: good | fair | poor. */
export function rateConnection({ rtt = null, lossPct = 0, fps = 0 } = {}) {
  if ((rtt !== null && rtt > 250) || lossPct > 5 || (fps > 0 && fps < 8)) return 'poor';
  if ((rtt !== null && rtt > 120) || lossPct > 1.5 || (fps > 0 && fps < 18)) return 'fair';
  return 'good';
}

/** How the connection is made, from the ICE candidate types in use. */
export function routeOf(localType, remoteType) {
  if (localType === 'relay' || remoteType === 'relay') return 'relay';
  if (localType === 'host' && remoteType === 'host') return 'lan';
  return 'direct';
}

/**
 * Viewer side of a session: requests access to a remote host, answers the
 * password challenge, receives the screen stream and sends input/chat over
 * the data channel.
 *
 * Events: status(text), failed(reason), connected({stream, name}),
 * ended({reason}), chat(text), control(allowed), hello({features, macs, platform}),
 * voice(stream), voice-state(on), idle-warning(seconds), clip-image(bytes),
 * stats({fps, kbps, width, height, rtt, lossPct, jitter, route, codec, quality})
 */
export class ViewerController extends Emitter {
  constructor({ signaling, nostr = null, bridge = null, getDeviceName, getDeviceId = () => null, canReceiveClip = () => false, getCodec = () => 'auto' }) {
    super();
    this.getCodec = getCodec;
    this.canReceiveClip = canReceiveClip;
    this.getDeviceId = getDeviceId;
    this.bridge = bridge;
    this.signaling = signaling;
    this.nostr = nostr;
    this.getDeviceName = getDeviceName;
    this.reset();
  }

  reset() {
    if (this.route === 'nostr' && this.peerId) this.nostr?.closeSession(this.peerId);
    this.route = null; // lan | nostr
    this.targetId = null;
    this.peerId = null;
    this.password = '';
    this.state = 'idle'; // idle | requesting | waiting-approval | waiting-code | connecting | connected
    this.pc = null;
    this.dc = null;
    this.remoteName = '';
    this.pendingCandidates = [];
    this.earlySignals = []; // signals that arrived before the peer connection existed
    this.features = [];
    this.videoStreamId = null;
    this.voiceTransceiver = null;
    this.fsWaiters = new Map(); // id -> { resolve, reject, entries }
    this.mic?.stop();
    this.mic = null;
    clearTimeout(this.timeout);
    clearTimeout(this.dropTimer);
    clearInterval(this.statsTimer);
    this.lastStats = null;
  }

  get busy() {
    return this.state !== 'idle';
  }

  sendSignal(payload) {
    if (this.route === 'nostr') this.nostr?.send(this.peerId, payload);
    else this.signaling.send(this.peerId, payload);
  }

  /** Tries the local network first, then the internet (needs the password). */
  connect(targetId, password) {
    if (this.busy) return;
    const lanOnline = this.signaling.state === 'online';
    const internetOnline = this.nostr?.state === 'online';
    if (!lanOnline && !internetOnline) {
      this.emit('failed', 'no-server');
      return;
    }
    this.targetId = targetId;
    this.password = password || '';
    this.state = 'requesting';
    if (lanOnline) {
      this.route = 'lan';
      this.peerId = targetId;
      this.emit('status', 'Uzak cihaza ulaşılıyor…');
      this.sendSignal(this.connectRequest());
      this.timeout = setTimeout(() => this.fail('timeout'), REQUEST_TIMEOUT_MS);
    } else {
      this.connectOverInternet();
    }
  }

  async connectOverInternet() {
    clearTimeout(this.timeout);
    if (!this.password) {
      this.fail('needs-password');
      return;
    }
    if (this.nostr?.state !== 'online') {
      this.fail('offline');
      return;
    }
    const targetId = this.targetId;
    this.route = 'nostr';
    this.emit('status', 'İnternet üzerinden şifreli bağlantı kuruluyor…');
    const peerId = await this.nostr.openSession(targetId, this.password);
    if (this.targetId !== targetId || this.route !== 'nostr') {
      this.nostr.closeSession(peerId);
      return;
    }
    this.peerId = peerId;
    // Give relays a moment to register our reply subscription.
    await new Promise((r) => setTimeout(r, 400));
    if (this.peerId !== peerId) return;
    this.sendSignal(this.connectRequest());
    this.timeout = setTimeout(() => this.fail('internet-timeout'), REQUEST_TIMEOUT_MS);
  }

  /** The device ID lets the host replace our old session after a dropped connection. */
  connectRequest() {
    return { type: 'connect-request', name: this.getDeviceName(), deviceId: this.getDeviceId() };
  }

  cancel() {
    if (!this.busy) return;
    if (this.state === 'connected') {
      this.end('local-hangup');
      return;
    }
    this.sendSignal({ type: 'hangup' });
    this.cleanup();
    this.reset();
  }

  fail(reason) {
    if (!this.busy) return;
    if (this.peerId && !['offline', 'needs-password'].includes(reason)) this.sendSignal({ type: 'hangup' });
    const wasConnected = this.state === 'connected';
    this.cleanup();
    this.reset();
    if (wasConnected) this.emit('ended', { reason });
    else this.emit('failed', reason);
  }

  handleUnavailable(to) {
    if (!this.busy || this.route !== 'lan' || to !== this.peerId) return;
    // Not on this network: fall back to the internet when possible.
    if (this.nostr?.state === 'online') this.connectOverInternet();
    else this.fail('offline');
  }

  async handleRelay(from, payload) {
    if (!this.busy || from !== this.peerId) return;
    switch (payload.type) {
      case 'challenge': {
        if (this.password) {
          this.emit('status', 'Şifre doğrulanıyor…');
          // A trusted-device key is used as it is; a password is turned into the device secret.
          const secret = this.password instanceof Uint8Array ? this.password : await deriveSecret(this.targetId, this.password);
          const proof = await computeProof(secret, String(payload.nonce || ''));
          if (this.peerId !== from) return;
          this.sendSignal({ type: 'auth', proof });
        } else {
          this.state = 'waiting-approval';
          this.emit('status', 'Uzak kullanıcının onayı bekleniyor…');
          this.sendSignal({ type: 'auth', proof: null });
        }
        break;
      }
      case 'totp-required':
        // Two-step verification: the code from the remote owner's authenticator app.
        clearTimeout(this.timeout);
        this.state = 'waiting-code';
        this.timeout = setTimeout(() => this.fail('timeout'), TOTP_TIMEOUT_MS);
        this.emit('status', 'Doğrulama kodu bekleniyor…');
        this.emit('totp', (code) => {
          if (this.peerId !== from || this.state !== 'waiting-code') return;
          this.state = 'requesting';
          this.emit('status', 'Kod doğrulanıyor…');
          this.sendSignal({ type: 'totp', code: String(code || '').replace(/\s/g, '').slice(0, 6) });
        });
        break;
      case 'accepted':
        clearTimeout(this.timeout);
        this.timeout = setTimeout(() => this.fail('timeout'), REQUEST_TIMEOUT_MS);
        this.state = 'connecting';
        this.remoteName = String(payload.name || '');
        this.emit('status', 'Bağlantı kuruluyor…');
        this.createPeerConnection();
        break;
      case 'rejected':
        this.cleanup();
        this.reset();
        this.emit('failed', payload.reason || 'declined');
        break;
      case 'signal':
        // Relays may deliver out of order: keep signals until the PC exists.
        if (!this.pc) this.earlySignals.push(payload);
        else await this.onSignal(payload);
        break;
      case 'hangup':
        this.end(['idle', 'ip-blocked', 'switched'].includes(payload.reason) ? payload.reason : 'remote-hangup', false);
        break;
      default:
        break;
    }
  }

  createPeerConnection() {
    const pc = new RTCPeerConnection({ iceServers: this.signaling.iceServers });
    this.pc = pc;
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) this.sendSignal({ type: 'signal', candidate: candidate.toJSON() });
    };
    pc.ontrack = (event) => {
      if (event.track.kind === 'audio') {
        // System sound shares the screen's stream; anything else is the
        // host's voice-chat line, which we open both ways for our microphone.
        const sid = event.streams[0]?.id || null;
        if (sid && sid !== this.videoStreamId) {
          this.voiceTransceiver = event.transceiver;
          try { event.transceiver.direction = 'sendrecv'; } catch { /* older engine */ }
          this.emit('voice', new MediaStream([event.track]));
          return;
        }
        // Sound (host system audio) plays separately so it can be muted locally.
        this.emit('audio', new MediaStream([event.track]));
        return;
      }
      const stream = event.streams[0] || new MediaStream([event.track]);
      this.videoStreamId = event.streams[0]?.id || null;
      clearTimeout(this.timeout);
      this.state = 'connected';
      this.emit('connected', { stream, name: this.remoteName, peerId: this.targetId, via: this.route });
      this.startStats();
    };
    pc.ondatachannel = (event) => {
      if (event.channel.label === 'file') {
        this.files = new FileTransfer({ channel: event.channel, bridge: this.bridge, canReceiveClip: () => this.canReceiveClip() });
        this.files.on('clip-image', (bytes) => this.emit('clip-image', bytes));
        this.emit('files', this.files);
        return;
      }
      this.dc = event.channel;
      this.dc.onmessage = (e) => this.onData(e.data);
    };
    pc.onconnectionstatechange = () => {
      if (this.pc !== pc) return;
      clearTimeout(this.dropTimer);
      if (pc.connectionState === 'failed') this.fail('connection-lost');
      // A connection that stays interrupted is given up, so a reconnect can follow.
      else if (pc.connectionState === 'disconnected') this.dropTimer = setTimeout(() => this.pc === pc && this.fail('connection-lost'), 10000);
    };
    const early = this.earlySignals.splice(0);
    (async () => {
      for (const p of early) await this.onSignal(p);
    })();
  }

  async onSignal(payload) {
    const pc = this.pc;
    if (!pc) return;
    try {
      if (payload.description) {
        await pc.setRemoteDescription(payload.description);
        for (const c of this.pendingCandidates.splice(0)) await pc.addIceCandidate(c);
        if (payload.description.type === 'offer') {
          this.applyCodec(pc);
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          this.sendSignal({ type: 'signal', description: pc.localDescription.toJSON() });
        }
      } else if (payload.candidate) {
        if (pc.remoteDescription) await pc.addIceCandidate(payload.candidate);
        else this.pendingCandidates.push(payload.candidate);
      }
    } catch (err) {
      console.warn('[xenon] viewer signal error', err);
    }
  }

  /** Asks the host to send the screen in the codec chosen in Settings (when both support it). */
  applyCodec(pc) {
    const preferred = this.getCodec();
    if (!preferred || preferred === 'auto' || !window.RTCRtpReceiver?.getCapabilities) return;
    const codecs = RTCRtpReceiver.getCapabilities('video')?.codecs || [];
    for (const t of pc.getTransceivers()) {
      if (t.receiver.track?.kind !== 'video' || !t.setCodecPreferences) continue;
      try { t.setCodecPreferences(orderCodecs(codecs, preferred)); } catch { /* engine refused: keep its order */ }
    }
  }

  onData(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (msg.t === 'chat') this.emit('chat', String(msg.text || '').slice(0, 2000));
    else if (msg.t === 'control') this.emit('control', Boolean(msg.allowed));
    else if (msg.t === 'clip' && typeof msg.text === 'string') this.emit('clip', msg.text.slice(0, 100000));
    else if (msg.t === 'screens' && Array.isArray(msg.list)) this.emit('screens', { list: msg.list.slice(0, 16), current: msg.current });
    else if (msg.t === 'privacy') this.emit('privacy', Boolean(msg.on));
    else if (msg.t === 'locked') this.emit('locked', Boolean(msg.on));
    else if (msg.t === 'secure') this.emit('secure', { on: Boolean(msg.on), available: Boolean(msg.available), state: typeof msg.state === 'string' ? msg.state.slice(0, 20) : null });
    else if (msg.t === 'host-recording') this.emit('host-recording', Boolean(msg.on));
    else if (msg.t === 'secure-info') this.emit('secure-info', { frames: Number(msg.frames) || 0, brightness: Number.isFinite(msg.brightness) ? msg.brightness : null, fallback: Boolean(msg.fallback) });
    else if (msg.t === 'input-blocked') this.emit('input-blocked', { on: Boolean(msg.on), byLocal: Boolean(msg.byLocal) });
    else if (msg.t === 'perms' && msg.perms && typeof msg.perms === 'object') this.emit('perms', msg.perms);
    else if (['fs-r', 'sys-r', 'term-r', 'power-r', 'res-r'].includes(msg.t)) this.onFsReply(msg);
    else if (msg.t === 'term-out') this.emit('term-out', { term: String(msg.term), data: String(msg.data || '') });
    else if (msg.t === 'term-exit') this.emit('term-exit', { term: String(msg.term), code: msg.code });
    else if (msg.t === 'trust' && /^[0-9a-f]{64}$/.test(String(msg.key))) this.emit('trust', String(msg.key));
    else if (msg.t === 'voice') this.emit('voice-state', Boolean(msg.on));
    else if (msg.t === 'power-plan') {
      const action = ['sleep', 'hibernate', 'restart', 'shutdown'].includes(msg.action) ? msg.action : null;
      this.emit('power-plan', action ? { action, in: Math.max(0, Number(msg.in) || 0), name: String(msg.name || '').slice(0, 64) } : { action: null, by: String(msg.by || '').slice(0, 64) });
    }
    else if (msg.t === 'idle-warning') this.emit('idle-warning', Number(msg.seconds) || 60);
    else if (msg.t === 'hello') {
      if (msg.name) this.remoteName = String(msg.name);
      this.features = Array.isArray(msg.features) ? msg.features.map(String) : [];
      const macs = Array.isArray(msg.macs) ? msg.macs.map(String).filter((m) => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(m)).slice(0, 4) : [];
      this.emit('platform', msg.platform === 'android' ? 'android' : 'desktop');
      this.emit('hello', { features: this.features, macs, platform: msg.platform === 'android' ? 'android' : 'desktop', os: String(msg.os || '').slice(0, 16), elevated: typeof msg.elevated === 'boolean' ? msg.elevated : null, inputError: msg.inputError ? String(msg.inputError).slice(0, 300) : null });
      this.emit('control', Boolean(msg.control));
      if (msg.voice) this.emit('voice-state', true);
    }
  }

  sendData(msg) {
    if (this.dc && this.dc.readyState === 'open') this.dc.send(JSON.stringify(msg));
  }

  sendInput(event) {
    this.sendData(event);
  }

  sendChat(text) {
    this.sendData({ t: 'chat', text });
  }

  sendClip(text) {
    this.sendData({ t: 'clip', text });
  }

  /** Swap sides: the remote computer connects to us with `key` (one-time) and controls us. */
  switchSides(id, key) {
    this.sendData({ t: 'switch-sides', id, key });
  }

  /** The remote computer's own mouse and keyboard off (Windows) or on again. */
  setInputBlock(on) {
    this.sendData({ t: 'block-input', on: Boolean(on) });
  }

  /** Ctrl+Alt+Del on the remote computer (lock screen; needs its Windows service). */
  sendSas() {
    this.sendData({ t: 'sas' });
  }

  setPrivacy(on) {
    this.sendData({ t: 'privacy', on });
  }

  switchScreen(sourceId) {
    this.sendData({ t: 'switch-screen', sourceId });
  }

  setQuality(value) {
    this.sendData({ t: 'quality', value });
  }

  has(feature) {
    return this.features.includes(feature);
  }

  /** Remote file browser request: roots | list(path) | get(paths). */
  fsRequest(op, data = {}, timeoutMs = 20000) {
    return this.request('fs', op, data, timeoutMs);
  }

  /**
   * Request to the host answered with `${type}-r`: fs, sys (info | procs |
   * kill), term (open), power (lock | sleep | hibernate | restart | shutdown |
   * schedule {action, delay} | cancel).
   */
  request(type, op, data = {}, timeoutMs = 20000) {
    const id = Math.random().toString(36).slice(2, 10);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fsWaiters.delete(id);
        reject(new Error('timeout'));
      }, timeoutMs);
      this.fsWaiters.set(id, { resolve, reject, timer, entries: [] });
      this.sendData({ t: type, id, op, ...data });
    });
  }

  onFsReply(msg) {
    const waiter = this.fsWaiters.get(String(msg.id));
    if (!waiter) return;
    if (msg.list && Array.isArray(msg.list.entries)) {
      // Large folders arrive in several pages.
      waiter.entries.push(...msg.list.entries);
      if (msg.more) return;
      msg = { ...msg, list: { ...msg.list, entries: waiter.entries } };
    }
    clearTimeout(waiter.timer);
    this.fsWaiters.delete(String(msg.id));
    if (msg.error) waiter.reject(new Error(msg.error));
    else waiter.resolve(msg);
  }

  /** Remote command line: input for an open terminal. */
  termInput(term, data) {
    this.sendData({ t: 'term', op: 'in', term, data });
  }

  termClose(term) {
    this.sendData({ t: 'term', op: 'close', term });
  }

  /** Annotation: new points of a stroke (normalized 0..1) drawn on the remote screen. */
  sendDraw(stroke) {
    this.sendData({ t: 'draw', ...stroke });
  }

  clearDrawing() {
    this.sendData({ t: 'draw-clear' });
  }

  /** Tells the host that this session is being recorded. */
  setRecording(on) {
    this.sendData({ t: 'recording', on: Boolean(on) });
  }

  /** Voice chat: our microphone on or off. */
  async setMicrophone(on) {
    if (!this.voiceTransceiver) throw new Error('no-voice');
    if (on && !this.mic) {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
      this.mic = stream.getAudioTracks()[0];
    } else if (!on && this.mic) {
      this.mic.stop();
      this.mic = null;
    }
    await this.voiceTransceiver.sender.replaceTrack(this.mic);
    this.sendData({ t: 'voice', on: Boolean(this.mic) });
    return Boolean(this.mic);
  }

  startStats() {
    clearInterval(this.statsTimer);
    this.statsTimer = setInterval(async () => {
      if (!this.pc) return;
      const report = await this.pc.getStats();
      let inbound = null;
      let rtt = null;
      let pair = null;
      let transport = null;
      report.forEach((s) => {
        if (s.type === 'inbound-rtp' && s.kind === 'video') inbound = s;
        if (s.type === 'transport') transport = s;
        if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') pair = s;
        if (s.type === 'candidate-pair' && s.nominated && s.currentRoundTripTime !== undefined) rtt = s.currentRoundTripTime;
      });
      if (!inbound) return;
      if (transport?.selectedCandidatePairId) pair = report.get(transport.selectedCandidatePairId) || pair;
      const local = pair && report.get(pair.localCandidateId);
      const remote = pair && report.get(pair.remoteCandidateId);
      const codec = inbound.codecId && report.get(inbound.codecId);
      const prev = this.lastStats;
      this.lastStats = { bytes: inbound.bytesReceived, ts: inbound.timestamp, lost: inbound.packetsLost || 0, recv: inbound.packetsReceived || 0 };
      const kbps = prev ? Math.round(((inbound.bytesReceived - prev.bytes) * 8) / (inbound.timestamp - prev.ts)) : 0;
      const lost = prev ? Math.max(0, (inbound.packetsLost || 0) - prev.lost) : 0;
      const recv = prev ? Math.max(0, (inbound.packetsReceived || 0) - prev.recv) : 0;
      const lossPct = lost + recv ? Math.round((lost / (lost + recv)) * 1000) / 10 : 0;
      const fps = Math.round(inbound.framesPerSecond || 0);
      const ms = rtt !== null ? Math.round(rtt * 1000) : null;
      this.emit('stats', {
        fps,
        kbps,
        width: inbound.frameWidth || 0,
        height: inbound.frameHeight || 0,
        rtt: ms,
        lossPct,
        jitter: inbound.jitter !== undefined ? Math.round(inbound.jitter * 1000) : null,
        route: local && remote ? routeOf(local.candidateType, remote.candidateType) : null,
        codec: codec?.mimeType ? codec.mimeType.split('/')[1] : '',
        freezes: inbound.freezeCount || 0,
        quality: rateConnection({ rtt: ms, lossPct, fps }),
      });
    }, 1000);
  }

  cleanup() {
    this.files?.close();
    this.files = null;
    for (const w of this.fsWaiters.values()) {
      clearTimeout(w.timer);
      w.reject(new Error('closed'));
    }
    this.fsWaiters.clear();
    clearTimeout(this.timeout);
    clearInterval(this.statsTimer);
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
  }

  end(reason = 'local-hangup', notify = true) {
    if (!this.busy) return;
    if (notify) this.sendSignal({ type: 'hangup' });
    this.cleanup();
    this.reset();
    this.emit('ended', { reason });
  }
}
