// Bridge to the native Android screen-sharing plugin (ScreenShare).
//
// On Android the WebView usually cannot do getDisplayMedia(), so the phone
// shares its screen through a native MediaProjection + WebRTC PeerConnection.
// Authentication and SDP/ICE relaying stay in JS (over Nostr); this module
// only drives the native peer: it produces the offer, accepts the remote
// answer and exchanges ICE candidates. The native peer also opens the
// "control" and "file" data channels; NativeChannel exposes them to JS with
// the RTCDataChannel API so chat, files and input work like on the desktop.

const DEFAULT_ICE = [{ urls: ['stun:stun.l.google.com:19302'] }];

const PLUGIN = 'ScreenShare';

/** The Capacitor native bridge (no @capacitor/core in this bundle). */
function bridge() {
  const cap = globalThis.Capacitor;
  if (!cap || typeof cap.isNativePlatform !== 'function' || !cap.isNativePlatform()) return null;
  if (typeof cap.nativePromise !== 'function' || typeof cap.addListener !== 'function') return null;
  return cap;
}

/** Thin wrapper over the bridge: call(method, options) and on(event, cb). */
function plugin() {
  const cap = bridge();
  if (!cap) return null;
  return {
    call: (method, options = {}) => cap.nativePromise(PLUGIN, method, options),
    on: (event, cb) => cap.addListener(PLUGIN, event, (data, err) => { if (!err) cb(data || {}); }),
  };
}

function toBase64(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function fromBase64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/** A native data channel with the subset of the RTCDataChannel API the app uses. */
export class NativeChannel {
  constructor(api, label) {
    this.api = api;
    this.label = label;
    this.readyState = 'connecting';
    this.binaryType = 'arraybuffer';
    this.bufferedAmount = 0;
    this.bufferedAmountLowThreshold = 0;
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onbufferedamountlow = null;
    this.sending = Promise.resolve();
  }

  send(data) {
    if (this.readyState !== 'open') throw new Error('channel not open');
    const binary = typeof data !== 'string';
    const payload = binary ? toBase64(data) : data;
    if (binary) this.bufferedAmount += data.byteLength;
    // Calls run in order on the plugin thread; track the native buffer level.
    this.sending = this.api.call('dcSend', { label: this.label, data: payload, binary })
      .then(({ buffered }) => this.setBuffered(buffered))
      .catch(() => {});
  }

  setBuffered(amount) {
    const was = this.bufferedAmount;
    this.bufferedAmount = Number(amount) || 0;
    if (was > this.bufferedAmountLowThreshold && this.bufferedAmount <= this.bufferedAmountLowThreshold) this.onbufferedamountlow?.();
  }

  setState(state) {
    if (state === this.readyState) return;
    this.readyState = state;
    if (state === 'open') this.onopen?.();
    if (state === 'closed') this.onclose?.();
  }

  receive({ data, binary }) {
    this.onmessage?.({ data: binary ? fromBase64(data) : data });
  }

  close() {
    this.setState('closed');
  }
}

/** True when running inside the Android app where native capture is available. */
export function nativeScreenShareAvailable() {
  return Boolean(plugin());
}

/**
 * Runs one native screen-sharing session as the host.
 *
 * Events: ended(reason)
 * Signaling is done by the caller via `send` ({type:'signal', description|candidate}).
 */
export class NativeHostSession {
  constructor({ iceServers, send, onEnded, onState }) {
    this.api = plugin();
    this.iceServers = iceServers && iceServers.length ? iceServers : DEFAULT_ICE;
    this.send = send;
    this.onEnded = onEnded;
    this.onState = onState;
    this.subs = [];
    this.ready = false; // candidates are held until the offer has been sent
    this.queued = [];
    this.channels = { control: new NativeChannel(this.api, 'control'), file: new NativeChannel(this.api, 'file') };
  }

  channel(label) {
    return this.channels[label];
  }

  /** Call after the offer was sent: releases ICE candidates gathered meanwhile. */
  flush() {
    this.ready = true;
    for (const msg of this.queued.splice(0)) this.send(msg);
  }

  /** Shows the system capture consent, starts capture and returns the SDP offer. */
  async startAndOffer() {
    this.subs.push(this.api.on('iceCandidate', (c) => {
      const msg = { type: 'signal', candidate: { candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex } };
      if (this.ready) this.send(msg);
      else this.queued.push(msg);
    }));
    this.subs.push(this.api.on('dcState', ({ label, state }) => this.channels[label]?.setState(state)));
    this.subs.push(this.api.on('dcMessage', (msg) => this.channels[msg.label]?.receive(msg)));
    this.subs.push(this.api.on('dcBuffered', ({ label, amount }) => this.channels[label]?.setBuffered(amount)));
    this.subs.push(this.api.on('ended', () => this.onEnded?.('capture-ended')));
    this.subs.push(this.api.on('connectionState', ({ state }) => {
      this.onState?.(String(state || ''));
      if (state === 'FAILED' || state === 'CLOSED') this.onEnded?.('connection-lost');
    }));
    const offer = await this.api.call('start', { iceServers: this.iceServers });
    return offer; // { type:'offer', sdp }
  }

  async onSignal(payload) {
    if (payload.description) {
      await this.api.call('setRemoteDescription', { type: payload.description.type, sdp: payload.description.sdp });
    } else if (payload.candidate) {
      await this.api.call('addIceCandidate', {
        sdpMid: payload.candidate.sdpMid,
        sdpMLineIndex: payload.candidate.sdpMLineIndex ?? 0,
        candidate: payload.candidate.candidate,
      });
    }
  }

  async close() {
    for (const ch of Object.values(this.channels)) ch.close();
    for (const sub of this.subs) {
      try {
        await sub.remove?.();
      } catch {
        // listener already gone
      }
    }
    this.subs = [];
    try {
      await this.api.call('stop');
    } catch {
      // plugin already stopped
    }
  }
}
