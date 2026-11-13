import { Emitter } from './emitter.js';

/**
 * WebSocket client for the Xenon signaling server. Reconnects automatically
 * and re-registers with the same ID so the ID stays stable for the user.
 *
 * Events: status(state), registered({id, iceServers}), relay(from, payload),
 * unavailable(to, ref)
 */
export class SignalingClient extends Emitter {
  constructor({ url, id }) {
    super();
    this.url = url;
    this.id = id || null;
    this.baseIceServers = [{ urls: ['stun:stun.l.google.com:19302'] }];
    this.relayIceServers = []; // user-configured TURN relays
    this.ws = null;
    this.state = 'offline';
    this.retry = 0;
    this.retryTimer = null;
    this.stopped = false;
  }

  /** STUN from the server (or default) plus the user's TURN relays. */
  get iceServers() {
    return [...this.baseIceServers, ...this.relayIceServers];
  }

  set iceServers(list) {
    this.baseIceServers = list;
  }

  setRelayServers(list) {
    this.relayIceServers = Array.isArray(list) ? list : [];
  }

  setStatus(state) {
    this.state = state;
    this.emit('status', state);
  }

  connect() {
    this.stopped = false;
    clearTimeout(this.retryTimer);
    if (!this.url) {
      this.setStatus('offline');
      return;
    }
    this.setStatus('connecting');
    let ws;
    try {
      ws = new WebSocket(this.url);
    } catch (err) {
      console.warn('[xenon] invalid signaling url', err);
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.retry = 0;
      ws.send(JSON.stringify({ type: 'register', id: this.id }));
    };
    ws.onmessage = (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if (msg.type === 'registered') {
        this.id = msg.id;
        if (Array.isArray(msg.iceServers) && msg.iceServers.length) this.iceServers = msg.iceServers;
        this.setStatus('online');
        this.emit('registered', { id: msg.id, iceServers: this.iceServers });
      } else if (msg.type === 'relay') {
        this.emit('relay', msg.from, msg.payload || {});
      } else if (msg.type === 'peer-unavailable') {
        this.emit('unavailable', msg.to, msg.ref);
      } else if (msg.type === 'owner') {
        this.emit('owner', /^\d{9}$/.test(String(msg.id)) ? String(msg.id) : null);
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.setStatus('offline');
      if (!this.stopped) this.scheduleReconnect();
    };
    ws.onerror = () => {
      // onclose follows and handles reconnection
    };
  }

  scheduleReconnect() {
    const delay = Math.min(15000, 1000 * 2 ** this.retry);
    this.retry += 1;
    clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => this.connect(), delay);
  }

  /** Asks the server which device runs it ("connect by IP address"); answered with an 'owner' event. */
  askOwner() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    this.ws.send(JSON.stringify({ type: 'owner' }));
    return true;
  }

  send(to, payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    this.ws.send(JSON.stringify({ type: 'relay', to, payload }));
    return true;
  }

  close() {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    const ws = this.ws;
    this.ws = null;
    if (ws) ws.close();
    this.setStatus('offline');
  }

  reconnect(url = this.url) {
    this.close();
    this.url = url;
    this.retry = 0;
    this.connect();
  }
}
