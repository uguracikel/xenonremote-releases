// Access to the Electron main process. When the renderer runs in a plain
// browser (development / web viewer) a fallback bridge is used: settings live
// in localStorage, the browser's own screen picker is shown and remote input
// cannot be injected (view-only hosting).

import { createAndroidUpdater } from './updates.js';

function readStorage(key, fallback) {
  try {
    const value = localStorage.getItem(key);
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // storage unavailable: settings stay in memory for this session
  }
}

/** Calls a native plugin of the Android app (Capacitor bridge). */
function nativeCall(plugin, method, options = {}) {
  return window.Capacitor.nativePromise(plugin, method, options);
}

function toBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Android app: phone control via the accessibility service, files saved to Downloads. */
function androidServices() {
  const device = (method, options) => nativeCall('XenonDevice', method, options);
  return {
    isAndroid: true,
    ...createAndroidUpdater(async () => (await device('info')).version),
    inputAvailable: async () => Boolean((await device('inputStatus')).enabled),
    openInputSettings: () => device('openAccessibilitySettings'),
    openAppSettings: () => device('openAppSettings'),
    lastCrash: async () => (await device('lastCrash')).text || null,
    sendInput: (msg) => { device('input', msg).catch(() => {}); },
    appInfo: async () => {
      const info = await device('info').catch(() => ({}));
      return { version: info.version || '', platform: 'android', hostname: '', sdk: info.sdk };
    },
    wake: async (macs) => (await device('wake', { macs })).sent,
    fileBegin: async (name, size) => (await device('fileBegin', { name, size })).token,
    fileWrite: (token, chunk) => device('fileWrite', { token, data: toBase64(chunk) }),
    fileEnd: async (token, ok) => (await device('fileEnd', { token, ok })).path || null,
  };
}

/** A page served from this network (the LAN server), not from the internet. */
function isLocalHost(hostname) {
  return !hostname || hostname === 'localhost' || /\.local$/.test(hostname)
    || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname);
}

function createBrowserBridge() {
  // In the Android app (Capacitor) there is no local server: internet mode only.
  // The web client on GitHub Pages has none either.
  const isApp = Boolean(window.Capacitor?.isNativePlatform?.());
  // iPhone/iPad app: a viewer like the web client (no native plugins).
  const isIos = isApp && window.Capacitor?.getPlatform?.() === 'ios';
  const defaults = {
    id: null,
    serverUrl: isApp || !isLocalHost(location.hostname) ? null : `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.hostname || 'localhost'}:8080`,
    deviceName: isIos ? 'iPhone' : isApp ? 'Android' : '',
    internetAccess: true,
  };
  let config = { ...defaults, ...readStorage('xenon.config', {}) };
  const downloads = new Map();
  const browser = {
    isBrowser: true,
    getConfig: async () => ({ ...config }),
    setConfig: async (patch) => {
      config = { ...config, ...patch };
      writeStorage('xenon.config', config);
      return { ...config };
    },
    listScreens: async () => [{ sourceId: isApp ? 'phone' : 'browser', name: isApp ? 'Telefon ekranı' : 'Tarayıcıda seçilecek', primary: true }],
    selectScreen: async () => null,
    inputAvailable: async () => false,
    setControlAllowed: () => {},
    setPrivacy: async () => false,
    sendInput: () => {},
    attention: (title, body) => {
      if ('Notification' in window && Notification.permission === 'granted') new Notification(title, { body });
    },
    focus: () => window.focus(),
    // The browser cannot run a server: always use the configured URL.
    getNetwork: async () => ({ mode: 'manual', role: 'manual', url: config.serverUrl || null, servers: [], addresses: [], unsupported: true }),
    setNetwork: async (_mode, serverUrl) => {
      if (serverUrl) config = { ...config, serverUrl };
      writeStorage('xenon.config', config);
      return { mode: 'manual', role: 'manual', url: config.serverUrl, servers: [], addresses: [], unsupported: true };
    },
    onNetwork: () => () => {},
    appInfo: async () => ({ version: isIos ? 'iOS' : isApp ? 'Android' : 'web', platform: isIos ? 'ios' : isApp ? 'android' : 'browser', hostname: '' }),
    // Received files are collected in memory and handed to the browser as a download.
    fileBegin: async (name, size) => {
      const token = Math.random().toString(36).slice(2);
      downloads.set(token, { name, size, parts: [] });
      return token;
    },
    fileWrite: async (token, chunk) => {
      downloads.get(token)?.parts.push(chunk);
    },
    fileEnd: async (token, ok) => {
      const file = downloads.get(token);
      downloads.delete(token);
      if (!file || !ok) return null;
      const url = URL.createObjectURL(new Blob(file.parts));
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      return file.name;
    },
  };
  return isApp && !isIos && window.Capacitor?.nativePromise ? { ...browser, ...androidServices() } : browser;
}

export const bridge = window.xenon || createBrowserBridge();
export { readStorage, writeStorage };
