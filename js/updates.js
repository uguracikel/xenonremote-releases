// New-version check for the Android app: asks GitHub for the latest release
// in the public releases repository and offers the APK download. (The desktop
// app does this in the main process, see src/updater.js.)

const LATEST_API = 'https://api.github.com/repos/uguracikel/xenonremote-releases/releases/latest';

/** True when version `a` (e.g. "v1.2.0") is newer than `b` ("1.1.9"). */
export function isNewer(a, b) {
  const parse = (v) => String(v || '').replace(/^v/i, '').split(/[.+-]/).slice(0, 3).map((n) => parseInt(n, 10) || 0);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] > y[i];
  }
  return false;
}

/** Update functions for the bridge: getUpdateStatus, checkUpdate, installUpdate, onUpdate. */
export function createAndroidUpdater(getVersion) {
  let status = { state: 'idle' };
  const listeners = new Set();
  const set = (next) => {
    status = next;
    for (const cb of listeners) cb(status);
  };
  return {
    getUpdateStatus: async () => status,
    onUpdate: (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    checkUpdate: async () => {
      if (status.state === 'checking') return status;
      set({ state: 'checking' });
      try {
        const res = await fetch(LATEST_API, { headers: { Accept: 'application/vnd.github+json' } });
        if (res.status === 404) {
          set({ state: 'none' });
          return status;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const release = await res.json();
        if (!isNewer(release.tag_name, await getVersion())) {
          set({ state: 'none' });
          return status;
        }
        const apk = (release.assets || []).find((a) => /android\.apk$/i.test(a.name));
        set({ state: 'available', version: String(release.tag_name).replace(/^v/i, ''), url: apk?.browser_download_url || release.html_url });
      } catch (err) {
        set({ state: 'error', error: String(err?.message || err) });
      }
      return status;
    },
    // The download opens in the system browser; Android then installs the
    // APK over the current app (same signature).
    installUpdate: async () => {
      if (status.url) location.href = status.url;
      return Boolean(status.url);
    },
  };
}
