// Connection history: incoming and outgoing sessions and refused attempts,
// kept on this device (newest first, at most MAX entries).

import { readStorage, writeStorage } from './bridge.js';

const KEY = 'xenon.history';
const MAX = 300;

export function listHistory() {
  const list = readStorage(KEY, []);
  return Array.isArray(list) ? list : [];
}

/** Adds an entry {dir: 'in'|'out', name, peer, via, result} and returns its id. */
export function addHistory(entry) {
  const item = { id: Math.random().toString(36).slice(2, 10), at: Date.now(), ...entry };
  writeStorage(KEY, [item, ...listHistory()].slice(0, MAX));
  return item.id;
}

export function updateHistory(id, patch) {
  if (!id) return;
  writeStorage(KEY, listHistory().map((e) => (e.id === id ? { ...e, ...patch } : e)));
}

export function clearHistory() {
  writeStorage(KEY, []);
}

export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '';
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h) return `${h} sa ${m} dk`;
  if (m) return `${m} dk ${s % 60} sn`;
  return `${s} sn`;
}
