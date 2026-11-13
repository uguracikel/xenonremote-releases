/** Minimal event emitter used by the renderer modules. */
export class Emitter {
  constructor() {
    this.listeners = new Map();
  }

  on(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
    return () => this.listeners.get(type)?.delete(fn);
  }

  emit(type, ...args) {
    for (const fn of this.listeners.get(type) || []) {
      try {
        fn(...args);
      } catch (err) {
        console.error(`[xenon] listener for "${type}" failed`, err);
      }
    }
  }
}
