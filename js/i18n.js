// Interface language. The app is written in Turkish; for English every
// visible text (static HTML, toasts, labels set from code, titles and
// placeholders) is looked up in the dictionary when it appears on screen.
// User content (names, IDs, chat, file names) is never translated.
import { EN, EN_PATTERNS } from './i18n-en.js';

export const LANGUAGES = ['tr', 'en'];

/** Elements whose text comes from people or devices, not from the app. */
const SKIP = [
  '#chat-messages .chat-msg:not(.system)', '#my-id', '#my-password', '#session-name', '#host-peer-name', '#request-name',
  '#request-id', '.recent-meta', '.fm-name', '#fm-path', '#crash-text', '#chat-peer', '#fm-device',
  '.history-device', '#device-name', '#app-version', 'kbd', 'code', 'option.raw',
].join(',');
const ATTRS = ['title', 'placeholder', 'aria-label', 'label'];

let lang = 'tr';
let observer = null;
// The Turkish originals of translated texts, to switch back without a reload.
const originalText = new WeakMap(); // Text node -> Turkish text
const originalAttrs = new WeakMap(); // Element -> { attr: Turkish value }
const touched = new Set(); // WeakRefs of nodes changed while in English
const exact = new Map(Object.entries(EN));
const patterns = EN_PATTERNS.map(([source, replacement]) => [new RegExp(`^${source}$`, 'u'), replacement]);

export function currentLanguage() {
  return lang;
}

/** Turkish text -> English (leading/trailing spaces kept); unknown text stays as is. */
export function translate(text, to = lang) {
  if (to === 'tr' || typeof text !== 'string') return text;
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(text);
  const core = m[2];
  if (!core) return text;
  let out = exact.get(core);
  if (out === undefined) {
    for (const [re, replacement] of patterns) {
      const match = re.exec(core);
      if (!match) continue;
      // Captured parts ($1, $2...) are translated too when they are known texts.
      out = replacement.replace(/\$(\d)/g, (_, i) => {
        const part = match[Number(i)] ?? '';
        return exact.get(part) ?? part;
      });
      break;
    }
  }
  return out === undefined ? text : m[1] + out + m[3];
}

function skipped(el) {
  return Boolean(el?.closest?.(SKIP));
}

function translateNode(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    const parent = node.parentElement;
    if (!parent || skipped(parent) || ['SCRIPT', 'STYLE'].includes(parent.tagName)) return;
    const next = translate(node.data);
    if (next !== node.data) {
      originalText.set(node, node.data);
      touched.add(new WeakRef(node));
      node.data = next;
    }
    return;
  }
  if (node.nodeType !== Node.ELEMENT_NODE || skipped(node)) return;
  for (const attr of ATTRS) {
    const value = node.getAttribute(attr);
    if (value) {
      const next = translate(value);
      if (next !== value) setTranslatedAttr(node, attr, value, next);
    }
  }
  if (node.tagName === 'INPUT' && ['button', 'submit'].includes(node.type) && node.value) node.value = translate(node.value);
  for (const child of node.childNodes) translateNode(child);
}

function setTranslatedAttr(el, attr, turkish, english) {
  const saved = originalAttrs.get(el) || {};
  saved[attr] = turkish;
  originalAttrs.set(el, saved);
  touched.add(new WeakRef(el));
  el.setAttribute(attr, english);
}

/** Puts the Turkish texts back (switching from English to Turkish). */
function restoreTurkish() {
  for (const ref of touched) {
    const node = ref.deref();
    if (!node) continue;
    if (node.nodeType === Node.TEXT_NODE) {
      const tr = originalText.get(node);
      if (tr !== undefined) node.data = tr;
      originalText.delete(node);
    } else {
      for (const [attr, value] of Object.entries(originalAttrs.get(node) || {})) node.setAttribute(attr, value);
      originalAttrs.delete(node);
    }
  }
  touched.clear();
}

/** Applies a language to the whole page (no reload needed) and keeps new content translated. */
export function applyLanguage(next) {
  const previous = lang;
  lang = LANGUAGES.includes(next) ? next : 'tr';
  document.documentElement.lang = lang;
  observer?.disconnect();
  observer = null;
  if (lang === 'tr') {
    if (previous !== 'tr') restoreTurkish();
    document.title = 'Xenon Remote';
    return;
  }
  translateNode(document.body);
  document.title = translate(document.title);
  observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === 'childList') m.addedNodes.forEach(translateNode);
      else if (m.type === 'characterData') translateNode(m.target);
      else if (m.type === 'attributes') {
        const value = m.target.getAttribute(m.attributeName);
        const next = translate(value);
        if (value && next !== value && !skipped(m.target)) setTranslatedAttr(m.target, m.attributeName, value, next);
      }
    }
  });
  observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
}

/** Date/time formatting locale for the current language. */
export function locale() {
  return lang === 'en' ? 'en-GB' : 'tr-TR';
}
