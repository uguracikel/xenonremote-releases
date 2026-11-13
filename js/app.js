import { bridge, readStorage, writeStorage } from './bridge.js';
import { deriveSecret, formatId, generateDeviceId, generatePassword, hexToSecret, normalizeId, secretToHex } from './auth.js';
import { ClipboardSync, captureFrame, comboEvents, saveBytes, timestampName } from './features.js';
import { SignalingClient } from './signaling.js';
import { NostrSignaling, DEFAULT_RELAYS } from './nostr.js';
import { HostController, DEFAULT_PERMISSIONS, UNATTENDED_LABEL, SWITCH_LABEL } from './host.js';
import { ViewerController, REJECT_MESSAGES } from './viewer.js';
import { attachInputCapture, attachMobileKeyboard } from './input-capture.js';
import { enableTvNavigation } from './tv-nav.js';
import { addHistory, clearHistory, formatDuration, listHistory, updateHistory } from './history.js';
import { PathFile } from './transfer.js';
import { SessionRecorder } from './recorder.js';
import { attachDrawing, DRAW_COLORS } from './annotate.js';
import { ALL_SCREENS } from './composite.js';
import { applyLanguage, locale, translate } from './i18n.js';
import { BUILD } from './build-info.js';
import { encryptJson, decryptJson } from './book-vault.js';
import { inviteLinks, parseInvite } from './invite.js';
import { qrSvg } from './qr.js';
import { parseIpRule } from './ip-allow.js';
import { generateTotpSecret, isTotpSecret, otpauthUri, verifyTotp } from './totp.js';

const $ = (sel) => document.querySelector(sel);

const state = {
  config: null,
  password: generatePassword(),
  showPassword: false,
  deviceName: '',
  screenSourceId: null,
  inputAvailable: false,
  chatPeer: null, // 'host' | 'viewer' | null
  hostTransfers: new Map(), // viewer peerId -> FileTransfer (host side)
  unread: 0,
  network: null,
  pendingNetwork: null,
  canHost: true,
  sessionSecret: null, // derived from the one-time password
  unattended: null, // derived from the permanent password (from the OS vault)
  vault: false,
  lastConnect: null,
};

/* Helpers ------------------------------------------------------------ */

function toast(message, kind = 'info', ms = 3500, action = null) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  const text = document.createElement('span');
  text.textContent = message;
  el.append(text);
  if (action) {
    const btn = document.createElement('button');
    btn.textContent = action.label;
    btn.addEventListener('click', () => {
      action.fn();
      el.remove();
    });
    el.append(btn);
  }
  $('#toasts').append(el);
  setTimeout(() => el.remove(), ms);
}

function reportStatus() {
  const session = host?.active ? 'host' : tabs.some((t) => t.connected) ? 'viewer' : null;
  bridge.reportStatus?.({ id: state.config?.id, session });
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} kopyalandı`, 'success', 2000);
  } catch {
    toast('Panoya kopyalanamadı', 'error');
  }
}

function deviceName() {
  return state.deviceName || state.config?.deviceName || 'Xenon kullanıcısı';
}

/* Connection history -------------------------------------------------- */

const RESULT_TEXT = {
  ok: 'Bağlandı',
  'bad-password': 'Hatalı şifre',
  'bad-totp': 'Hatalı doğrulama kodu',
  'ip-blocked': 'IP adresi izin listesinde değil',
  locked: 'Engellendi (çok fazla deneme)',
  declined: 'Reddedildi',
  'remote-hangup': 'Karşı taraf kapattı',
  'local-hangup': 'Kapatıldı',
  'connection-lost': 'Bağlantı koptu',
  replaced: 'Yeniden bağlandı',
  'capture-ended': 'Ekran paylaşımı bitti',
  idle: 'İşlem yapılmadığı için kapatıldı',
};
const historyIds = new Map(); // live session key -> history entry id

function renderHistory() {
  const filter = $('#history-filter').value;
  const rows = listHistory().filter((e) => filter === 'all'
    || (filter === 'refused' ? e.result !== 'ok' && !e.end : e.dir === filter));
  const body = $('#history-rows');
  body.replaceChildren(...rows.map((e) => {
    const tr = document.createElement('tr');
    const cells = [
      new Date(e.at).toLocaleString(locale()),
      e.dir === 'in' ? 'Gelen' : 'Giden',
      `${e.name || translate('Bilinmeyen cihaz')}${e.peer ? ` (${e.peer})` : ''}`,
      e.end ? formatDuration(e.end - e.at) : (e.result === 'ok' ? 'sürüyor' : ''),
      e.result === 'ok' ? (e.end ? RESULT_TEXT[e.reason] || 'Bitti' : 'Bağlı') : (RESULT_TEXT[e.result] || REJECT_MESSAGES[e.result] || e.result),
    ];
    for (const text of cells) {
      const td = document.createElement('td');
      td.textContent = text;
      tr.append(td);
    }
    tr.children[2].className = 'history-device'; // a device name: never translated
    tr.lastChild.className = e.result === 'ok' ? 'ok' : 'bad';
    return tr;
  }));
  $('#history-empty').hidden = rows.length > 0;
}

$('#history-filter').addEventListener('change', renderHistory);
$('#history-clear').addEventListener('click', () => {
  clearHistory();
  renderHistory();
  toast('Geçmiş temizlendi', 'success', 1800);
});

function peerLabel(peerId, via) {
  return via === 'internet' || via === 'nostr' || String(peerId).startsWith('nostr:') ? 'internet' : formatId(peerId);
}

/* Views -------------------------------------------------------------- */

function showView(name) {
  if (name === 'history') renderHistory();
  if (name === 'book') renderBook();
  for (const view of document.querySelectorAll('.view')) view.hidden = view.id !== `view-${name}`;
  for (const item of document.querySelectorAll('.nav-item')) item.classList.toggle('active', item.dataset.view === name);
}

for (const item of document.querySelectorAll('.nav-item')) {
  item.addEventListener('click', () => showView(item.dataset.view));
}

/* Local device card -------------------------------------------------- */

function renderPassword() {
  $('#my-password').textContent = state.showPassword ? state.password : '•'.repeat(state.password.length);
  $('#toggle-password').classList.toggle('active', state.showPassword);
}

$('#toggle-password').addEventListener('click', () => {
  state.showPassword = !state.showPassword;
  renderPassword();
});
$('#refresh-password').addEventListener('click', () => {
  state.password = generatePassword();
  renderPassword();
  refreshSecrets();
  toast('Yeni şifre oluşturuldu', 'success', 2000);
});
$('#partner-password').addEventListener('input', (e) => {
  delete e.target.dataset.key; // typing a password replaces a remembered access key
  // Editing a vault-filled password starts over, so it can never be revealed.
  if (!e.target.dataset.saved) return;
  delete e.target.dataset.saved;
  e.target.value = e.data || '';
});

// "Show password" eye button on every password field.
for (const btn of document.querySelectorAll('.reveal-btn')) {
  btn.addEventListener('click', () => {
    const input = btn.parentElement.querySelector('input');
    // A password filled in from the vault stays hidden (it belongs to another device).
    if (input.dataset.saved && input.type === 'password') {
      toast('Kayıtlı şifre gösterilmez', 'info', 2000);
      return;
    }
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.classList.toggle('active', show);
    btn.title = show ? 'Şifreyi gizle' : 'Şifreyi göster';
    btn.setAttribute('aria-label', btn.title);
    btn.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
    input.focus();
  });
}
$('#copy-password').addEventListener('click', () => copy(state.password, 'Şifre'));
$('#copy-id').addEventListener('click', () => copy(state.config.id, 'ID'));

async function loadScreens() {
  const select = $('#screen-source');
  let screens = [];
  try {
    screens = await bridge.listScreens();
  } catch (err) {
    console.warn('[xenon] could not list screens', err);
  }
  select.replaceChildren(
    ...screens.map((s, i) => {
      const option = document.createElement('option');
      option.value = s.sourceId;
      option.textContent = `${s.primary ? 'Ana ekran' : `Ekran ${i + 1}`}${s.name ? ` — ${s.name}` : ''}`;
      return option;
    }),
  );
  // Several monitors: they can also be shared all at once.
  if (screens.length > 1 && !bridge.isAndroid && !bridge.isBrowser) select.append(new Option('Tüm ekranlar (hepsi birlikte)', ALL_SCREENS));
  // A single program's window: the rest of the screen stays private.
  const windows = bridge.listWindows ? await bridge.listWindows().catch(() => []) : [];
  if (windows.length) {
    const group = document.createElement('optgroup');
    group.label = 'Yalnızca bir pencere';
    for (const w of windows) {
      const option = new Option(`Pencere: ${w.name}`, w.sourceId);
      group.append(option);
    }
    select.append(group);
  }
  const chosenWindow = windows.find((w) => w.sourceId === state.screenSourceId);
  const preferred = state.screenSourceId === ALL_SCREENS && screens.length > 1 ? { sourceId: ALL_SCREENS }
    : chosenWindow || screens.find((s) => s.sourceId === state.screenSourceId) || screens.find((s) => s.primary) || screens[0];
  if (preferred) {
    select.value = preferred.sourceId;
    state.screenSourceId = preferred.sourceId;
  }
}

$('#screen-source').addEventListener('change', (e) => {
  state.screenSourceId = e.target.value;
  // While someone is connected the new choice applies at once (e.g. hide everything but one window).
  if (host?.capture) host.switchScreen(state.screenSourceId);
  if (state.screenSourceId.startsWith('window:')) toast('Bağlananlar yalnızca bu pencereyi görür', 'info', 4000);
});
$('#screen-source').addEventListener('focus', () => loadScreens());

/* Connection status ------------------------------------------------- */

const STATUS_LABELS = { online: 'Hazır — bağlantılara açık', connecting: 'Sunucuya bağlanıyor…', offline: 'Sunucuya ulaşılamıyor' };
let noticeTimer = null;

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url || '';
  }
}

function roleText(net) {
  if (!net) return '';
  if (net.role === 'server') return 'Bu cihaz ağ sunucusu';
  if (net.role === 'client') return `Ağ sunucusu: ${hostOf(net.url)}`;
  if (net.role === 'manual') return hostOf(net.url);
  return net.error ? 'Sunucu başlatılamadı' : 'Ağ taranıyor…';
}

function internetText() {
  if (!nostr) return 'İnternet erişimi kapalı';
  if (nostr.state !== 'online') return 'İnternet: bağlanıyor…';
  const hosts = nostr.connectedRelayHosts();
  if (!hosts.length) return 'İnternet: hazır';
  // Show the server (relay) we are actually connected through.
  return `İnternet: ${hosts[0]}${hosts.length > 1 ? ` +${hosts.length - 1}` : ''}`;
}

function renderConnection() {
  const lan = signaling?.state || 'offline';
  const internet = nostr?.state === 'online';
  const net = state.network;
  const searching = net && !net.url && !net.error && !internet;
  let status = lan;
  let label = STATUS_LABELS[lan] || lan;
  if (lan !== 'online' && internet) {
    status = 'online';
    label = 'Hazır — internet üzerinden';
  }
  const el = $('#server-status');
  el.dataset.state = searching ? 'connecting' : status;
  el.querySelector('.label').textContent = searching ? 'Ağ taranıyor…' : label;
  $('#server-role').textContent = [net?.url || net?.error ? roleText(net) : '', internetText()].filter(Boolean).join(' · ');

  // Show a hint on the home screen when we stay offline for a while.
  clearTimeout(noticeTimer);
  if (status === 'online' || searching) {
    $('#network-notice').hidden = true;
    return;
  }
  noticeTimer = setTimeout(() => {
    let title = 'Sunucuya ulaşılamıyor';
    let text = 'Bağlantı kurulamadı. Ayarlardan sunucu seçimini kontrol edin.';
    if (net?.error) {
      title = 'Ağ sunucusu başlatılamadı';
      text = `${net.error}. Ayarlardan özel bir sunucu adresi girebilirsiniz.`;
    } else if (net?.role === 'client') {
      text = `${hostOf(net.url)} adresindeki Xenon sunucusuna bağlanılamadı. O bilgisayarda güvenlik duvarının Xenon Remote'a izin verdiğinden emin olun.`;
    } else if (net?.role === 'manual') {
      text = `${hostOf(net.url)} adresine bağlanılamadı. Adresi ve internet bağlantınızı kontrol edin.`;
    }
    $('#network-notice-title').textContent = title;
    $('#network-notice-text').textContent = text;
    $('#network-notice').hidden = false;
  }, 4000);
}

/** Applies the server chosen by the main process (auto LAN mode or manual). */
function applyNetwork(net) {
  state.network = net;
  renderNetworkSettings();
  if (!signaling) return;
  if (host.active || anyViewerBusy()) {
    state.pendingNetwork = net; // switch servers once the session ends
  } else if (net.url !== signaling.url) {
    if (net.url) signaling.reconnect(net.url);
    else signaling.close();
  }
  renderConnection();
}

function applyPendingNetwork() {
  const net = state.pendingNetwork;
  state.pendingNetwork = null;
  if (net) applyNetwork(net);
}

$('#network-notice-btn').addEventListener('click', () => showView('settings'));

/* Recent connections ------------------------------------------------- */

function getRecent() {
  return readStorage('xenon.recent', []);
}

function rememberRecent(id, name) {
  const list = getRecent().filter((r) => r.id !== id);
  list.unshift({ id, name: name || '', at: Date.now() });
  writeStorage('xenon.recent', list.slice(0, 8));
  renderRecent();
}

/* Wake-on-LAN ------------------------------------------------------------ */

/** Network adapters of devices we connected to, so they can be woken up later. */
function rememberMacs(id, macs) {
  const all = readStorage('xenon.macs', {});
  all[id] = macs;
  writeStorage('xenon.macs', all);
  renderRecent();
}

function macsOf(id) {
  const list = readStorage('xenon.macs', {})[id];
  return Array.isArray(list) ? list : [];
}

/** A "wake up" button for a device whose network adapter we know. */
function wakeButton(id, name, cls = 'btn btn-ghost btn-sm wake-btn') {
  if (!bridge.wake || !macsOf(id).length) return null;
  const b = document.createElement('button');
  b.type = 'button';
  b.className = cls;
  b.title = 'Uzaktan uyandır (Wake-on-LAN): aynı ağdaki kapalı veya uykudaki bilgisayarı açar';
  b.innerHTML = '<svg><use href="#i-power"/></svg>Uyandır';
  b.addEventListener('click', async (e) => {
    e.stopPropagation();
    try {
      await bridge.wake(macsOf(id));
      toast(`${name || formatId(id)} için uyandırma sinyali gönderildi. Açılması bir dakika sürebilir.`, 'success', 6000);
    } catch (err) {
      console.warn('[xenon] wake failed', err);
      toast('Uyandırma sinyali gönderilemedi', 'error');
    }
  });
  return b;
}

/** Fills in the ID and connects right away when a password is remembered. */
async function connectTo(id) {
  showView('home');
  $('#partner-id').value = formatId(id);
  const saved = state.vault ? await bridge.getSavedPassword(id).catch(() => null) : null;
  const field = $('#partner-password');
  delete field.dataset.key;
  delete field.dataset.saved;
  if (saved?.startsWith('key:')) {
    // Permanent access given by that computer: no password needed.
    field.value = '';
    field.dataset.key = saved;
    $('#connect-form').requestSubmit();
  } else if (saved) {
    field.value = saved;
    field.dataset.saved = '1';
    $('#remember-password').checked = true;
    $('#connect-form').requestSubmit();
  } else {
    $('#partner-password').value = '';
    $('#partner-password').focus();
  }
}

/* Address book ---------------------------------------------------------- */

// With a master password the book is stored encrypted ("xenon.book.enc")
// and only readable after unlocking; the password stays in memory only.
const book = { enc: readStorage('xenon.book.enc', null), list: null, password: null, saving: Promise.resolve() };

function bookLocked() {
  return Boolean(book.enc) && !book.list;
}

function getBook() {
  const list = book.enc ? (book.list || []) : readStorage('xenon.book', []);
  return Array.isArray(list) ? list.filter((e) => /^\d{9}$/.test(e.id)) : [];
}

function writeBook(list) {
  if (!book.enc) {
    writeStorage('xenon.book', list);
    return;
  }
  if (!book.list) return; // locked: never overwrite
  book.list = list;
  const { password } = book;
  book.saving = book.saving.then(async () => {
    book.enc = await encryptJson(password, list);
    writeStorage('xenon.book.enc', book.enc);
  });
}

function saveBookEntry(entry, previousId = entry.id) {
  if (bookLocked()) {
    toast('Adres defteri kilitli: önce ana şifreyle açın', 'error');
    return false;
  }
  const list = getBook().filter((e) => e.id !== previousId && e.id !== entry.id);
  writeBook([...list, entry].sort((a, b) => (a.group || '').localeCompare(b.group || '', 'tr') || a.name.localeCompare(b.name, 'tr')));
  return true;
}

function renderBookSecurity() {
  const locked = bookLocked();
  $('#book-unlock-form').hidden = !locked;
  $('#book-form').hidden = locked;
  $('#book-main').hidden = locked;
  $('#book-set-master').textContent = book.enc ? 'Ana şifreyi değiştir' : 'Ana şifre koy';
  $('#book-remove-master').hidden = !book.enc || locked;
  $('#book-lock').hidden = !book.enc || locked;
  $('#book-security-text').textContent = book.enc
    ? 'Adres defteri ana şifreyle şifreli. Uygulama her açıldığında şifre sorulur.'
    : 'Adres defterini bir ana şifreyle şifreleyebilirsiniz.';
}

$('#book-unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#book-unlock-password').value;
  try {
    book.list = await decryptJson(password, book.enc);
    book.password = password;
    $('#book-unlock-password').value = '';
    renderBook();
    renderRecent();
  } catch {
    toast('Ana şifre hatalı', 'error');
  }
});
$('#book-lock').addEventListener('click', () => {
  book.list = null;
  book.password = null;
  renderBook();
  renderRecent();
});
$('#book-set-master').addEventListener('click', () => {
  $('#book-master-new').value = '';
  $('#book-master-confirm').value = '';
  $('#book-master-dialog').showModal();
});
$('#book-master-cancel').addEventListener('click', () => $('#book-master-dialog').close());
$('#book-master-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#book-master-new').value;
  if (password.length < 6) {
    toast('Ana şifre en az 6 karakter olmalı', 'error');
    return;
  }
  if (password !== $('#book-master-confirm').value) {
    toast('Şifreler eşleşmiyor', 'error');
    return;
  }
  const list = getBook();
  book.enc = await encryptJson(password, list);
  book.list = list;
  book.password = password;
  writeStorage('xenon.book.enc', book.enc);
  try { localStorage.removeItem('xenon.book'); } catch { /* storage unavailable */ }
  $('#book-master-dialog').close();
  renderBook();
  toast('Adres defteri ana şifreyle şifrelendi', 'success');
});
$('#book-remove-master').addEventListener('click', async () => {
  if (bookLocked() || !window.confirm(translate('Ana şifre kaldırılsın mı? Adres defteri şifresiz saklanacak.'))) return;
  await book.saving;
  const list = getBook();
  book.enc = null;
  book.list = null;
  book.password = null;
  try { localStorage.removeItem('xenon.book.enc'); } catch { /* storage unavailable */ }
  writeStorage('xenon.book', list);
  renderBook();
  toast('Ana şifre kaldırıldı', 'success');
});

function inBook(id) {
  return getBook().some((e) => e.id === id);
}

let bookEditing = null; // id of the entry being edited

/** Tag colours: each tag text always gets the same one. */
const TAG_COLORS = ['#22d3ee', '#8b5cf6', '#f59e0b', '#22c55e', '#f43f5e', '#3b82f6', '#ec4899', '#14b8a6'];
function tagColor(tag) {
  let h = 0;
  for (const ch of tag.toLocaleLowerCase('tr')) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return TAG_COLORS[h % TAG_COLORS.length];
}

/** "sunucu, Muhasebe ,, acil" -> ['sunucu', 'Muhasebe', 'acil'] (at most 8, no repeats). */
function parseTags(text) {
  const seen = new Set();
  return String(text || '').split(',').map((t) => t.trim().slice(0, 24)).filter((t) => {
    const key = t.toLocaleLowerCase('tr');
    if (!t || seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 8);
}

function fillBookForm(entry = null) {
  bookEditing = entry?.id || null;
  $('#book-id').value = entry ? formatId(entry.id) : '';
  $('#book-name').value = entry?.name || '';
  $('#book-group').value = entry?.group || '';
  $('#book-tags').value = (entry?.tags || []).join(', ');
  $('#book-note').value = entry?.note || '';
  $('#book-save').textContent = entry ? 'Değişiklikleri kaydet' : 'Deftere ekle';
  $('#book-cancel').hidden = !entry;
}

function renderBook() {
  renderBookSecurity();
  const all = getBook();
  const q = $('#book-search').value.trim().toLocaleLowerCase('tr');
  const list = all.filter((e) => !q || `${e.name} ${e.group || ''} ${e.id} ${(e.tags || []).join(' ')} ${e.note || ''}`.toLocaleLowerCase('tr').includes(q));
  $('#book-groups').replaceChildren(...[...new Set(all.map((e) => e.group).filter(Boolean))].map((g) => new Option(g)));
  $('#book-empty').hidden = list.length > 0;
  $('#book-empty').textContent = all.length ? 'Aramayla eşleşen cihaz yok.' : 'Henüz cihaz eklenmedi. Yukarıdan ekleyin ya da bir bağlantıdan sonra "Adres defterine ekle" deyin.';
  const groups = new Map();
  for (const e of list) {
    const g = e.group || translate('Grupsuz');
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(e);
  }
  const out = [];
  for (const [group, entries] of groups) {
    const h = document.createElement('h3');
    h.className = 'book-group';
    h.textContent = group;
    out.push(h);
    for (const e of entries) {
      const row = document.createElement('div');
      row.className = 'book-item';
      row.innerHTML = `
        <span class="recent-thumb"><svg><use href="#i-monitor"/></svg></span>
        <span class="recent-meta"><strong></strong><span></span></span>
        <button type="button" class="btn btn-primary btn-sm" data-act="connect">Bağlan</button>
        <button type="button" class="btn btn-ghost btn-sm" data-act="edit">Düzenle</button>
        <button type="button" class="icon-btn" data-act="delete" title="Defterden sil"><svg><use href="#i-x"/></svg></button>`;
      row.querySelector('strong').textContent = e.name;
      row.querySelector('.recent-meta span').textContent = formatId(e.id);
      if (e.note) {
        const note = document.createElement('span');
        note.className = 'book-note';
        note.textContent = e.note;
        note.title = e.note;
        row.querySelector('.recent-meta').append(note);
      }
      if (e.tags?.length) {
        const tags = document.createElement('span');
        tags.className = 'book-tags';
        for (const t of e.tags) {
          const chip = document.createElement('button');
          chip.type = 'button';
          chip.className = 'book-tag';
          chip.textContent = t;
          chip.style.color = tagColor(t);
          chip.style.borderColor = tagColor(t);
          chip.title = translate('Bu etiketle süz');
          chip.addEventListener('click', () => {
            $('#book-search').value = t;
            renderBook();
          });
          tags.append(chip);
        }
        row.querySelector('.recent-meta').append(tags);
      }
      row.querySelector('[data-act="connect"]').addEventListener('click', () => connectTo(e.id));
      const wake = wakeButton(e.id, e.name);
      if (wake) row.querySelector('[data-act="connect"]').before(wake);
      row.querySelector('[data-act="edit"]').addEventListener('click', () => {
        fillBookForm(e);
        $('#book-name').focus();
      });
      row.querySelector('[data-act="delete"]').addEventListener('click', () => {
        writeBook(getBook().filter((x) => x.id !== e.id));
        if (bookEditing === e.id) fillBookForm();
        renderBook();
        toast(`${e.name} defterden silindi`, 'info', 2000);
      });
      out.push(row);
    }
  }
  $('#book-list').replaceChildren(...out);
}

$('#book-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const id = normalizeId($('#book-id').value);
  if (!/^\d{9}$/.test(id)) {
    toast('Lütfen 9 haneli bir Xenon ID girin', 'error');
    return;
  }
  const name = $('#book-name').value.trim() || `Cihaz ${formatId(id)}`;
  const entry = { id, name: name.slice(0, 60), group: $('#book-group').value.trim().slice(0, 40) };
  const tags = parseTags($('#book-tags').value);
  const note = $('#book-note').value.trim().slice(0, 500);
  if (tags.length) entry.tags = tags;
  if (note) entry.note = note;
  saveBookEntry(entry, bookEditing || id);
  toast(bookEditing ? 'Cihaz güncellendi' : 'Cihaz deftere eklendi', 'success', 2000);
  fillBookForm();
  renderBook();
});
$('#book-cancel').addEventListener('click', () => fillBookForm());
$('#book-search').addEventListener('input', renderBook);

function renderRecent() {
  const list = getRecent();
  $('#recent-empty').hidden = list.length > 0;
  $('#recent-list').replaceChildren(
    ...list.map((r) => {
      const li = document.createElement('li');
      li.className = 'recent-item';
      li.title = 'Bağlanmak için tıklayın';
      li.innerHTML = `
        <span class="recent-thumb"><svg><use href="#i-monitor"/></svg></span>
        <span class="recent-meta"><strong></strong><span></span></span>
        <button class="recent-remove recent-add" title="Adres defterine ekle"><svg><use href="#i-book"/></svg></button>
        <button class="recent-remove" title="Listeden kaldır"><svg><use href="#i-x"/></svg></button>`;
      li.querySelector('strong').textContent = r.name || translate('Uzak cihaz');
      li.querySelector('.recent-add').hidden = inBook(r.id) || bookLocked();
      li.querySelector('.recent-add').addEventListener('click', (e) => {
        e.stopPropagation();
        saveBookEntry({ id: r.id, name: r.name || `Cihaz ${formatId(r.id)}`, group: '' });
        toast('Adres defterine eklendi', 'success', 2000);
        renderRecent();
      });
      li.querySelector('.recent-meta span').textContent = formatId(r.id);
      const wake = wakeButton(r.id, r.name, 'recent-remove wake-icon');
      if (wake) {
        wake.innerHTML = '<svg><use href="#i-power"/></svg>';
        li.querySelector('.recent-add').before(wake);
      }
      li.addEventListener('click', () => connectTo(r.id));
      li.querySelector('.recent-remove:not(.recent-add)').addEventListener('click', (e) => {
        e.stopPropagation();
        writeStorage('xenon.recent', getRecent().filter((x) => x.id !== r.id));
        renderRecent();
      });
      return li;
    }),
  );
}

/* Chat --------------------------------------------------------------- */

function openChat(peer, title) {
  state.chatPeer = peer;
  state.unread = 0;
  $('.chat-badge').hidden = true;
  $('#chat-peer').textContent = title || '';
  $('#chat-panel').hidden = false;
  $('#chat-input').focus();
}

function closeChat() {
  $('#chat-panel').hidden = true;
}

function addChatMessage(text, kind) {
  const li = document.createElement('li');
  li.className = `chat-msg ${kind}`;
  li.textContent = text;
  $('#chat-messages').append(li);
  li.scrollIntoView({ block: 'end' });
}

function clearChat() {
  $('#chat-messages').replaceChildren();
  closeChat();
  state.chatPeer = null;
}

function onIncomingChat(peer, text, title) {
  addChatMessage(text, 'them');
  if ($('#chat-panel').hidden) {
    state.unread += 1;
    if (peer === 'viewer') $('.chat-badge').hidden = false;
    toast(`Yeni mesaj: ${text.slice(0, 60)}`);
    if (peer === 'host') openChat('host', title);
  }
}

$('#chat-close').addEventListener('click', closeChat);
$('#chat-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('#chat-input');
  const text = input.value.trim();
  if (!text) return;
  if (state.chatPeer === 'viewer' && activeTab) {
    viewer.sendChat(text);
    activeTab.chat.push({ text, kind: 'me' });
  } else if (state.chatPeer === 'host') host.sendChat(text);
  else return;
  addChatMessage(text, 'me');
  input.value = '';
});

/* Signaling ---------------------------------------------------------- */

let signaling;
let nostr = null;
let host;
let viewer;

function acceptedSecrets() {
  // The permanent password is labelled: with two-step verification it also needs a code.
  const unattended = state.unattended ? { secret: state.unattended, label: UNATTENDED_LABEL } : null;
  // Swap sides: the one-time key given to the computer we were controlling.
  const grant = state.switchGrant && Date.now() < state.switchGrant.until ? { secret: state.switchGrant.secret, label: SWITCH_LABEL } : null;
  return [state.sessionSecret, unattended, ...trustedSecrets(), grant].filter(Boolean);
}

/** Re-derives the session secret after the password or ID changed. */
async function refreshSecrets() {
  const { id } = state.config;
  const password = state.password;
  const secret = await deriveSecret(id, password);
  if (state.config.id === id && state.password === password) state.sessionSecret = secret;
  listenOnInternet();
}

/** Lets remote viewers reach this device over the internet (password required). */
function listenOnInternet() {
  if (!nostr || !state.canHost) return;
  nostr.listen(state.config.id, acceptedSecrets()).catch((err) => console.warn('[xenon] internet listen failed', err));
}

/** The permanent password is bound to the device ID; a new ID invalidates it. */
async function onIdChanged() {
  if (state.unattended) {
    state.unattended = null;
    state.totp = null;
    await bridge.setUnattended?.(null);
    renderUnattended();
    toast('ID değişti: gözetimsiz erişim şifresini yeniden belirleyin', 'error', 8000);
  }
  reportStatus();
  await refreshSecrets();
}

function createControllers() {
  signaling = new SignalingClient({ url: state.network?.url || null, id: state.config.id });
  signaling.setRelayServers(turnIceServers(state.config.turn));
  if (state.config.internetAccess !== false) {
    const relays = Array.isArray(state.config.relays) && state.config.relays.length ? state.config.relays : DEFAULT_RELAYS;
    nostr = new NostrSignaling({ relays });
  }

  host = new HostController({
    signaling,
    nostr,
    // System notifications are not part of the page: translate them here.
    bridge: { ...bridge, attention: (title, body) => bridge.attention(translate(title), translate(body)) },
    getSecrets: async () => {
      if (!state.sessionSecret) await refreshSecrets();
      // Wait for the permanent-access secret to load before judging a password.
      if (state.vaultReady) await state.vaultReady.catch(() => {});
      return acceptedSecrets();
    },
    getScreenSourceId: () => state.screenSourceId,
    getDeviceName: deviceName,
    isBusy: () => anyViewerBusy(),
    getPermissions: () => ({ ...DEFAULT_PERMISSIONS, ...(state.config.permissions || {}) }),
    getIdleMs: () => (Number(state.config.idleMinutes) || 0) * 60 * 1000,
    platform: state.platform,
    // Lets viewers wake this computer later (Wake-on-LAN).
    getHelloExtras: async () => ({
      macs: bridge.ownMacs ? await bridge.ownMacs() : [],
      os: state.platform,
      // Windows without admin rights cannot control admin windows (viewers are told).
      elevated: bridge.getAdminMode ? Boolean((await bridge.getAdminMode().catch(() => null))?.elevated) : null,
      // Why remote control is not possible here, if it is not (shown to the viewer).
      inputError: state.inputAvailable ? null : (await bridge.inputError?.().catch(() => null)) || 'unavailable',
    }),
    getAccess: () => ({ mode: state.config.accessMode || 'all', blocked: state.config.blockedIds || [] }),
    onTrust: trustDevice,
    // On the sign-in screen everyone gets the same narrow permissions (the app runs as SYSTEM there).
    getTrustedPerms: (deviceId) => (state.loginScreen ? null : (state.trusted || []).find((t) => t.deviceId === deviceId)?.perms || null),
    getTotp: async () => (state.unattended ? state.totp || null : null),
    getAllowedIps: () => state.config.allowedIps || [],
    getSecureState: () => state.secureState || null,
  });


  signaling.on('status', renderConnection);
  signaling.on('registered', async ({ id }) => {
    $('#my-id').textContent = formatId(id);
    if (id !== state.config.id) {
      state.config = await bridge.setConfig({ id });
      await onIdChanged();
    }
  });
  if (nostr) {
    nostr.on('status', renderConnection);
    nostr.on('relay', (from, payload, meta) => {
      const v = viewerFor(from);
      if (v) v.handleRelay(from, payload);
      else if (state.canHost) host.handleRelay(from, payload, meta);
    });
    nostr.start();
    listenOnInternet();
  }
  signaling.on('relay', (from, payload) => {
    const v = viewerFor(from);
    if (v) v.handleRelay(from, payload);
    else host.handleRelay(from, payload);
  });
  signaling.on('unavailable', (to) => tabs.forEach((t) => t.viewer.handleUnavailable(to)));

  wireHost();
  wireViewer();
  signaling.connect();
}

/* Host side ---------------------------------------------------------- */

let requestTimer = null;

function wireHost() {
  const dialog = $('#request-dialog');
  let respond = null;
  let requestPeer = null;

  const finish = (accepted) => {
    clearInterval(requestTimer);
    if (dialog.open) dialog.close();
    if (respond) respond(accepted, $('#request-allow-control').checked);
    respond = null;
    requestPeer = null;
  };

  $('#request-accept').addEventListener('click', (e) => { e.preventDefault(); finish(true); });
  $('#request-reject').addEventListener('click', (e) => { e.preventDefault(); finish(false); });
  dialog.addEventListener('cancel', (e) => { e.preventDefault(); finish(false); });

  host.on('request', (req) => {
    // Sign-in screen (Windows, nobody signed in): nobody can approve; only the
    // permanent password or a trusted device gets in.
    if (state.loginScreen) {
      req.respond(false, false);
      return;
    }
    respond = req.respond;
    requestPeer = req.peerId;
    $('#request-name').textContent = req.name || translate('Bilinmeyen cihaz');
    $('#request-id').textContent = `(${formatId(req.peerId)})`;
    $('#request-allow-control').checked = state.inputAvailable;
    $('#request-allow-control').disabled = !state.inputAvailable;
    let left = 30;
    $('#request-countdown').textContent = left;
    clearInterval(requestTimer);
    requestTimer = setInterval(() => {
      left -= 1;
      $('#request-countdown').textContent = left;
      if (left <= 0) finish(false);
    }, 1000);
    bridge.focus();
    dialog.showModal();
  });

  host.on('request-cancelled', (peerId) => {
    if (peerId !== requestPeer) return;
    respond = null;
    finish(false);
    toast('Bağlantı isteği karşı taraf tarafından iptal edildi');
  });

  // Banner: who is watching (several viewers may be connected at once).
  host.on('sessions', (list) => {
    renderTrustButtons(list);
    $('#host-terminal-tag').hidden = !list.some((s) => s.terminal);
    $('#host-banner').hidden = !list.length;
    if (!list.length) return;
    const names = list.map((s) => s.name || translate('Uzak kullanıcı'));
    $('#host-peer-name').textContent = names.length > 2 ? `${names.slice(0, 2).join(', ')}${translate(` ve ${names.length - 2} kişi daha`)}` : names.join(', ');
    const [only] = list;
    $('#host-recording-tag').hidden = !list.some((s) => s.recording);
    $('#host-peer-id').textContent = list.length > 1
      ? `(${list.length} bağlantı)`
      : only.via === 'internet' ? '(internet üzerinden)' : `(${formatId(only.peerId)})`;
  });

  host.on('refused', ({ peerId, name, reason }) => {
    addHistory({ dir: 'in', name, peer: peerLabel(peerId), result: reason });
  });

  host.on('started', ({ peerId, name, via }) => {
    historyIds.set(`in:${peerId}`, addHistory({ dir: 'in', name, peer: peerLabel(peerId, via), result: 'ok' }));
    reportStatus();
    if (host.sessions.size === 1) {
      clipboardSync.start();
      clearChat();
    }
    $('#connect-btn').disabled = true;
    addChatMessage(`${name || formatId(peerId)} bağlandı`, 'system');
    if (state.config.recordIncoming && !hostRecorder.active) startHostRecording();
  });

  host.on('control', (allowed) => {
    $('#host-control-toggle').checked = allowed;
  });

  host.on('privacy', (on) => {
    $('#host-privacy-tag').hidden = !on;
  });

  host.on('chat', ({ name, text }) => {
    const multi = host.sessions.size > 1;
    onIncomingChat('host', multi ? `${name || translate('Uzak kullanıcı')}: ${text}` : text, multi ? translate('Sohbet (herkes)') : name);
  });

  host.on('files', (transfer, peerId) => {
    state.hostTransfers.set(peerId, transfer);
    wireTransfer(transfer);
  });

  host.on('clip', (text) => clipboardSync.apply(text));
  host.on('clip-image', (bytes) => clipboardSync.applyImage(bytes));

  host.on('admin', ({ name, action, detail }) => {
    const who = name || translate('Uzak kullanıcı');
    const texts = {
      lock: `${who} bu bilgisayarı kilitledi`,
      sleep: `${who} bu bilgisayarı uyku moduna alıyor`,
      hibernate: `${who} bu bilgisayarı hazırda bekletiyor`,
      restart: `${who} bu bilgisayarı yeniden başlatıyor`,
      shutdown: `${who} bu bilgisayarı kapatıyor`,
      schedule: `${who} bu bilgisayar için bir güç işlemi zamanladı`,
      kill: `${who} bir programı sonlandırdı: ${detail}`,
    };
    toast(texts[action] || action, 'error', 8000);
    addChatMessage(texts[action] || action, 'system');
  });

  host.on('input-blocked', ({ on }) => {
    $('#host-blocked-tag').hidden = !on;
    if (on) bridge.attention(translate('Fare ve klavye kilitlendi'), translate('Uzak kullanıcı çalışırken fare ve klavyeniz kilitli. Açmak için Ctrl+Alt+Del › Kilitle.'));
  });

  // Swap sides: we were controlled; now we connect to the viewer's computer.
  host.on('switch-sides', ({ id, key, name }) => {
    toast(`${name || formatId(id)} sizin onu kontrol etmenizi istedi; bağlanılıyor…`, 'info', 6000);
    setTimeout(() => startConnection(id, `key:${key}`), 900);
  });
  host.on('switch-used', () => {
    clearTimeout(state.switchGrant?.timer);
    state.switchGrant = null; // works once
    listenOnInternet();
  });

  host.on('power-plan', (plan, by) => {
    renderPowerPlan(plan);
    if (plan) bridge.attention(translate('Zamanlanmış işlem'), translate(`Bu bilgisayar ${clockText(Math.round((plan.at - Date.now()) / 1000))} sonra ${POWER_PLAN_TEXT[plan.action]}`));
    else if (by) toast(`${by} zamanlanmış işlemi iptal etti`, 'info', 5000);
  });

  host.on('recording', ({ name, on }) => {
    toast(on ? `${name || 'Uzak kullanıcı'} bu oturumu kaydetmeye başladı` : `${name || 'Uzak kullanıcı'} kaydı durdurdu`, on ? 'error' : 'info', 6000);
  });

  // Voice chat: each viewer's microphone plays here.
  host.on('voice', ({ peerId, stream }) => {
    let el = hostVoices.get(peerId);
    if (!el) {
      el = document.createElement('audio');
      el.autoplay = true;
      el.hidden = true;
      document.body.append(el);
      hostVoices.set(peerId, el);
    }
    el.srcObject = stream;
    el.play().catch(() => {});
  });
  host.on('voice-state', ({ name, on }) => {
    toast(on ? `${name || 'Uzak kullanıcı'} mikrofonunu açtı` : `${name || 'Uzak kullanıcı'} mikrofonunu kapattı`, 'info', 3000);
  });
  $('#host-mic-btn').addEventListener('click', async () => {
    try {
      renderHostMic(await host.setMicrophone(!host.mic));
    } catch (err) {
      console.warn('[xenon] microphone', err);
      toast('Mikrofon açılamadı. Mikrofon bağlı mı ve izin verildi mi kontrol edin.', 'error', 6000);
    }
  });

  host.on('ended', ({ peerId, name, reason, remaining }) => {
    updateHistory(historyIds.get(`in:${peerId}`), { end: Date.now(), reason });
    historyIds.delete(`in:${peerId}`);
    state.hostTransfers.delete(peerId);
    const voiceEl = hostVoices.get(peerId);
    if (voiceEl) {
      voiceEl.srcObject = null;
      voiceEl.remove();
      hostVoices.delete(peerId);
    }
    setTimeout(reportStatus);
    if (remaining) {
      addChatMessage(`${name || 'Uzak kullanıcı'} ayrıldı`, 'system');
      if (reason !== 'replaced') toast(`${name || 'Uzak kullanıcı'} bağlantıyı kapattı`);
      return;
    }
    setTimeout(applyPendingNetwork);
    clipboardSync.stop();
    if (host.mic) host.setMicrophone(false).then(renderHostMic).catch(() => {});
    $('#host-recording-tag').hidden = true;
    $('#host-blocked-tag').hidden = true;
    $('#connect-btn').disabled = false;
    clearChat();
    if (reason === 'replaced') return; // the same viewer reconnected right away
    stopHostRecording();
    // Settings: nobody may find this computer unlocked after a remote session.
    if (state.config.lockOnEnd && bridge.power) bridge.power('lock').catch(() => {});
    toast(reason === 'remote-hangup' ? 'Uzak kullanıcı bağlantıyı kapattı'
      : reason === 'connection-lost' ? 'Bağlantı koptu, oturum kapatıldı'
        : reason === 'idle' ? 'İşlem yapılmadığı için bağlantı kapatıldı' : 'Oturum sona erdi');
  });

  host.on('error', (message) => toast(message, 'error', 5000));

  // Tell viewers when this computer's session is locked. Windows does not
  // always report the unlock (e.g. after a Remote Desktop session), so the
  // state is checked again every few seconds while someone is connected.
  const checkLock = () => bridge.isLocked?.().then((locked) => { if (locked !== host.locked) host.setLocked(locked); }).catch(() => {});
  bridge.onLockChange?.((locked) => {
    host.setLocked(locked);
    setTimeout(checkLock, 3000);
  });
  checkLock();
  setInterval(() => { if (host.active) checkLock(); }, 5000);

  $('#host-control-toggle').addEventListener('change', (e) => {
    if (e.target.checked && !state.inputAvailable) {
      e.target.checked = false;
      toast('Uzaktan kontrol modülü bu sistemde kullanılamıyor', 'error');
      return;
    }
    host.setControlAllowed(e.target.checked);
  });
  $('#host-end-btn').addEventListener('click', () => host.end());
  $('#host-chat-btn').addEventListener('click', () => openChat('host', host.sessions.size > 1 ? translate('Sohbet (herkes)') : $('#host-peer-name').textContent));
}

const hostVoices = new Map(); // viewer peerId -> <audio> playing their microphone

/** Settings › record incoming sessions: this computer's screen while someone is connected. */
const hostRecorder = new SessionRecorder(bridge);
async function startHostRecording() {
  const stream = host.capture?.stream;
  if (!stream) return;
  try {
    await hostRecorder.start(stream, stream.getAudioTracks().length ? [stream] : [], 'Xenon-gelen-oturum');
    host.setHostRecording(true);
  } catch (err) {
    console.warn('[xenon] incoming session recording failed', err);
  }
}
async function stopHostRecording() {
  if (!hostRecorder.active) return;
  host.setHostRecording(false);
  const path = await hostRecorder.stop();
  if (path) toast('Gelen oturumun kaydı kaydedildi', 'success', 8000, bridge.revealFile ? { label: 'Klasörü aç', fn: () => bridge.revealFile(path) } : null);
}

function renderMic(btn, on, labelled = false) {
  btn.classList.toggle('live', on);
  btn.querySelector('use').setAttribute('href', on ? '#i-mic' : '#i-mic-off');
  btn.title = on ? 'Mikrofonu kapat' : 'Sesli görüşme: mikrofonu aç';
  if (labelled) btn.querySelector('span').textContent = on ? 'Mikrofon açık' : 'Mikrofon';
}

function renderHostMic(on) {
  renderMic($('#host-mic-btn'), Boolean(on), true);
}

/* Viewer side: one tab per remote device ------------------------------ */

const MAX_TABS = 6;
const tabs = []; // connections opened from this device (being set up or connected)
let activeTab = null; // the tab on screen
let pendingTab = null; // the connection being set up from the home screen
let capture = null;
let drawing = null;
let recordTimer = null;
let detachKeyboard = null;
let remoteControl = false; // remote control of the active tab
// Reconnect after a remote restart: { id, until, timer }
const reconnects = new Map();
/**
 * How long a dropped connection is retried. Long enough for a sign-in on the
 * remote computer: the sign-in screen copy of the app ends and the user's
 * own app starts with Windows.
 */
const DROP_RECONNECT_MS = 3 * 60 * 1000;

function setConnecting(text) {
  $('#connect-status').hidden = !text;
  $('#connect-form').querySelector('button').disabled = Boolean(text);
  if (text) $('.connect-status-text').textContent = text;
}

function anyViewerBusy() {
  return tabs.some((t) => t.viewer.busy);
}

/** The viewer that talks to `peerId` (relay messages are routed by it). */
function viewerFor(peerId) {
  return tabs.find((t) => t.viewer.busy && t.viewer.peerId === peerId)?.viewer || null;
}

function tabLabel(tab) {
  return tab.name || formatId(tab.id);
}

/** `direct`: a signaling client of its own (connected by IP address), closed with the tab. */
function createTab(id, direct = null) {
  const tab = {
    id,
    name: '',
    via: null,
    stream: null,
    connected: false,
    control: false,
    platform: 'desktop',
    features: [],
    perms: null,
    transfer: null,
    screens: null,
    locked: false,
    privacy: false,
    audio: null,
    voice: null,
    stats: null,
    chat: [],
    unread: 0,
    quality: 'auto',
    recorder: new SessionRecorder(bridge),
    historyId: null,
    terminal: null, // { term, output } of the open command line
  };
  tab.direct = direct;
  tab.viewer = new ViewerController({
    signaling: direct || signaling,
    nostr: direct ? null : nostr,
    bridge,
    getDeviceName: deviceName,
    getDeviceId: () => state.config.id,
    canReceiveClip: () => Boolean(tab.perms?.clipboard && tab.control),
    getCodec: () => state.config.codec || 'auto',
  });
  wireTab(tab);
  if (direct) {
    direct.on('relay', (from, payload) => { if (tab.viewer.peerId === from) tab.viewer.handleRelay(from, payload); });
    direct.on('unavailable', (to) => tab.viewer.handleUnavailable(to));
  }
  tabs.push(tab);
  return tab;
}

function removeTab(tab) {
  const i = tabs.indexOf(tab);
  if (i >= 0) tabs.splice(i, 1);
  tab.direct?.close();
  if (pendingTab === tab) {
    pendingTab = null;
    setConnecting(null);
  }
}

/** Adds a message to a tab's chat; shown at once when it is the tab on screen. */
function tabChat(tab, text, kind) {
  tab.chat.push({ text, kind });
  if (tab.chat.length > 500) tab.chat.shift();
  if (tab === activeTab) {
    if (kind === 'them') onIncomingChat('viewer', text);
    else addChatMessage(text, kind);
  } else if (kind === 'them') {
    tab.unread += 1;
    renderTabs();
    toast(`${tabLabel(tab)}: ${text.slice(0, 60)}`);
  }
}

function renderTabs() {
  const strip = $('#session-tabs');
  strip.replaceChildren(...tabs.filter((t) => t.connected).map((t) => {
    const b = document.createElement('div');
    b.className = `session-tab${t === activeTab ? ' active' : ''}`;
    b.innerHTML = '<span class="live-dot"></span><span class="tab-name"></span><span class="tab-unread" hidden></span><button class="tab-close" title="Bağlantıyı kes"><svg><use href="#i-x"/></svg></button>';
    b.querySelector('.tab-name').textContent = tabLabel(t);
    b.title = `${tabLabel(t)} (${formatId(t.id)})`;
    b.querySelector('.tab-unread').hidden = !t.unread;
    b.querySelector('.tab-unread').textContent = t.unread;
    b.addEventListener('click', () => activateTab(t));
    b.querySelector('.tab-close').addEventListener('click', (e) => {
      e.stopPropagation();
      t.viewer.end();
    });
    return b;
  }));
  const add = document.createElement('button');
  add.className = 'session-tab add';
  add.title = 'Başka bir cihaza bağlan (bu bağlantılar açık kalır)';
  add.innerHTML = '<svg><use href="#i-plus"/></svg>';
  add.addEventListener('click', showHomeDuringSessions);
  strip.append(add);
  const count = tabs.filter((t) => t.connected).length;
  $('#sessions-return').hidden = !count || !$('#session').hidden;
  $('#sessions-return-count').textContent = count;
}

/** Back to the home screen to connect to another device; sessions keep running. */
function showHomeDuringSessions() {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  capture?.releaseAll();
  closeChat();
  $('#session').hidden = true;
  document.body.classList.remove('in-session');
  showView('home');
  renderTabs();
  $('#partner-id').focus();
}

$('#remote-locked-close').addEventListener('click', () => { $('#remote-locked').hidden = true; });

$('#sessions-return').addEventListener('click', () => {
  if (activeTab) activateTab(activeTab);
});

function applyControlUi() {
  const allowed = Boolean(activeTab?.control);
  remoteControl = allowed;
  const badge = $('#control-badge');
  badge.textContent = allowed ? 'Uzaktan kontrol açık' : 'Sadece görüntüleme';
  badge.classList.toggle('on', allowed);
  $('#privacy-btn').disabled = !allowed;
  if (!allowed) {
    capture?.releaseAll();
    $('#privacy-btn').classList.remove('on');
  }
  renderFeatures();
}

function renderPlatform() {
  const platform = activeTab?.platform || 'desktop';
  document.body.classList.toggle('remote-android', platform === 'android');
  $('#keys-btn').title = platform === 'android' ? 'Telefon tuşları' : 'Özel tuşlar';
}

/** What the remote device offers: drawing, voice, file browser, administration. */
function renderFeatures() {
  const f = activeTab?.features || [];
  $('#draw-btn').hidden = !f.includes('draw');
  $('#mic-btn').hidden = !f.includes('voice');
  $('#file-menu [data-file="browser"]').hidden = !f.includes('fs');
  const admin = {
    terminal: 'terminal', system: 'system', procs: 'system', lock: 'power', restart: 'power', shutdown: 'power',
    sleep: 'power-plan', hibernate: 'power-plan', schedule: 'power-plan', 'cancel-plan': 'power-plan', 'block-input': 'block-input', resolution: 'resolution', switch: 'switch',
  };
  let any = false;
  for (const item of document.querySelectorAll('#admin-menu [data-admin]')) {
    const name = item.dataset.admin;
    item.hidden = !f.includes(admin[name])
      || (name === 'hibernate' && activeTab?.os === 'darwin') // macOS has no hibernate command
      || (name === 'cancel-plan' && !activeTab?.powerPlan)
      || (name === 'switch' && !state.canHost); // this device must be able to share its screen
    any = any || !item.hidden;
  }
  $('#power-action option[value="hibernate"]').hidden = activeTab?.os === 'darwin';
  $('#admin-menu [data-admin="block-input"]').textContent = activeTab?.inputBlocked ? 'Karşının fare ve klavyesini aç' : 'Karşının fare ve klavyesini kilitle';
  $('#admin-menu .menu-sep').hidden = !(f.includes('power') && (f.includes('terminal') || f.includes('system')));
  $('#admin-btn').hidden = !any;
}

function applyPermsUi() {
  const perms = activeTab?.perms;
  state.viewerPerms = perms || null;
  const files = Boolean(perms?.files && perms?.control);
  $('#file-btn').disabled = Boolean(perms) && !files;
  $('#file-btn').title = !perms || files ? 'Dosya gönder (veya sürükleyip bırakın)' : 'Uzak cihaz dosya kabul etmiyor';
  if (perms && !files) $('#fm-panel').hidden = true;
  if (perms?.draw === false && drawing?.enabled) setDrawMode(false);
}

function renderTabAudio() {
  const audio = $('#remote-audio');
  audio.srcObject = activeTab?.audio || null;
  audio.muted = readStorage('xenon.audioMuted', false);
  if (activeTab?.audio) audio.play().catch(() => {});
  renderAudioButton();
  $('#audio-btn').hidden = !activeTab?.audio;
  const voice = $('#voice-audio');
  voice.srcObject = activeTab?.voice || null;
  if (activeTab?.voice) voice.play().catch(() => {});
}

function renderScreens() {
  const select = $('#monitor-select');
  const s = activeTab?.screens;
  select.replaceChildren(...(s?.list || []).map((x) => new Option(x.name, x.sourceId, false, x.sourceId === s.current)));
  select.hidden = !s || s.list.length < 2;
}

function renderStats() {
  const stats = activeTab?.stats;
  state.lastStats = stats || null;
  if (!stats) {
    $('#session-stats').textContent = '';
    delete $('#net-dot').dataset.q;
    return;
  }
  const { fps, kbps, width, height, rtt } = stats;
  const parts = [`${width}×${height}`, `${fps} fps`, `${(kbps / 1000).toFixed(1)} Mbps`];
  if (rtt !== null) parts.push(`${rtt} ms`);
  $('#session-stats').textContent = parts.join('  ·  ');
  $('#net-dot').dataset.q = stats.quality;
  if (!$('#net-panel').hidden) renderNetPanel();
}

/** Shows a connected tab: picture, toolbar state, chat, panels. */
function activateTab(tab) {
  if (activeTab && activeTab !== tab) {
    capture?.releaseAll();
    setDrawMode(false);
    $('#fm-panel').hidden = true;
    $('#term-panel').hidden = true;
    $('#sys-panel').hidden = true;
    $('#net-panel').hidden = true;
    fm.roots = [];
    fm.path = null;
  }
  activeTab = tab;
  viewer = tab.viewer;
  tab.unread = 0;
  state.viewerTransfer = tab.transfer;
  const video = $('#remote-video');
  if (video.srcObject !== tab.stream) {
    video.srcObject = tab.stream;
    video.play().catch(() => {});
  }
  $('#session-name').textContent = tab.name || translate('Uzak cihaz');
  $('#session-id').textContent = `${formatId(tab.id)}${tab.via === 'nostr' ? ' · internet' : ''}`;
  $('#quality-select').value = tab.quality;
  $('#privacy-btn').classList.toggle('on', tab.privacy);
  $('#remote-locked').hidden = !tab.locked;
  renderSecureUi();
  applyControlUi();
  renderPlatform();
  applyPermsUi();
  renderTabAudio();
  renderScreens();
  renderStats();
  renderRecordUi();
  renderMic($('#mic-btn'), Boolean(tab.viewer.mic));
  // Chat of this tab.
  $('#chat-messages').replaceChildren();
  for (const m of tab.chat) addChatMessage(m.text, m.kind);
  state.chatPeer = 'viewer';
  $('#chat-peer').textContent = tab.name || '';
  $('.chat-badge').hidden = true;
  if (tab.terminal) renderTerminal();
  $('#session').hidden = false;
  document.body.classList.add('in-session');
  renderTabs();
  video.focus();
}

// The session's side panels live inside the session view, so the toolbar
// menus (same stacking layer) open above them instead of underneath.
for (const id of ['#fm-panel', '#term-panel', '#sys-panel']) $('#session').append($(id));

/** Input, drawing and keyboard handlers: set up with the first tab, kept for all. */
function ensureSessionUi() {
  $('#session').append($('#chat-panel')); // chat too, while viewing
  if (capture) return;
  const video = $('#remote-video');
  drawing = attachDrawing($('#draw-canvas'), video, { send: (stroke) => viewer.sendDraw(stroke), onClear: () => viewer.clearDrawing() });
  capture = attachInputCapture(video, (ev) => viewer.sendInput(adjustMouse(ev)), {
    // Draw mode uses the mouse for drawing, not for the remote device.
    isEnabled: () => remoteControl && !drawing?.enabled,
    textKeys: () => document.body.classList.contains('remote-android'),
  });
  detachKeyboard = attachMobileKeyboard($('#mobile-keys'), (ev) => viewer.sendInput(ev), { isEnabled: () => remoteControl });
  clipboardSync.start();
}

/** The last tab closed: back to the home screen. */
function closeSessionUi() {
  drawing?.detach();
  drawing = null;
  setDrawMode(false);
  capture?.detach();
  capture = null;
  detachKeyboard?.();
  detachKeyboard = null;
  remoteControl = false;
  viewer = null;
  state.viewerPerms = null;
  state.viewerTransfer = null;
  state.lastStats = null;
  if (!host?.active) clipboardSync.stop();
  document.body.append($('#chat-panel')); // the host's chat lives outside the session view
  for (const id of ['#fm-panel', '#term-panel', '#sys-panel', '#net-panel', '#keys-menu', '#admin-menu', '#transfer-bar', '#remote-locked']) $(id).hidden = true;
  fm.roots = [];
  fm.path = null;
  $('#remote-video').srcObject = null;
  $('#remote-audio').srcObject = null;
  $('#voice-audio').srcObject = null;
  $('#audio-btn').hidden = true;
  $('#draw-btn').hidden = true;
  $('#mic-btn').hidden = true;
  $('#admin-btn').hidden = true;
  renderMic($('#mic-btn'), false);
  document.body.classList.remove('remote-android');
  $('#file-btn').disabled = false;
  $('#session').hidden = true;
  document.body.classList.remove('in-session');
  $('#session-stats').textContent = '';
  clearChat();
  renderRecordUi();
  renderTabs();
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
}

function wireTab(tab) {
  const v = tab.viewer;
  const active = () => tab === activeTab;

  v.on('status', (text) => { if (tab === pendingTab) setConnecting(text); });

  v.on('failed', (reason) => {
    if (totpRespond?.tab === tab) {
      totpRespond = null;
      $('#totp-dialog').close();
    }
    const reconnect = reconnects.get(tab.id);
    removeTab(tab);
    setTimeout(applyPendingNetwork);
    if (reconnect && !['bad-password', 'blocked', 'not-trusted', 'declined', 'bad-totp'].includes(reason)) {
      scheduleReconnect(tab.id); // still waiting for the restarted computer: try again later
      return;
    }
    if (reconnect) cancelReconnect(tab.id);
    addHistory({ dir: 'out', name: '', peer: formatId(tab.id), result: reason });
    toast(REJECT_MESSAGES[reason] || 'Bağlantı kurulamadı', 'error', 5000);
  });

  v.on('connected', ({ stream, name, peerId, via }) => {
    cancelReconnect(peerId);
    tab.connected = true;
    tab.stream = stream;
    tab.name = name || '';
    tab.via = via;
    tab.historyId = addHistory({ dir: 'out', name, peer: formatId(peerId), via, result: 'ok' });
    if (!inBook(peerId) && !bookLocked()) {
      toast(`${name || formatId(peerId)} adres defterinizde yok`, 'info', 8000, {
        label: 'Deftere ekle',
        fn: () => {
          saveBookEntry({ id: peerId, name: name || `Cihaz ${formatId(peerId)}`, group: '' });
          toast('Adres defterine eklendi', 'success', 2000);
        },
      });
    }
    const last = state.lastConnect;
    if (last?.id === peerId && state.vault && !last.key) {
      bridge.setSavedPassword(peerId, last.remember && last.password ? last.password : null).catch(() => {});
    }
    if (tab === pendingTab) {
      pendingTab = null;
      setConnecting(null);
      $('#partner-password').value = '';
      delete $('#partner-password').dataset.saved;
    }
    rememberRecent(peerId, name);
    reportStatus();
    ensureSessionUi();
    tab.chat.push({ text: `${name || formatId(peerId)} cihazına bağlandınız`, kind: 'system' });
    activateTab(tab);
  });

  v.on('control', (allowed) => {
    tab.control = allowed;
    if (active()) applyControlUi();
  });
  v.on('platform', (platform) => {
    tab.platform = platform;
    if (active()) renderPlatform();
  });
  v.on('locked', (on) => {
    tab.locked = on;
    if (!active()) return;
    renderSecureUi();
    $('#remote-locked').hidden = !on;
  });
  v.on('secure', ({ on, available, state: why }) => {
    const was = tab.secure?.on;
    tab.secure = { on, available, state: why };
    if (active()) renderSecureUi();
    if (on && !was) {
      toast(`${active() ? 'Uzak bilgisayar' : tabLabel(tab)}: kilit ekranı gösteriliyor. Kilidi açmak için Windows şifresini yazın; şifre alanı yoksa önce Özel tuşlar › Ctrl+Alt+Del.`, 'info', 10000);
    }
  });
  v.on('hello', ({ features, macs, os, elevated, inputError }) => {
    tab.features = features;
    tab.os = os;
    if (inputError && !tab.inputHint) {
      tab.inputHint = true;
      toast(`Uzak bilgisayarda fare/klavye modülü çalışmıyor, bu yüzden yalnızca izlenebilir. ${inputError === 'unavailable' ? '' : `Hata: ${inputError}`}`.trim(), 'error', 15000);
    }
    if (os === 'win32' && elevated === false && !tab.elevationHint) {
      tab.elevationHint = true;
      toast('Uzak bilgisayar yönetici yetkisiyle çalışmıyor: önde Görev Yöneticisi gibi yönetici yetkili bir pencere varken fare ve klavye çalışmaz. Karşı tarafta Ayarlar › "Yönetici olarak çalıştır" açılabilir.', 'info', 12000);
    }
    if (macs.length) rememberMacs(tab.id, macs);
    if (active()) renderFeatures();
  });
  v.on('voice', (stream) => {
    tab.voice = stream;
    if (active()) renderTabAudio();
  });
  v.on('audio', (stream) => {
    tab.audio = stream;
    if (active()) renderTabAudio();
  });
  v.on('voice-state', (on) => toast(on ? `${active() ? 'Karşı taraf' : tabLabel(tab)} mikrofonunu açtı` : `${active() ? 'Karşı taraf' : tabLabel(tab)} mikrofonunu kapattı`, 'info', 3000));
  v.on('idle-warning', (seconds) => toast(`İşlem yapılmazsa bağlantı ${seconds} saniye içinde kapatılacak`, 'error', 8000));
  v.on('clip-image', (bytes) => clipboardSync.applyImage(bytes));
  v.on('perms', (perms) => {
    tab.perms = perms;
    tab.control = Boolean(perms.control);
    if (active()) {
      applyPermsUi();
      applyControlUi();
    }
  });
  v.on('privacy', (on) => {
    tab.privacy = on;
    if (!active()) return;
    $('#privacy-btn').classList.toggle('on', on);
    toast(on ? 'Gizlilik modu açıldı: uzak ekran karartıldı' : 'Gizlilik modu kapatıldı', on ? 'success' : 'info');
  });
  v.on('chat', (text) => tabChat(tab, text, 'them'));
  v.on('clip', (text) => clipboardSync.apply(text));
  v.on('files', (transfer) => {
    tab.transfer = transfer;
    wireTransfer(transfer);
    if (active()) state.viewerTransfer = transfer;
  });
  v.on('screens', (screens) => {
    tab.screens = screens;
    if (active()) renderScreens();
  });
  v.on('stats', (stats) => {
    tab.stats = stats;
    if (active()) renderStats();
  });
  v.on('term-out', ({ term, data }) => onTerminalOutput(tab, term, data));
  v.on('term-exit', ({ term }) => onTerminalExit(tab, term));
  v.on('trust', (key) => onTrusted(tab, key));
  v.on('power-plan', (plan) => onRemotePowerPlan(tab, plan));
  v.on('input-blocked', ({ on, byLocal }) => {
    tab.inputBlocked = on;
    if (active()) renderFeatures();
    if (on) toast(`${active() ? 'Karşı bilgisayarın' : `${tabLabel(tab)}:`} fare ve klavyesi kilitlendi; yalnızca siz kontrol ediyorsunuz`, 'success', 5000);
    else toast(byLocal ? 'Karşıdaki kişi fare ve klavyesinin kilidini açtı' : 'Karşı bilgisayarın fare ve klavyesi yeniden açık', 'info', 5000);
  });
  // How the lock screen pictures came through (shown only when they did not).
  v.on('secure-info', (info) => {
    tab.secureInfo = info;
    console.info('[xenon] lock screen pictures', info);
    if (info.fallback) return; // the normal capture shows the lock screen instead
    if (info.frames === 0) toast('Kilit ekranı hizmetinden görüntü gelmiyor; fare ve klavye yine çalışır', 'error', 10000);
    else if (info.brightness !== null && info.brightness < 4) toast('Kilit ekranı görüntüsü siyah geliyor (ekran kartı izin vermiyor olabilir); fare ve klavye yine çalışır', 'error', 10000);
  });
  v.on('host-recording', (on) => {
    if (on) toast(`${active() ? 'Karşı bilgisayar' : tabLabel(tab)} bu oturumu kaydediyor`, 'info', 8000);
  });
  v.on('totp', (respond) => askTotp(tab, respond));

  v.on('ended', ({ reason }) => {
    if (tab.recorder.active) stopRecording(tab, false);
    updateHistory(tab.historyId, { end: Date.now(), reason });
    const wasActive = active();
    const others = tabs.filter((t) => t !== tab && t.connected).length;
    removeTab(tab);
    setTimeout(applyPendingNetwork);
    setTimeout(reportStatus);
    if (wasActive) {
      activeTab = null;
      const next = tabs.find((t) => t.connected);
      if (next) activateTab(next);
      else closeSessionUi();
    } else {
      renderTabs();
    }
    const messages = {
      'remote-hangup': 'Uzak cihaz bağlantıyı kapattı',
      'connection-lost': 'Bağlantı koptu',
      timeout: 'Bağlantı zaman aşımına uğradı',
      idle: 'Uzun süre işlem yapılmadığı için bağlantı kapatıldı',
      'ip-blocked': 'Uzak bilgisayar bu IP adresinden bağlanılmasına izin vermiyor',
      switched: 'Roller değişti: karşı taraf şimdi sizin ekranınıza bağlanıyor',
    };
    const text = messages[reason] || 'Oturum sona erdi';
    if (reason === 'connection-lost' && !reconnects.has(tab.id)) {
      // A short network drop: try to get back in for a while instead of giving up.
      reconnects.set(tab.id, { credential: tab.credential, name: tab.name, until: Date.now() + DROP_RECONNECT_MS, every: 3000, drop: true, timer: null });
      toast(`${others ? `${tabLabel(tab)}: ` : ''}${translate('Bağlantı koptu, yeniden bağlanılıyor…')}`, 'error', 8000,
        { label: 'Vazgeç', fn: () => cancelReconnect(tab.id) });
      scheduleReconnect(tab.id);
      return;
    }
    toast(others ? `${tabLabel(tab)}: ${translate(text)}` : text, reason === 'local-hangup' ? 'info' : 'error');
    if (reconnects.has(tab.id)) scheduleReconnect(tab.id);
  });
}

/**
 * "10.8.0.5", "10.8.0.5:8090", "server.example.lan" -> ws:// address of the
 * Xenon server built into the app on that computer (port 8080 by default);
 * a Xenon ID (digits only) -> null.
 */
function addressUrl(text) {
  const t = String(text || '').trim();
  if (!t || /^[\d\s]+$/.test(t)) return null;
  const m = /^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9][a-zA-Z0-9.-]*)(?::(\d{1,5}))?$/.exec(t);
  if (!m || (!m[1].includes('.') && !m[1].startsWith('[') && !/[a-z]/i.test(m[1]))) return null;
  const port = m[2] ? Number(m[2]) : 8080;
  if (port < 1 || port > 65535) return null;
  return `ws://${m[1]}:${port}`;
}

/** Connects straight to a computer's own Xenon server by IP address (VPN, other networks). */
function connectByAddress(address, password) {
  if (pendingTab) return;
  const url = addressUrl(address);
  setConnecting(translate('Adrese bağlanılıyor…'));
  const client = new SignalingClient({ url, id: state.config.id });
  let done = false;
  const finish = (id) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (!id) {
      client.close();
      setConnecting(null);
      toast(`${address} adresinde Xenon Remote bulunamadı. O bilgisayarda uygulama açık mı, ağ modu "Otomatik" ya da sunucu mu, güvenlik duvarı ${url.split(':').pop()} portuna izin veriyor mu?`, 'error', 10000);
      return;
    }
    setConnecting(null);
    startConnection(id, password, { signaling: client });
    if (pendingTab?.direct !== client) client.close(); // not used (e.g. already open, or this device)
  };
  const timer = setTimeout(() => finish(null), 8000);
  client.on('registered', () => client.askOwner());
  client.on('owner', (id) => finish(id));
  client.connect();
}

/** Opens a new tab (or shows the existing one) for a device. */
function startConnection(id, password, { remember = false, signaling: direct = null } = {}) {
  if (pendingTab) return;
  if (!/^\d{9}$/.test(id)) {
    toast('Lütfen 9 haneli bir Xenon ID girin', 'error');
    return;
  }
  if (id === signaling.id) {
    toast('Kendi cihazınıza bağlanamazsınız', 'error');
    return;
  }
  if (host.active) {
    toast('Bu cihaz şu anda paylaşılıyor', 'error');
    return;
  }
  const open = tabs.find((t) => t.id === id && t.connected);
  if (open) {
    activateTab(open);
    return;
  }
  if (tabs.length >= MAX_TABS) {
    toast(`Aynı anda en fazla ${MAX_TABS} cihaza bağlanılabilir`, 'error');
    return;
  }
  // A trusted-device key ("key:<hex>") connects without the password.
  const key = typeof password === 'string' && password.startsWith('key:') ? hexToSecret(password.slice(4)) : null;
  state.lastConnect = { id, password: key ? '' : password, key: Boolean(key), remember: state.vault && remember };
  pendingTab = createTab(id, direct);
  pendingTab.credential = password; // for reconnecting after a remote restart
  if (!viewer) viewer = pendingTab.viewer;
  pendingTab.viewer.connect(id, key || password);
}

function wireViewer() {
  $('#connect-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const raw = $('#partner-id').value.trim();
    const field = $('#partner-password');
    // A remembered trusted-device key stays hidden in the field's dataset.
    const password = field.dataset.key || field.value;
    if (addressUrl(raw)) {
      connectByAddress(raw, password);
      return;
    }
    startConnection(normalizeId(raw), password, { remember: $('#remember-password').checked });
  });

  $('#partner-id').addEventListener('input', (e) => {
    delete $('#partner-password').dataset.key;
    // An IP address or host name is left as typed (connect by address).
    if (/[^\d\s]/.test(e.target.value)) return;
    const digits = normalizeId(e.target.value).slice(0, 9);
    e.target.value = formatId(digits);
  });

  $('#cancel-connect').addEventListener('click', () => {
    const tab = pendingTab;
    if (!tab) return;
    tab.viewer.cancel();
    removeTab(tab);
  });

  $('#privacy-btn').addEventListener('click', () => {
    if (!remoteControl) {
      toast('Gizlilik modu için uzaktan kontrol izni gerekir', 'error');
      return;
    }
    viewer.setPrivacy(!$('#privacy-btn').classList.contains('on'));
  });

  $('#monitor-select').addEventListener('change', (e) => {
    if (!remoteControl) {
      toast('Monitör değiştirmek için uzaktan kontrol izni gerekir', 'error');
      return;
    }
    viewer.switchScreen(e.target.value);
  });

  $('#disconnect-btn').addEventListener('click', () => viewer?.end());
  $('#keyboard-btn').addEventListener('click', () => {
    if (!remoteControl) {
      toast('Uzak cihaz kontrole izin vermiyor', 'error');
      return;
    }
    $('#mobile-keys').focus();
  });
  $('#quality-select').addEventListener('change', (e) => {
    if (activeTab) activeTab.quality = e.target.value;
    viewer.setQuality(e.target.value);
  });
  $('#fit-toggle').addEventListener('click', () => {
    const stage = $('#stage');
    stage.dataset.fit = stage.dataset.fit === 'contain' ? 'actual' : 'contain';
    $('#fit-toggle').classList.toggle('active', stage.dataset.fit === 'actual');
    $('#remote-video').focus();
  });
  $('#fullscreen-btn').addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else $('#session').requestFullscreen().catch(() => {});
  });
  $('#session-chat-btn').addEventListener('click', () => {
    if ($('#chat-panel').hidden) openChat('viewer', $('#session-name').textContent);
    else closeChat();
  });
}

/* Settings ----------------------------------------------------------- */

function selectedMode() {
  return document.querySelector('input[name="server-mode"]:checked')?.value || 'auto';
}

/** Validated TURN relay from the settings form; null when left empty. */
function readTurnForm() {
  const urls = $('#turn-url').value.split(/[\s,]+/).map((u) => u.trim()).filter(Boolean);
  if (!urls.length) return null;
  if (!urls.every((u) => /^turns?:[^\s]+$/i.test(u))) throw new Error('TURN adresi turn: veya turns: ile başlamalı');
  return { urls, username: $('#turn-user').value.trim(), credential: $('#turn-pass').value };
}

function turnIceServers(turn) {
  if (!turn?.urls?.length) return [];
  return [{ urls: turn.urls, username: turn.username || undefined, credential: turn.credential || undefined }];
}

function renderSettings() {
  $('#device-name').value = state.config.deviceName || '';
  const turn = state.config.turn;
  $('#turn-url').value = turn?.urls?.join(', ') || '';
  $('#turn-user').value = turn?.username || '';
  $('#turn-pass').value = turn?.credential || '';
  $('#turn-settings').open = Boolean(turn);
  $('#server-url').value = state.config.serverUrl && !/127\.0\.0\.1|localhost/.test(state.config.serverUrl) ? state.config.serverUrl : '';
  const mode = state.network?.mode || state.config.serverMode || 'auto';
  for (const radio of document.querySelectorAll('input[name="server-mode"]')) radio.checked = radio.value === mode;
  renderModeFields();
}

function renderModeFields() {
  $('#manual-server').hidden = selectedMode() !== 'manual';
}

function renderNetworkSettings() {
  const net = state.network;
  const info = $('#network-info');
  const list = $('#network-addresses');
  const autoRadio = document.querySelector('input[name="server-mode"][value="auto"]');
  autoRadio.disabled = Boolean(net?.unsupported);
  list.hidden = true;
  if (!net) {
    info.textContent = '';
    return;
  }
  if (net.mode === 'manual') {
    info.textContent = `Özel sunucu kullanılıyor: ${net.url || '—'}`;
  } else if (net.role === 'server') {
    info.textContent = 'Bu bilgisayar ağın sunucusu. Aynı ağdaki diğer cihazlar otomatik olarak bağlanır. Başka bir ağdan bağlanmak için şu adresler "Özel sunucu" olarak kullanılabilir:';
    list.replaceChildren(
      ...(net.addresses || []).map((address) => {
        const li = document.createElement('li');
        li.innerHTML = '<code></code><button type="button" class="icon-btn" title="Kopyala"><svg><use href="#i-copy"/></svg></button>';
        li.querySelector('code').textContent = address;
        li.querySelector('button').addEventListener('click', () => copy(address, 'Adres'));
        return li;
      }),
    );
    list.hidden = !(net.addresses || []).length;
  } else if (net.role === 'client') {
    const server = (net.servers || []).find((x) => x.url === net.url);
    info.textContent = `Ağdaki sunucuya bağlı: ${hostOf(net.url)}${server?.name ? ` (${server.name})` : ''}`;
  } else {
    info.textContent = net.error ? `Sunucu başlatılamadı: ${net.error}` : 'Ağ taranıyor…';
  }
}

for (const radio of document.querySelectorAll('input[name="server-mode"]')) {
  radio.addEventListener('change', renderModeFields);
}

$('#settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const mode = selectedMode();
  const serverUrl = $('#server-url').value.trim();
  // An empty field keeps the current server (or none: internet-only, e.g. the phone).
  const needsUrl = mode === 'manual' && (serverUrl || state.network?.mode !== 'manual');
  if (needsUrl && !/^wss?:\/\/\S+$/i.test(serverUrl)) {
    toast('Sunucu adresi ws:// veya wss:// ile başlamalı', 'error');
    return;
  }
  const internetAccess = $('#internet-access').checked;
  const internetChanged = internetAccess !== (state.config.internetAccess !== false);
  if (internetChanged && (host.active || anyViewerBusy())) {
    toast('Aktif oturum sırasında internet erişimi değiştirilemez', 'error');
    return;
  }
  let turn;
  try {
    turn = readTurnForm();
  } catch (err) {
    toast(err.message, 'error');
    return;
  }
  state.config = await bridge.setConfig({ deviceName: $('#device-name').value.trim(), internetAccess, turn });
  signaling.setRelayServers(turnIceServers(state.config.turn));
  state.deviceName = state.config.deviceName || state.deviceName;
  if (internetChanged) {
    location.reload();
    return;
  }
  const modeChanged = mode !== state.network?.mode || (mode === 'manual' && serverUrl && serverUrl !== state.network?.url);
  if (modeChanged) {
    applyNetwork(await bridge.setNetwork(mode, mode === 'manual' ? serverUrl : undefined));
    state.config = await bridge.getConfig();
  }
  toast('Ayarlar kaydedildi', 'success');
});

$('#new-id-btn').addEventListener('click', async () => {
  if (host.active || anyViewerBusy()) {
    toast('Aktif oturum sırasında ID değiştirilemez', 'error');
    return;
  }
  const id = generateDeviceId();
  state.config = await bridge.setConfig({ id });
  $('#my-id').textContent = formatId(id);
  signaling.id = id;
  signaling.reconnect();
  await onIdChanged();
  toast('Yeni ID oluşturuldu', 'success');
});

/* Unattended access / startup ---------------------------------------- */

function renderUnattended() {
  const status = $('#unattended-status');
  const enabled = Boolean(state.unattended);
  if (!state.vault) {
    status.textContent = 'Bu cihazda işletim sisteminin şifreli deposu kullanılamıyor; gözetimsiz erişim kapalı.';
    $('#unattended-fields').hidden = true;
    $('#unattended-save').hidden = true;
    $('#unattended-remove').hidden = true;
    return;
  }
  status.textContent = enabled
    ? 'Açık: bu bilgisayara kalıcı şifreyle her zaman bağlanılabilir.'
    : 'Kapalı: yalnızca ekrandaki tek kullanımlık şifre geçerli.';
  $('#unattended-fields').hidden = false;
  $('#unattended-save').hidden = false;
  $('#unattended-save').textContent = enabled ? 'Kalıcı şifreyi değiştir' : 'Kalıcı şifreyi kaydet';
  $('#unattended-remove').hidden = !enabled;
  renderTotp();
}

/* Two-step verification for the permanent password ----------------------- */

let totpDraft = null; // secret being set up (not saved until a code checks out)

function renderTotp() {
  const on = Boolean(state.totp);
  $('#totp-section').hidden = !state.unattended;
  $('#totp-status').textContent = on
    ? 'Açık: kalıcı şifreyle bağlanan kişi ayrıca telefonunuzdaki doğrulama uygulamasının kodunu girmek zorunda.'
    : 'Kapalı: kalıcı şifreyi bilen herkes bağlanabilir. Açarsanız şifre çalınsa bile telefonunuz olmadan kimse bağlanamaz.';
  $('#totp-setup').hidden = !totpDraft;
  $('#totp-actions').hidden = Boolean(totpDraft);
  $('#totp-toggle').textContent = on ? 'İki aşamalı doğrulamayı kapat' : 'İki aşamalı doğrulamayı aç';
}

async function saveTotp(totp) {
  const stored = await bridge.getUnattended();
  if (!stored) throw new Error('no unattended access');
  await bridge.setUnattended({ secret: stored.secret, id: stored.id, ...(totp ? { totp } : {}) });
  const back = await bridge.getUnattended();
  if ((back?.totp || null) !== (totp || null)) throw new Error('verify failed');
  state.totp = totp || null;
}

$('#totp-toggle').addEventListener('click', async () => {
  if (state.totp) {
    if (!window.confirm(translate('İki aşamalı doğrulama kapatılsın mı? Kalıcı şifre tek başına yeterli olur.'))) return;
    try {
      await saveTotp(null);
      toast('İki aşamalı doğrulama kapatıldı', 'success');
    } catch {
      toast('Ayar kaydedilemedi', 'error');
    }
    renderTotp();
    return;
  }
  totpDraft = generateTotpSecret();
  const account = formatId(state.config.id);
  $('#totp-qr').innerHTML = qrSvg(otpauthUri(totpDraft, account));
  $('#totp-secret').textContent = totpDraft.replace(/(.{4})/g, '$1 ').trim();
  $('#totp-code').value = '';
  renderTotp();
  $('#totp-code').focus();
});

$('#totp-setup-cancel').addEventListener('click', () => {
  totpDraft = null;
  renderTotp();
});

async function confirmTotp() {
  if (!totpDraft) return;
  if ((await verifyTotp(totpDraft, $('#totp-code').value)) < 0) {
    toast('Kod tutmadı. Telefonun saatinin doğru olduğundan emin olup yeni kodu girin.', 'error', 6000);
    return;
  }
  try {
    await saveTotp(totpDraft);
  } catch {
    toast('Ayar kaydedilemedi (işletim sistemi şifreli deposu)', 'error', 6000);
    return;
  }
  totpDraft = null;
  renderTotp();
  toast('İki aşamalı doğrulama açıldı', 'success', 4000);
}
$('#totp-confirm').addEventListener('click', confirmTotp);
// Enter in the code field must not submit the permanent-password form around it.
$('#totp-code').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  confirmTotp();
});

/** Viewer side: the remote computer asks for the code from its owner's authenticator app. */
let totpRespond = null;
function askTotp(tab, respond) {
  totpRespond = { tab, respond };
  $('#totp-device').textContent = tab.name || formatId(tab.id);
  $('#totp-input').value = '';
  if (!$('#totp-dialog').open) $('#totp-dialog').showModal();
  $('#totp-input').focus();
}
$('#totp-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const pending = totpRespond;
  totpRespond = null;
  $('#totp-dialog').close();
  pending?.respond($('#totp-input').value);
});
$('#totp-cancel').addEventListener('click', () => {
  const pending = totpRespond;
  totpRespond = null;
  $('#totp-dialog').close();
  if (!pending) return;
  cancelReconnect(pending.tab.id);
  pending.tab.viewer.cancel();
  removeTab(pending.tab);
});
$('#totp-dialog').addEventListener('cancel', (e) => {
  e.preventDefault();
  $('#totp-cancel').click();
});

$('#unattended-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#unattended-password').value;
  if (password.length < 8) {
    toast('Kalıcı şifre en az 8 karakter olmalı', 'error');
    return;
  }
  if (password !== $('#unattended-confirm').value) {
    toast('Şifreler eşleşmiyor', 'error');
    return;
  }
  const secret = await deriveSecret(state.config.id, password);
  try {
    await bridge.setUnattended({ secret: secretToHex(secret), id: state.config.id, ...(state.totp ? { totp: state.totp } : {}) });
    const back = await bridge.getUnattended();
    if (!back || back.secret !== secretToHex(secret)) throw new Error('verify failed');
  } catch (err) {
    console.warn('[xenon] unattended save failed', err);
    toast('Kalıcı şifre kaydedilemedi (işletim sistemi şifreli deposu). Oturumu yönetici olarak açmayı deneyin.', 'error', 8000);
    return;
  }
  state.unattended = secret;
  $('#unattended-password').value = '';
  $('#unattended-confirm').value = '';
  renderUnattended();
  listenOnInternet();
  toast('Gözetimsiz erişim açıldı', 'success');
});

$('#unattended-remove').addEventListener('click', async () => {
  await bridge.setUnattended(null);
  state.unattended = null;
  state.totp = null;
  renderUnattended();
  listenOnInternet();
  toast('Gözetimsiz erişim kapatıldı');
});

async function initStartup() {
  if (!bridge.getAutoStart) {
    $('#startup-card').hidden = true;
    return;
  }
  const auto = await bridge.getAutoStart();
  $('#autostart-toggle').checked = auto.enabled;
  $('#autostart-toggle').disabled = !auto.supported;
  if (!auto.supported) $('#autostart-hint').textContent = 'Bu kurulum türünde desteklenmiyor.';
  $('#background-toggle').checked = state.config.runInBackground !== false;
}

$('#autostart-toggle').addEventListener('change', async (e) => {
  const result = await bridge.setAutoStart(e.target.checked);
  e.target.checked = result.enabled;
  toast(result.enabled ? 'Xenon Remote bilgisayar açılınca başlayacak' : 'Otomatik başlatma kapatıldı', 'success');
});

/** Windows: run as administrator, to control admin windows (Task Manager...). */
async function initAdminMode() {
  if (!bridge.getAdminMode) return;
  const mode = await bridge.getAdminMode().catch(() => null);
  if (!mode?.supported) return;
  $('#admin-mode-option').hidden = false;
  $('#admin-mode').checked = mode.enabled;
  $('#admin-mode-state').hidden = !mode.elevated;
}

$('#admin-mode').addEventListener('change', async (e) => {
  const on = e.target.checked;
  if (on && !window.confirm(translate('Xenon Remote yönetici olarak yeniden başlatılacak (Windows bir kez izin isteyecek). Açık bağlantılar kapanır. Devam edilsin mi?'))) {
    e.target.checked = false;
    return;
  }
  const result = await bridge.setAdminMode(on).catch(() => null);
  if (result?.restarting) toast('Yönetici olarak yeniden başlatılıyor…', 'info', 5000);
  else if (on) toast(result?.task ? 'Yönetici modu açık' : 'Yönetici modu açıldı, ancak otomatik yönetici başlatma ayarlanamadı', result?.task ? 'success' : 'error', 6000);
  else toast('Yönetici modu kapatıldı; uygulama bir sonraki açılışta normal yetkiyle çalışır', 'success', 6000);
});

/* Remote printing (Windows) ---------------------------------------------- */

let printerInfo = null;

async function renderPrinterCard() {
  if (!bridge.printerStatus) return;
  printerInfo = await bridge.printerStatus().catch(() => null);
  $('#printer-card').hidden = !printerInfo?.supported;
  if (!printerInfo?.supported) return;
  $('#printer-status').textContent = printerInfo.installed
    ? `Açık: yazıcı kurulu (${printerInfo.driver}).`
    : 'Kapalı.';
  $('#printer-toggle').textContent = printerInfo.installed ? 'Kapat (yazıcıyı kaldır)' : 'Aç (yazıcıyı ekle)';
}

$('#printer-toggle').addEventListener('click', async () => {
  const on = !printerInfo?.installed;
  $('#printer-toggle').disabled = true;
  try {
    const result = await bridge.setPrinter(on);
    if (!result?.ok) toast(on ? 'Yazıcı eklenemedi (yönetici izni verilmedi ya da bir hata oluştu)' : 'Yazıcı kaldırılamadı', 'error', 7000);
    else toast(on ? 'Uzak yazıcı eklendi' : 'Uzak yazıcı kaldırıldı', 'success', 4000);
  } finally {
    $('#printer-toggle').disabled = false;
    renderPrinterCard();
  }
});

// A job printed on this computer to "Xenon Remote Yazıcı": to the connected viewer(s).
bridge.onPrintJob?.((job) => {
  const sent = host?.active ? host.sendPrintJob(job) : 0;
  toast(sent ? 'Yazdırma işi uzak kullanıcıya gönderiliyor' : 'Yazdırma işi gönderilemedi: dosya alabilen bağlı kimse yok', sent ? 'info' : 'error', 6000);
});

/* Lock screen access (Windows service) ----------------------------------- */

let secureInfo = null;

async function renderSecureCard() {
  if (!bridge.getSecure) return;
  secureInfo = await bridge.getSecure().catch(() => null);
  // Told to viewers when this computer gets locked (what is missing for the lock screen).
  const before = state.secureState;
  state.secureState = !secureInfo?.supported ? null : !secureInfo.installed ? 'not-installed'
    : secureInfo.link?.state === 'needs-admin' || !secureInfo.elevated ? 'needs-admin' : secureInfo.link?.state || null;
  if (before !== state.secureState && host?.active) host.sendData(host.secureMessage());
  const card = $('#secure-card');
  card.hidden = !secureInfo?.supported;
  if (card.hidden) return;
  const link = secureInfo.link?.state;
  let text;
  if (!secureInfo.installed) text = 'Kapalı: bilgisayar kilitliyken uzaktan yalnızca kilit ekranı bildirimi görünür.';
  else if (!secureInfo.running) text = 'Hizmet kurulu ama çalışmıyor. Kapatıp yeniden açmayı deneyin.';
  else if (!secureInfo.elevated || link === 'needs-admin') text = 'Hizmet kurulu. Kullanabilmek için uygulamanın yönetici olarak çalışması gerekiyor.';
  else if (link === 'connected') text = 'Açık: kilit ekranı, yeniden başlatma sonrası giriş ekranı ve UAC pencereleri uzaktan kullanılabilir.';
  else if (link === 'error') text = `Hizmet kurulu ama bağlantı kurulamadı: ${secureInfo.link?.error || ''}`.trim();
  else text = 'Hizmet kurulu, bağlantısı bekleniyor…';
  $('#secure-status').textContent = text;
  $('#secure-toggle').textContent = secureInfo.installed ? 'Kapat (hizmeti kaldır)' : 'Aç (hizmeti kur)';
  $('#secure-admin').hidden = !secureInfo.installed || secureInfo.elevated;
}

/**
 * Windows: offered once, so a locked computer can be used remotely without
 * someone first finding the setting; and a reminder while it cannot work.
 */
function offerSecure() {
  if (!secureInfo?.supported || state.loginScreen) return;
  if (!secureInfo.installed && !state.config.secureOffered) {
    bridge.setConfig({ secureOffered: true }).then((c) => { state.config = c; }).catch(() => {});
    toast('Bu bilgisayar kilitliyken de uzaktan kullanılabilsin mi? (Kilit ekranında erişim)', 'info', 20000, {
      label: 'Aç',
      fn: () => {
        showView('settings');
        $('#secure-toggle').click();
      },
    });
  } else if (secureInfo.installed && state.secureState === 'needs-admin') {
    toast('Kilit ekranında erişim için Xenon Remote yönetici olarak çalışmalı', 'error', 15000, { label: 'Yönetici olarak çalıştır', fn: () => $('#secure-admin').click() });
  }
}

$('#secure-toggle').addEventListener('click', async () => {
  const on = !secureInfo?.installed;
  if (on && !window.confirm(translate('Kilit ekranı erişimi için Xenon Remote Service kurulsun mu? Windows bir kez yönetici izni isteyecek.'))) return;
  $('#secure-toggle').disabled = true;
  try {
    const result = await bridge.setSecure(on);
    if (!result?.ok) toast(on ? 'Hizmet kurulamadı (yönetici izni verilmedi ya da bir hata oluştu)' : 'Hizmet kaldırılamadı', 'error', 7000);
    else if (on) toast('Kilit ekranı erişimi açıldı', 'success', 4000);
    else toast('Kilit ekranı erişimi kapatıldı', 'success', 4000);
    if (result?.ok && on && !result.elevated) $('#secure-admin').click();
  } finally {
    $('#secure-toggle').disabled = false;
    renderSecureCard();
  }
});

$('#secure-admin').addEventListener('click', async () => {
  if (!window.confirm(translate('Xenon Remote yönetici olarak yeniden başlatılacak (Windows bir kez izin isteyecek). Açık bağlantılar kapanır. Devam edilsin mi?'))) return;
  const result = await bridge.setAdminMode(true).catch(() => null);
  if (result?.restarting) toast('Yönetici olarak yeniden başlatılıyor…', 'info', 5000);
  else renderSecureCard();
});

bridge.onSecureLink?.(() => renderSecureCard());

$('#background-toggle').addEventListener('change', async (e) => {
  state.config = await bridge.setConfig({ runInBackground: e.target.checked });
});

/* Session tools: files, special keys, screenshot, clipboard ------------- */

const clipboardSync = new ClipboardSync({
  bridge,
  send: (text) => (host?.active ? host.sendClip(text) : viewer?.sendClip(text)),
  sendImage: (png) => (host?.active ? host.sendClipImage(png) : state.viewerTransfer?.sendClipImage(png)),
  isEnabled: () => (host?.active ? host.clipboardShared : Boolean(state.viewerPerms?.clipboard ?? remoteControl)),
});

function renderAudioButton() {
  const muted = $('#remote-audio').muted;
  $('#audio-btn').querySelector('use').setAttribute('href', muted ? '#i-volume-off' : '#i-volume');
  $('#audio-btn').title = muted ? 'Uzak sesi aç' : 'Uzak sesi kapat';
  $('#audio-btn').classList.toggle('on', muted);
}

$('#audio-btn').addEventListener('click', () => {
  const audio = $('#remote-audio');
  audio.muted = !audio.muted;
  writeStorage('xenon.audioMuted', audio.muted);
  if (!audio.muted) audio.play().catch(() => {});
  renderAudioButton();
});

/* Permissions: defaults (Settings) and live toggles (host banner) ---------- */

/** The viewer's mouse settings: swapped buttons, reversed wheel. */
function adjustMouse(ev) {
  const c = state.config;
  if (c.mouseSwap && (ev.t === 'md' || ev.t === 'mu') && (ev.b === 0 || ev.b === 2)) return { ...ev, b: 2 - ev.b };
  if (c.wheelReverse && ev.t === 'wh') return { ...ev, dx: -ev.dx, dy: -ev.dy };
  return ev;
}

function applyPointerStyle() {
  $('#remote-video').dataset.pointer = ['dot', 'none'].includes(state.config.pointerStyle) ? state.config.pointerStyle : 'normal';
}

for (const [id, key] of [['#lock-on-end', 'lockOnEnd'], ['#record-incoming', 'recordIncoming'], ['#mouse-swap', 'mouseSwap'], ['#wheel-reverse', 'wheelReverse']]) {
  $(id).addEventListener('change', async (e) => {
    state.config = await bridge.setConfig({ [key]: e.target.checked });
  });
}
$('#pointer-style').addEventListener('change', async (e) => {
  state.config = await bridge.setConfig({ pointerStyle: e.target.value });
  applyPointerStyle();
});

function renderSessionSettings() {
  $('#idle-timeout').value = String(Number(state.config.idleMinutes) || 0);
  $('#lock-on-end').checked = Boolean(state.config.lockOnEnd);
  $('#record-incoming').checked = Boolean(state.config.recordIncoming);
  $('#mouse-swap').checked = Boolean(state.config.mouseSwap);
  $('#wheel-reverse').checked = Boolean(state.config.wheelReverse);
  $('#pointer-style').value = ['dot', 'none'].includes(state.config.pointerStyle) ? state.config.pointerStyle : 'normal';
  applyPointerStyle();
  $('#language-select').value = state.config.language === 'en' ? 'en' : 'tr';
  $('#theme-select').value = ['light', 'system'].includes(state.config.theme) ? state.config.theme : 'dark';
}

/* Colours: dark, light or the operating system's choice. */
const lightScheme = window.matchMedia?.('(prefers-color-scheme: light)');
let themeChoice = readStorage('xenon.theme', 'dark');

function applyTheme(choice = themeChoice) {
  themeChoice = ['light', 'system'].includes(choice) ? choice : 'dark';
  const light = themeChoice === 'light' || (themeChoice === 'system' && Boolean(lightScheme?.matches));
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', light ? '#f4f6fb' : '#0b1020');
  // Remembered here too, so the next start shows the right colours at once.
  writeStorage('xenon.theme', themeChoice);
}
applyTheme();
lightScheme?.addEventListener?.('change', () => { if (themeChoice === 'system') applyTheme(); });

$('#theme-select').addEventListener('change', async (e) => {
  applyTheme(e.target.value);
  state.config = await bridge.setConfig({ theme: themeChoice });
});

// The language changes at once (no reload, so even during a session).
$('#language-select').addEventListener('change', async (e) => {
  const language = e.target.value === 'en' ? 'en' : 'tr';
  applyLanguage(language);
  state.config = await bridge.setConfig({ language });
  // Texts that only refresh when shown again.
  renderRecent();
  if (bridge.getUpdateStatus) renderUpdate(await bridge.getUpdateStatus().catch(() => ({})));
  toast(language === 'en' ? 'Language: English' : 'Dil: Türkçe', 'success', 2000);
});

$('#idle-timeout').addEventListener('change', async (e) => {
  state.config = await bridge.setConfig({ idleMinutes: Number(e.target.value) || 0 });
  toast(Number(e.target.value) ? 'İşlem yapılmayan oturumlar kapatılacak' : 'Oturumlar süresiz açık kalacak', 'success', 2000);
});

function renderDefaultPermissions() {
  const perms = { ...DEFAULT_PERMISSIONS, ...(state.config.permissions || {}) };
  for (const box of document.querySelectorAll('[data-default-perm]')) box.checked = Boolean(perms[box.dataset.defaultPerm]);
}

for (const box of document.querySelectorAll('[data-default-perm]')) {
  box.addEventListener('change', async () => {
    const permissions = { ...DEFAULT_PERMISSIONS, ...(state.config.permissions || {}), [box.dataset.defaultPerm]: box.checked };
    state.config = await bridge.setConfig({ permissions });
    toast('İzin varsayılanı kaydedildi', 'success', 1800);
  });
}

function renderHostPermissions(perms) {
  for (const box of document.querySelectorAll('#host-perms-menu [data-perm]')) box.checked = Boolean(perms[box.dataset.perm]);
}

$('#host-perms-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  renderHostPermissions(host.currentPermissions());
  $('#host-perms-menu').hidden = !$('#host-perms-menu').hidden;
});
$('#host-perms-menu').addEventListener('click', (e) => e.stopPropagation());
document.addEventListener('click', () => { $('#host-perms-menu').hidden = true; });
for (const box of document.querySelectorAll('#host-perms-menu [data-perm]')) {
  box.addEventListener('change', () => host.setPermission(box.dataset.perm, box.checked));
}

function formatBytes(n) {
  if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Remaining time as "0:42", "12:05" or "1:04:09". */
function etaText(sec) {
  if (sec === null || sec === undefined || !Number.isFinite(sec)) return '';
  const two = (n) => String(n).padStart(2, '0');
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h ? `${h}:${two(m)}:${two(sec % 60)}` : `${m}:${two(sec % 60)}`;
}

function wireTransfer(transfer) {
  const bar = $('#transfer-bar');
  transfer.on('progress', ({ direction, name, done, size, rate, eta }) => {
    if ($('#session').hidden) return; // the host sees toasts instead
    bar.hidden = done >= size;
    const speed = rate ? ` · ${formatBytes(rate)}/sn${eta !== null && eta !== undefined ? ` · kalan ${etaText(eta)}` : ''}` : '';
    $('#transfer-text').textContent = `${direction === 'out' ? 'Gönderiliyor' : 'Alınıyor'}: ${name} (${formatBytes(done)} / ${formatBytes(size)}${speed})`;
    $('#transfer-progress').value = size ? Math.round((done / size) * 100) : 100;
  });
  let lastSent = '';
  let verifiedAll = true;
  transfer.on('sent', ({ name, verified }) => {
    lastSent = name;
    if (!verified) verifiedAll = false;
  });
  transfer.on('done', ({ sent }) => {
    const check = verifiedAll ? ' (bütünlüğü doğrulandı)' : '';
    verifiedAll = true;
    if (sent === 1) toast(`Gönderildi: ${lastSent}${check}`, 'success');
    else if (sent > 1) toast(`${sent} dosya gönderildi${check}`, 'success');
    if (!$('#fm-panel').hidden && fm.path) fmOpen(fm.path); // show uploads in the remote folder
  });
  // Many files (a folder) arrive as one message.
  let received = [];
  let receivedTimer = null;
  transfer.on('received', (file) => {
    // A print job from the remote computer's "Xenon Remote Yazıcı": offered to open (PDF/XPS only).
    if (file.kind === 'print' && /\.(pdf|xps)$/i.test(file.name) && bridge.openPrintJob) {
      toast('Uzak bilgisayardan yazdırma işi geldi', 'success', 15000, { label: 'Aç', fn: () => bridge.openPrintJob(file.path) });
      return;
    }
    received.push(file);
    clearTimeout(receivedTimer);
    receivedTimer = setTimeout(() => {
      const list = received;
      received = [];
      const last = list[list.length - 1];
      const action = bridge.revealFile && last.path ? { label: 'Klasörü aç', fn: () => bridge.revealFile(last.path) } : null;
      const check = list.every((f) => f.verified) ? ' (bütünlüğü doğrulandı)' : '';
      toast(`${list.length === 1 ? `Dosya alındı: ${last.name}` : `${list.length} dosya alındı`}${check}`, 'success', 8000, action);
    }, 700);
  });
  transfer.on('rejected', ({ name }) => toast(`${name} reddedildi: karşı tarafta uzaktan kontrol veya dosya izni kapalı olabilir`, 'error', 6000));
  transfer.on('blocked', ({ name }) => toast(`${name} reddedildi: uzaktan kontrol ya da dosya aktarımı izni kapalı`, 'error', 6000));
  transfer.on('error', (message) => toast(message, 'error', 6000));
}

let fileTarget = null;
/** target: 'viewer' (to the remote Downloads), 'host' (to every viewer) or 'fm' (into the open remote folder). */
function pickFiles(target, folder = false) {
  fileTarget = target;
  const input = folder ? $('#folder-input') : $('#file-input');
  input.value = '';
  input.click();
}

function sendPicked(files) {
  if (!files.length) return;
  if (fileTarget === 'host') {
    for (const transfer of state.hostTransfers.values()) transfer.send(files); // to every connected viewer
  } else if (state.viewerTransfer) {
    state.viewerTransfer.send(files, fileTarget === 'fm' && fm.path ? { dir: fm.path } : {});
  }
}

$('#file-input').addEventListener('change', (e) => sendPicked([...e.target.files]));
$('#folder-input').addEventListener('change', (e) => sendPicked([...e.target.files]));
$('#file-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('#file-menu').hidden = !$('#file-menu').hidden;
});
document.addEventListener('click', () => { $('#file-menu').hidden = true; });
for (const item of document.querySelectorAll('#file-menu [data-file]')) {
  item.addEventListener('click', () => {
    $('#file-menu').hidden = true;
    if (item.dataset.file === 'browser') openFileManager();
    else pickFiles('viewer', item.dataset.file === 'folder');
  });
}
$('#host-file-btn').addEventListener('click', () => pickFiles('host'));

/** Files and whole folders dropped on the remote screen (folders keep their structure). */
async function filesFromDrop(dataTransfer) {
  const entries = [...(dataTransfer?.items || [])].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return [...(dataTransfer?.files || [])];
  const out = [];
  const walk = async (entry) => {
    if (out.length >= 10000) return;
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      file.relativeName = entry.fullPath.replace(/^\/+/, '');
      out.push(file);
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        for (const child of batch) await walk(child);
      }
    }
  };
  for (const entry of entries) await walk(entry).catch(() => {});
  return out;
}

const stage = $('#stage');
stage.addEventListener('dragover', (e) => {
  if (!state.viewerTransfer || !e.dataTransfer?.types.includes('Files')) return;
  e.preventDefault();
  $('#drop-hint').hidden = false;
});
stage.addEventListener('dragleave', () => { $('#drop-hint').hidden = true; });
stage.addEventListener('drop', async (e) => {
  e.preventDefault();
  $('#drop-hint').hidden = true;
  if (!state.viewerTransfer) return;
  const files = await filesFromDrop(e.dataTransfer);
  if (files.length && state.viewerTransfer) state.viewerTransfer.send(files);
});

/* Paste copied files: Ctrl+V on the remote screen sends them over -------- */

let lastPaste = { sig: '', at: 0 };
async function pasteFiles() {
  if (!bridge.clipboardFiles || !state.viewerTransfer || !remoteControl || !state.viewerPerms?.files) return;
  const paths = await bridge.clipboardFiles().catch(() => []);
  if (!paths.length) return;
  const sig = paths.join('\n');
  if (sig === lastPaste.sig && Date.now() - lastPaste.at < 5000) return; // key repeat
  lastPaste = { sig, at: Date.now() };
  const items = await bridge.fsExpand(paths).catch(() => []);
  if (!items.length) return;
  state.viewerTransfer.send(items.map((it) => new PathFile(bridge, it)));
  toast(items.length === 1 ? `Kopyalanan dosya gönderiliyor: ${items[0].rel}` : `${items.length} kopyalanan dosya gönderiliyor`, 'info', 4000);
}
$('#remote-video').addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.code === 'KeyV') pasteFiles();
}, true);

/* Remote file manager ------------------------------------------------------ */

const fm = { path: null, parent: null, sep: '/', roots: [] };
const FS_ERRORS = { denied: 'Uzak cihaz dosya erişimine izin vermiyor (dosya izni ve uzaktan kontrol gerekli).', timeout: 'Uzak cihaz yanıt vermedi.', empty: 'Klasör boş.' };

function fsError(err) {
  const code = String(err?.message || err);
  if (FS_ERRORS[code]) return FS_ERRORS[code];
  if (/EACCES|EPERM/.test(code)) return 'Bu klasöre erişim izni yok.';
  if (/ENOENT/.test(code)) return 'Klasör bulunamadı.';
  return `Hata: ${code}`;
}

async function openFileManager() {
  if (!viewer.has('fs')) {
    toast('Uzak cihaz dosya yöneticisini desteklemiyor', 'error');
    return;
  }
  if (!(state.viewerPerms?.files && remoteControl)) {
    toast(FS_ERRORS.denied, 'error', 6000);
    return;
  }
  closeChat();
  $('#fm-panel').hidden = false;
  $('#fm-device').textContent = $('#session-name').textContent;
  try {
    if (!fm.roots.length) {
      fm.roots = (await viewer.fsRequest('roots')).roots || [];
      $('#fm-roots').replaceChildren(new Option('Konum seçin…', ''), ...fm.roots.map((r) => new Option(r.name, r.path)));
    }
    await fmOpen(fm.path || fm.roots[0]?.path || '');
  } catch (err) {
    $('#fm-status').textContent = fsError(err);
  }
}

function fmJoin(dir, name) {
  return dir.endsWith(fm.sep) ? dir + name : dir + fm.sep + name;
}

function fileSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

async function fmDownload(path, name) {
  try {
    const r = await viewer.fsRequest('get', { path });
    toast(r.count === 1 ? `İndiriliyor: ${name}` : `${name}: ${r.count} dosya indiriliyor (${fileSize(r.size)})`, 'info', 4000);
  } catch (err) {
    toast(fsError(err), 'error', 5000);
  }
}

async function fmOpen(path) {
  $('#fm-status').textContent = 'Yükleniyor…';
  try {
    const { list } = await viewer.fsRequest('list', { path });
    fm.path = list.path;
    fm.parent = list.parent;
    fm.sep = list.sep || '/';
    $('#fm-path').textContent = list.path;
    $('#fm-up').disabled = !list.parent;
    $('#fm-roots').value = fm.roots.some((r) => r.path === list.path) ? list.path : '';
    $('#fm-list').replaceChildren(...list.entries.map((e) => {
      const li = document.createElement('li');
      li.className = `fm-item${e.dir ? ' dir' : ''}`;
      li.innerHTML = `<svg><use href="#${e.dir ? 'i-folder' : 'i-file'}"/></svg><span class="fm-name"></span><span class="fm-size"></span>
        <button class="icon-btn" title="Bu cihaza indir"><svg><use href="#i-download"/></svg></button>`;
      li.querySelector('.fm-name').textContent = e.name;
      li.querySelector('.fm-name').title = e.name;
      li.querySelector('.fm-size').textContent = e.dir ? '' : fileSize(e.size);
      const full = fmJoin(list.path, e.name);
      if (e.dir) li.querySelector('.fm-name').addEventListener('click', () => fmOpen(full));
      li.querySelector('button').addEventListener('click', () => fmDownload(full, e.name));
      return li;
    }));
    $('#fm-status').textContent = list.entries.length ? '' : 'Klasör boş.';
  } catch (err) {
    $('#fm-status').textContent = fsError(err);
  }
}

$('#fm-close').addEventListener('click', () => { $('#fm-panel').hidden = true; });
$('#fm-up').addEventListener('click', () => { if (fm.parent) fmOpen(fm.parent); });
$('#fm-refresh').addEventListener('click', () => fmOpen(fm.path || ''));
$('#fm-roots').addEventListener('change', (e) => { if (e.target.value) fmOpen(e.target.value); });
$('#fm-upload-files').addEventListener('click', () => pickFiles('fm'));
$('#fm-upload-folder').addEventListener('click', () => pickFiles('fm', true));

/* Drawing on the remote screen ---------------------------------------------- */

function setDrawMode(on) {
  const enabled = Boolean(on && drawing);
  drawing?.setEnabled(enabled);
  $('#draw-btn').classList.toggle('active', enabled);
  $('#draw-palette').hidden = !enabled;
  if (enabled) capture?.releaseAll();
}

$('#draw-colors').replaceChildren(...DRAW_COLORS.map((color, i) => {
  const b = document.createElement('button');
  b.type = 'button';
  b.style.background = color;
  b.title = 'Renk';
  b.classList.toggle('active', i === 0);
  b.addEventListener('click', () => {
    drawing?.setColor(color);
    for (const x of $('#draw-colors').children) x.classList.toggle('active', x === b);
  });
  return b;
}));
$('#draw-btn').addEventListener('click', () => {
  if (state.viewerPerms && state.viewerPerms.draw === false) {
    toast('Uzak cihaz ekrana çizime izin vermiyor', 'error');
    return;
  }
  setDrawMode(!drawing?.enabled);
});
$('#draw-clear').addEventListener('click', () => drawing?.clear());
$('#draw-done').addEventListener('click', () => setDrawMode(false));

/* Session recording (per tab) --------------------------------------------------- */

/** Record button and timer for the tab on screen. */
function renderRecordUi() {
  clearInterval(recordTimer);
  const rec = activeTab?.recorder;
  const on = Boolean(rec?.active);
  $('#record-btn').classList.toggle('on', on);
  $('#record-btn').title = on ? 'Kaydı durdur' : 'Oturumu kaydet';
  $('#record-time').hidden = !on;
  if (!on) return;
  const tick = () => {
    const sec = Math.floor((Date.now() - rec.startedAt) / 1000);
    $('#record-time').textContent = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
  };
  tick();
  recordTimer = setInterval(tick, 1000);
}

async function startRecording(tab = activeTab) {
  if (!tab?.stream || !window.MediaRecorder) {
    toast('Bu cihaz kayıt yapamıyor', 'error');
    return;
  }
  try {
    await tab.recorder.start(tab.stream, [tab.audio, tab.voice, tab.viewer.mic ? new MediaStream([tab.viewer.mic]) : null]);
  } catch (err) {
    console.warn('[xenon] recording failed', err);
    toast('Kayıt başlatılamadı', 'error');
    return;
  }
  tab.viewer.setRecording(true);
  renderRecordUi();
  toast('Kayıt başladı. Karşı tarafa kaydedildiği bildirildi.', 'info', 4000);
}

async function stopRecording(tab = activeTab, notify = true) {
  if (!tab) return;
  if (notify) tab.viewer.setRecording(false);
  const done = tab.recorder.stop();
  renderRecordUi();
  const path = await done;
  if (path) {
    const action = bridge.revealFile ? { label: 'Klasörü aç', fn: () => bridge.revealFile(path) } : null;
    toast('Kayıt kaydedildi (İndirilenler › Xenon Remote)', 'success', 8000, action);
  } else {
    toast('Kayıt kaydedilemedi', 'error');
  }
}

$('#record-btn').addEventListener('click', () => (activeTab?.recorder.active ? stopRecording() : startRecording()));

/* Voice chat (viewer side) ------------------------------------------------------- */

$('#mic-btn').addEventListener('click', async () => {
  try {
    renderMic($('#mic-btn'), await viewer.setMicrophone(!viewer.mic));
  } catch (err) {
    console.warn('[xenon] microphone', err);
    toast('Mikrofon açılamadı. Mikrofon bağlı mı ve izin verildi mi kontrol edin.', 'error', 6000);
  }
});

/* Remote administration: command line, system information, tasks, power ---- */

const ADMIN_ERRORS = {
  denied: 'Uzak cihaz buna izin vermiyor (uzaktan kontrol ve ilgili izin gerekli).',
  timeout: 'Uzak cihaz yanıt vermedi.',
  protected: 'Bu program sonlandırılamaz.',
  unsupported: 'Uzak bilgisayar bu işlemi desteklemiyor.',
};

function adminError(err) {
  const code = String(err?.message || err);
  return ADMIN_ERRORS[code] || `Hata: ${code}`;
}

$('#admin-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('#admin-menu').hidden = !$('#admin-menu').hidden;
});
document.addEventListener('click', () => { $('#admin-menu').hidden = true; });
for (const item of document.querySelectorAll('#admin-menu [data-admin]')) {
  item.addEventListener('click', () => {
    $('#admin-menu').hidden = true;
    const action = item.dataset.admin;
    if (!remoteControl) {
      toast('Uzak cihaz kontrole izin vermiyor', 'error');
      return;
    }
    if (action === 'terminal') openTerminal();
    else if (action === 'system') openSystemPanel('info');
    else if (action === 'procs') openSystemPanel('procs');
    else if (action === 'schedule') $('#power-dialog').showModal();
    else if (action === 'cancel-plan') cancelPowerPlan();
    else if (action === 'block-input') activeTab?.viewer.setInputBlock(!activeTab.inputBlocked);
    else if (action === 'resolution') openResolution();
    else if (action === 'switch') switchSides();
    else runPower(action);
  });
}

function closeSidePanels(except) {
  for (const id of ['#chat-panel', '#fm-panel', '#term-panel', '#sys-panel']) if (id !== except) $(id).hidden = true;
}

// Command line ------------------------------------------------------------

const TERM_MAX_CHARS = 200000;
const termHistory = [];
let termHistoryPos = 0;

function renderTerminal() {
  const tab = activeTab;
  const out = $('#term-output');
  out.textContent = tab?.terminal?.output || '';
  out.scrollTop = out.scrollHeight;
  $('#term-device').textContent = tab ? tabLabel(tab) : '';
  $('#term-state').textContent = tab?.terminal?.term ? '' : 'Kapalı';
}

function appendTerminal(tab, text) {
  if (!tab.terminal) return;
  tab.terminal.output = (tab.terminal.output + text).slice(-TERM_MAX_CHARS);
  if (tab === activeTab && !$('#term-panel').hidden) {
    const out = $('#term-output');
    const atEnd = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
    out.textContent = tab.terminal.output;
    if (atEnd) out.scrollTop = out.scrollHeight;
  }
}

async function openTerminal(restart = false) {
  const tab = activeTab;
  if (!tab) return;
  closeSidePanels('#term-panel');
  $('#term-panel').hidden = false;
  if (tab.terminal?.term && !restart) {
    renderTerminal();
    $('#term-input').focus();
    return;
  }
  if (tab.terminal?.term) tab.viewer.termClose(tab.terminal.term);
  tab.terminal = { term: null, output: tab.terminal?.output || '', os: tab.os };
  renderTerminal();
  try {
    const { term } = await tab.viewer.request('term', 'open');
    tab.terminal.term = term;
    renderTerminal();
    $('#term-input').focus();
  } catch (err) {
    tab.terminal.output += `\n${translate(adminError(err))}\n`;
    renderTerminal();
  }
}

function onTerminalOutput(tab, term, data) {
  if (tab.terminal?.term !== term) return;
  appendTerminal(tab, data);
}

function onTerminalExit(tab, term) {
  if (tab.terminal?.term !== term) return;
  tab.terminal.term = null;
  appendTerminal(tab, `\n[${translate('Komut satırı kapandı')}]\n`);
  if (tab === activeTab) renderTerminal();
}

$('#term-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const tab = activeTab;
  const input = $('#term-input');
  const line = input.value;
  if (!tab?.terminal?.term) {
    toast('Komut satırı kapalı: "Yeniden başlat" ile açın', 'error');
    return;
  }
  // Shells without a terminal show no prompt: echo the command (Windows' cmd shows its own).
  if (tab.os !== 'win32') appendTerminal(tab, `$ ${line}\n`);
  tab.viewer.termInput(tab.terminal.term, `${line}${tab.os === 'win32' ? '\r\n' : '\n'}`);
  if (line.trim()) termHistory.push(line);
  if (termHistory.length > 100) termHistory.shift();
  termHistoryPos = termHistory.length;
  input.value = '';
});
$('#term-input').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowUp' && termHistoryPos > 0) {
    termHistoryPos -= 1;
    e.target.value = termHistory[termHistoryPos];
    e.preventDefault();
  } else if (e.key === 'ArrowDown') {
    termHistoryPos = Math.min(termHistory.length, termHistoryPos + 1);
    e.target.value = termHistory[termHistoryPos] || '';
    e.preventDefault();
  }
});
$('#term-restart').addEventListener('click', () => openTerminal(true));
$('#term-clear').addEventListener('click', () => {
  if (activeTab?.terminal) activeTab.terminal.output = '';
  renderTerminal();
});
$('#term-close').addEventListener('click', () => {
  const tab = activeTab;
  if (tab?.terminal?.term) tab.viewer.termClose(tab.terminal.term);
  if (tab) tab.terminal = null;
  $('#term-panel').hidden = true;
});

// System information and task manager -------------------------------------

function sizeText(n) {
  return fileSize(Number(n) || 0);
}

function durationText(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d ? `${d} gün ${h} sa` : h ? `${h} sa ${m} dk` : `${m} dk`;
}

function showSysTab(name) {
  for (const b of document.querySelectorAll('#sys-tabs [data-sys]')) b.classList.toggle('active', b.dataset.sys === name);
  $('#sys-info').hidden = name !== 'info';
  $('#sys-procs').hidden = name !== 'procs';
}

async function openSystemPanel(which) {
  const tab = activeTab;
  if (!tab) return;
  closeSidePanels('#sys-panel');
  $('#sys-panel').hidden = false;
  $('#sys-device').textContent = tabLabel(tab);
  showSysTab(which);
  if (which === 'info') await loadSystemInfo();
  else await loadProcesses();
}

async function loadSystemInfo() {
  const box = $('#sys-info');
  box.replaceChildren(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'Yükleniyor…' }));
  let info;
  try {
    info = (await viewer.request('sys', 'info', {}, 60000)).info;
  } catch (err) {
    box.replaceChildren(Object.assign(document.createElement('p'), { className: 'muted', textContent: adminError(err) }));
    return;
  }
  const used = info.memory.total - info.memory.free;
  const rows = [
    ['Bilgisayar adı', info.hostname],
    ['Kullanıcı', info.user],
    ['İşletim sistemi', `${info.os} · ${info.arch}`],
    ['Açık kalma süresi', durationText(info.uptime)],
    ['İşlemci', `${info.cpu.model} (${info.cpu.cores} çekirdek)`],
    ['Bellek', `${sizeText(used)} / ${sizeText(info.memory.total)} kullanımda`],
    ['Ekran kartı', info.gpu || '—'],
    ['Ekranlar', (info.displays || []).map((d) => `${d.width}×${d.height}`).join(', ') || '—'],
    ['Ağ', (info.network || []).map((n) => `${n.name}: ${n.address}`).join(', ') || '—'],
    ['Xenon Remote', info.appVersion ? `v${info.appVersion}` : '—'],
  ];
  const dl = document.createElement('dl');
  dl.className = 'sys-list';
  for (const [k, v] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.className = 'raw-value';
    dd.textContent = v;
    dl.append(dt, dd);
  }
  const disks = document.createElement('div');
  disks.className = 'sys-disks';
  disks.append(Object.assign(document.createElement('h4'), { textContent: 'Diskler' }));
  for (const d of info.disks || []) {
    const row = document.createElement('div');
    row.className = 'sys-disk';
    const pct = d.size ? Math.round(((d.size - d.free) / d.size) * 100) : 0;
    row.innerHTML = '<span class="raw-value"></span><progress max="100"></progress><span class="muted"></span>';
    row.querySelector('span').textContent = d.name;
    row.querySelector('progress').value = pct;
    row.querySelector('.muted').textContent = `${sizeText(d.free)} boş / ${sizeText(d.size)}`;
    disks.append(row);
  }
  const progs = document.createElement('div');
  progs.className = 'sys-programs';
  progs.innerHTML = '<h4></h4><input class="input input-sm" type="search" placeholder="Program ara"><ul class="raw-value"></ul>';
  progs.querySelector('h4').textContent = `Kurulu programlar (${(info.programs || []).length})`;
  const list = progs.querySelector('ul');
  const renderProgs = (q = '') => {
    const needle = q.toLocaleLowerCase('tr');
    list.replaceChildren(...(info.programs || []).filter((p) => !needle || p.name.toLocaleLowerCase('tr').includes(needle)).slice(0, 400).map((p) => {
      const li = document.createElement('li');
      li.textContent = p.version ? `${p.name} — ${p.version}` : p.name;
      return li;
    }));
  };
  progs.querySelector('input').addEventListener('input', (e) => renderProgs(e.target.value));
  renderProgs();
  box.replaceChildren(dl, disks, progs);
}

let procCache = [];

function renderProcesses() {
  const q = $('#proc-search').value.trim().toLocaleLowerCase('tr');
  const rows = procCache.filter((p) => !q || `${p.name} ${p.title} ${p.pid}`.toLocaleLowerCase('tr').includes(q))
    .sort((a, b) => b.memory - a.memory).slice(0, 500);
  $('#proc-rows').replaceChildren(...rows.map((p) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="raw-value"></td><td></td><td></td><td></td><td><button class="btn btn-ghost btn-sm">Sonlandır</button></td>';
    tr.children[0].textContent = p.title ? `${p.name} — ${p.title}` : p.name;
    tr.children[0].title = tr.children[0].textContent;
    tr.children[1].textContent = String(p.pid);
    tr.children[2].textContent = p.cpu !== undefined ? `%${p.cpu}` : `${p.cpuTime || 0} sn`;
    tr.children[3].textContent = sizeText(p.memory);
    tr.querySelector('button').addEventListener('click', () => killRemoteProcess(p));
    return tr;
  }));
  $('#proc-count').textContent = `${procCache.length} program`;
}

async function loadProcesses() {
  $('#proc-count').textContent = 'Yükleniyor…';
  try {
    procCache = (await viewer.request('sys', 'procs', {}, 40000)).procs || [];
    renderProcesses();
  } catch (err) {
    $('#proc-count').textContent = adminError(err);
  }
}

async function killRemoteProcess(p) {
  if (!window.confirm(translate(`"${p.name}" (${p.pid}) sonlandırılsın mı? Kaydedilmemiş işler kaybolabilir.`))) return;
  try {
    await viewer.request('sys', 'kill', { pid: p.pid, label: p.name });
    toast(`${p.name} sonlandırıldı`, 'success', 2500);
    procCache = procCache.filter((x) => x.pid !== p.pid);
    renderProcesses();
  } catch (err) {
    toast(adminError(err), 'error');
  }
}

for (const b of document.querySelectorAll('#sys-tabs [data-sys]')) {
  b.addEventListener('click', () => openSystemPanel(b.dataset.sys));
}
$('#proc-search').addEventListener('input', renderProcesses);
$('#proc-refresh').addEventListener('click', loadProcesses);
$('#sys-close').addEventListener('click', () => { $('#sys-panel').hidden = true; });

// Power: lock, restart (and reconnect), shut down ----------------------------

const POWER_TEXT = {
  lock: 'Uzak bilgisayar kilitlensin mi?',
  sleep: 'Uzak bilgisayar uyku moduna alınsın mı? Uyandırmak için Wake-on-LAN veya karşıdaki kişi gerekir.',
  hibernate: 'Uzak bilgisayar hazırda bekletilsin mi? Uyandırmak için Wake-on-LAN veya karşıdaki kişi gerekir.',
  restart: 'Uzak bilgisayar yeniden başlatılsın mı? Açık programlardaki kaydedilmemiş işler kaybolabilir.',
  shutdown: 'Uzak bilgisayar kapatılsın mı? Uzaktan yeniden açmak için Wake-on-LAN gerekir.',
};

async function runPower(action) {
  const tab = activeTab;
  if (!tab || !window.confirm(translate(POWER_TEXT[action]))) return;
  try {
    await tab.viewer.request('power', action);
  } catch (err) {
    toast(adminError(err), 'error', 6000);
    return;
  }
  if (action === 'lock') {
    toast('Uzak bilgisayar kilitlendi', 'success');
  } else if (action === 'sleep' || action === 'hibernate') {
    toast(action === 'sleep' ? 'Uzak bilgisayar uyku moduna alınıyor' : 'Uzak bilgisayar hazırda bekletiliyor', 'info', 6000);
  } else if (action === 'restart') {
    reconnects.set(tab.id, { credential: tab.credential, name: tab.name, until: Date.now() + 5 * 60 * 1000, timer: null });
    toast('Uzak bilgisayar yeniden başlatılıyor. Uygulama yeniden açılınca otomatik bağlanılacak (en çok 5 dakika).', 'info', 10000,
      { label: 'Vazgeç', fn: () => cancelReconnect(tab.id) });
  } else {
    toast('Uzak bilgisayar kapatılıyor', 'info', 6000);
  }
}

/* Swap sides ------------------------------------------------------------- */

/** The computer we control connects back to us with a one-time key and controls us. */
function switchSides() {
  const tab = activeTab;
  if (!tab) return;
  if (!window.confirm(translate(`${tabLabel(tab)} bundan sonra sizin ekranınızı görüp kontrol edecek. Bu bağlantı kapanır. Devam edilsin mi?`))) return;
  const secret = crypto.getRandomValues(new Uint8Array(32));
  clearTimeout(state.switchGrant?.timer);
  state.switchGrant = { secret, until: Date.now() + 2 * 60 * 1000 };
  state.switchGrant.timer = setTimeout(() => { state.switchGrant = null; listenOnInternet(); }, 2 * 60 * 1000);
  listenOnInternet();
  // Give the internet listener a moment to take the new key before the other side calls.
  setTimeout(() => tab.viewer.switchSides(state.config.id, secretToHex(secret)), 600);
}

/* Remote resolution ------------------------------------------------------ */

async function openResolution() {
  const tab = activeTab;
  if (!tab) return;
  let display;
  try {
    ({ display } = await tab.viewer.request('res', 'list'));
  } catch (err) {
    toast(adminError(err), 'error', 6000);
    return;
  }
  const select = $('#res-select');
  select.replaceChildren(...display.modes.map((m) => new Option(`${m.replace('x', ' × ')}${m === display.current ? ' (şu anki)' : ''}`, m)));
  select.value = display.current;
  $('#res-dialog').showModal();
}

$('#res-cancel').addEventListener('click', () => $('#res-dialog').close());
$('#res-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#res-dialog').close();
  try {
    await activeTab?.viewer.request('res', 'set', { mode: $('#res-select').value });
    toast(`Uzak ekran: ${$('#res-select').value.replace('x', ' × ')}`, 'success', 3000);
  } catch (err) {
    toast(adminError(err), 'error', 6000);
  }
});
$('#res-restore').addEventListener('click', async () => {
  $('#res-dialog').close();
  try {
    await activeTab?.viewer.request('res', 'restore');
    toast('Uzak ekranın çözünürlüğü eski haline döndü', 'success', 3000);
  } catch (err) {
    toast(adminError(err), 'error', 6000);
  }
});

/** What a scheduled action does, as the end of a sentence ("… sonra yeniden başlatılacak"). */
const POWER_PLAN_TEXT = { restart: 'yeniden başlatılacak', shutdown: 'kapatılacak', sleep: 'uyku moduna alınacak', hibernate: 'hazırda bekletilecek' };

/** "0:42", "12:05" or "1:04:09" */
function clockText(sec) {
  const two = (n) => String(n).padStart(2, '0');
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h ? `${h}:${two(m)}:${two(sec % 60)}` : `${m}:${two(sec % 60)}`;
}

$('#power-cancel').addEventListener('click', () => $('#power-dialog').close());
$('#power-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const tab = activeTab;
  $('#power-dialog').close();
  if (!tab) return;
  const action = $('#power-action').value;
  const delay = Number($('#power-delay').value);
  try {
    await tab.viewer.request('power', 'schedule', { action, delay });
  } catch (err) {
    toast(adminError(err), 'error', 6000);
  }
});

async function cancelPowerPlan() {
  const tab = activeTab;
  if (!tab) return;
  try {
    await tab.viewer.request('power', 'cancel');
  } catch (err) {
    toast(adminError(err), 'error', 6000);
  }
}

/** Viewer side: the remote computer has (or no longer has) a scheduled power action. */
function onRemotePowerPlan(tab, plan) {
  const had = tab.powerPlan;
  tab.powerPlan = plan.action ? { action: plan.action, at: Date.now() + plan.in * 1000 } : null;
  if (tab === activeTab) renderFeatures();
  if (plan.action) {
    toast(`${tabLabel(tab)} ${clockText(plan.in)} sonra ${POWER_PLAN_TEXT[plan.action]}`, 'info', 6000);
  } else if (had) {
    toast(`${tabLabel(tab)}: zamanlanmış işlem iptal edildi`, 'info', 5000);
  }
}

/** Host side: the countdown bar for a scheduled power action, which the person here can cancel. */
let powerPlanTimer = null;
let powerPlanWarned = false;
function renderPowerPlan(plan) {
  clearInterval(powerPlanTimer);
  powerPlanTimer = null;
  const bar = $('#power-plan-bar');
  bar.hidden = !plan;
  if (!plan) return;
  powerPlanWarned = false;
  const tick = () => {
    const left = Math.max(0, Math.round((plan.at - Date.now()) / 1000));
    const by = plan.name ? ` (${plan.name})` : '';
    $('#power-plan-text').textContent = `Bu bilgisayar ${clockText(left)} sonra ${POWER_PLAN_TEXT[plan.action]}${by}`;
    if (left <= 60 && !powerPlanWarned) {
      powerPlanWarned = true;
      bridge.attention(translate('Zamanlanmış işlem'), translate(`Bu bilgisayar ${clockText(left)} sonra ${POWER_PLAN_TEXT[plan.action]}`));
    }
  };
  tick();
  powerPlanTimer = setInterval(tick, 1000);
}

$('#power-plan-cancel').addEventListener('click', () => {
  if (host.cancelPowerPlan(translate('bilgisayardaki kişi'), { local: true })) toast('Zamanlanmış işlem iptal edildi', 'success', 3000);
});

function cancelReconnect(id) {
  const r = reconnects.get(id);
  if (!r) return;
  clearTimeout(r.timer);
  reconnects.delete(id);
}

/** Tries again every 15 seconds while the restarted computer comes back. */
function scheduleReconnect(id) {
  const r = reconnects.get(id);
  if (!r) return;
  clearTimeout(r.timer);
  if (Date.now() > r.until) {
    reconnects.delete(id);
    if (r.drop) toast(`${r.name || formatId(id)} cihazına yeniden bağlanılamadı`, 'error', 8000);
    else toast(`${r.name || formatId(id)} yeniden başladıktan sonra bağlanılamadı. Uygulama, bilgisayarda oturum açılınca başlar.`, 'error', 10000);
    return;
  }
  r.timer = setTimeout(() => {
    if (!reconnects.has(id)) return;
    if (pendingTab || tabs.some((t) => t.id === id)) {
      scheduleReconnect(id);
      return;
    }
    startConnection(id, r.credential || '');
  }, r.every || 15000);
}

// Trusted devices (host side settings, viewer side keys) ----------------------

/** A host gave this device a permanent key: it is kept in the OS vault. */
async function onTrusted(tab, key) {
  if (!state.vault || !bridge.setSavedPassword) {
    toast('Bu cihaz kalıcı erişim anahtarını saklayamıyor', 'error', 6000);
    return;
  }
  try {
    await bridge.setSavedPassword(tab.id, `key:${key}`);
    tab.credential = `key:${key}`;
    toast(`${tabLabel(tab)} size kalıcı erişim verdi: artık şifre olmadan bağlanabilirsiniz`, 'success', 8000);
  } catch {
    toast('Kalıcı erişim anahtarı kaydedilemedi', 'error');
  }
}

/** Accepted secrets of trusted devices, labelled with their device ID. */
function trustedSecrets() {
  return (state.trusted || []).map((t) => ({ secret: hexToSecret(t.secret), label: `trusted:${t.deviceId}` })).filter((t) => t.secret);
}

async function saveTrusted(list) {
  state.trusted = await bridge.setTrusted(list);
  renderAccess();
  listenOnInternet();
}

async function trustDevice({ deviceId, name, secret }) {
  if (!bridge.setTrusted || !state.vault) {
    toast('Bu cihazda işletim sisteminin şifreli deposu yok; kalıcı erişim verilemez', 'error', 6000);
    return false;
  }
  const list = (state.trusted || []).filter((t) => t.deviceId !== deviceId);
  list.push({ deviceId, name: name || '', secret, addedAt: Date.now() });
  await saveTrusted(list);
  toast(`${name || formatId(deviceId)} artık şifre sormadan bağlanabilir`, 'success', 5000);
  return true;
}

/** The permissions a trusted device may have, with the labels of the host's İzinler menu. */
const TRUSTED_PERM_LABELS = [
  ['control', 'Uzaktan kontrol (fare ve klavye)'],
  ['clipboard', 'Pano paylaşımı'],
  ['files', 'Dosya aktarımı ve dosya yöneticisi'],
  ['audio', 'Ses'],
  ['draw', 'Ekrana çizim'],
  ['terminal', 'Komut satırı'],
  ['system', 'Sistem bilgisi ve görev yöneticisi'],
  ['power', 'Kilitle / yeniden başlat / kapat'],
];
let openTrustedPerms = null; // device whose permission list is open

function trustedSummary(perms) {
  if (!perms) return 'Varsayılan izinler';
  if (perms.control === false) return 'Yalnızca izleme';
  return 'Özel izinler';
}

/** The permission checkboxes of one trusted device ("defaults" or its own choice). */
function fillTrustedPerms(box, t) {
  box.innerHTML = '<label class="check"><input type="checkbox" data-default> Ayarlardaki varsayılan izinleri kullan</label>';
  const own = t.perms || null;
  const base = { control: true, ...DEFAULT_PERMISSIONS, ...(state.config.permissions || {}) };
  for (const [key, label] of TRUSTED_PERM_LABELS) {
    const row = document.createElement('label');
    row.className = 'check';
    row.innerHTML = `<input type="checkbox" data-trusted-perm="${key}"> `;
    row.append(label);
    const input = row.querySelector('input');
    input.checked = own ? own[key] !== false : base[key] !== false;
    input.disabled = !own;
    box.append(row);
  }
  const useDefault = box.querySelector('[data-default]');
  useDefault.checked = !own;
  const save = async () => {
    const perms = useDefault.checked ? null
      : Object.fromEntries([...box.querySelectorAll('[data-trusted-perm]')].map((i) => [i.dataset.trustedPerm, i.checked]));
    const list = (state.trusted || []).map((x) => (x.deviceId === t.deviceId ? { ...x, perms } : x));
    if (!perms) list.forEach((x) => { if (x.deviceId === t.deviceId) delete x.perms; });
    await saveTrusted(list);
    toast('İzinler kaydedildi; bu cihazın bir sonraki bağlantısında geçerli', 'success', 3000);
  };
  box.addEventListener('change', save);
}

function renderAccess() {
  const card = $('#access-card');
  if (!bridge.setTrusted || !state.canHost) {
    card.hidden = true;
    return;
  }
  card.hidden = false;
  const trusted = state.trusted || [];
  $('#access-trusted-only').checked = state.config.accessMode === 'trusted';
  $('#trusted-empty').hidden = trusted.length > 0;
  $('#trusted-list').replaceChildren(...trusted.map((t) => {
    const li = document.createElement('li');
    li.className = 'access-item trusted-item';
    li.innerHTML = '<span class="recent-meta"><strong></strong><span></span></span><span class="trusted-summary"></span>'
      + '<button type="button" class="btn btn-ghost btn-sm" data-act="perms">İzinler</button>'
      + '<button type="button" class="btn btn-ghost btn-sm" data-act="remove">Kaldır</button><div class="trusted-perms" hidden></div>';
    li.querySelector('strong').textContent = t.name || formatId(t.deviceId);
    li.querySelector('.recent-meta span').textContent = `${formatId(t.deviceId)} · ${new Date(t.addedAt).toLocaleDateString(locale())}`;
    li.querySelector('.trusted-summary').textContent = trustedSummary(t.perms);
    const box = li.querySelector('.trusted-perms');
    if (openTrustedPerms === t.deviceId) {
      box.hidden = false;
      fillTrustedPerms(box, t);
    }
    li.querySelector('[data-act="perms"]').addEventListener('click', () => {
      box.hidden = !box.hidden;
      openTrustedPerms = box.hidden ? null : t.deviceId;
      if (!box.hidden) fillTrustedPerms(box, t);
    });
    li.querySelector('[data-act="remove"]').addEventListener('click', async () => {
      await saveTrusted((state.trusted || []).filter((x) => x.deviceId !== t.deviceId));
      toast('Kalıcı erişim kaldırıldı', 'success', 2000);
    });
    return li;
  }));
  const ips = state.config.allowedIps || [];
  $('#allowed-ip-list').replaceChildren(...ips.map((ip) => {
    const li = document.createElement('li');
    li.className = 'access-item';
    li.innerHTML = '<span class="recent-meta"><strong></strong></span><button type="button" class="btn btn-ghost btn-sm">Kaldır</button>';
    li.querySelector('strong').textContent = ip;
    li.querySelector('button').addEventListener('click', async () => {
      state.config = await bridge.setConfig({ allowedIps: (state.config.allowedIps || []).filter((x) => x !== ip) });
      renderAccess();
    });
    return li;
  }));
  const blocked = state.config.blockedIds || [];
  $('#blocked-empty').hidden = blocked.length > 0;
  $('#blocked-list').replaceChildren(...blocked.map((id) => {
    const li = document.createElement('li');
    li.className = 'access-item';
    li.innerHTML = '<span class="recent-meta"><strong></strong></span><button type="button" class="btn btn-ghost btn-sm">Kaldır</button>';
    li.querySelector('strong').textContent = formatId(id);
    li.querySelector('button').addEventListener('click', async () => {
      state.config = await bridge.setConfig({ blockedIds: (state.config.blockedIds || []).filter((x) => x !== id) });
      renderAccess();
    });
    return li;
  }));
}

$('#access-trusted-only').addEventListener('change', async (e) => {
  if (e.target.checked && !(state.trusted || []).length) {
    toast('Önce bir oturum sırasında İzinler › "Kalıcı erişim ver" ile en az bir cihaza güvenin', 'error', 7000);
    e.target.checked = false;
    return;
  }
  state.config = await bridge.setConfig({ accessMode: e.target.checked ? 'trusted' : 'all' });
  toast(e.target.checked ? 'Yalnızca güvenilen cihazlar bağlanabilir' : 'Şifreyle veya onayla herkes bağlanabilir', 'success', 3000);
});
$('#allowed-ip-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const rule = parseIpRule($('#allowed-ip').value);
  if (!rule) {
    toast('Geçerli bir IP adresi ya da aralık girin (ör. 192.168.1.0/24)', 'error');
    return;
  }
  const list = [...new Set([...(state.config.allowedIps || []), rule])];
  if ((state.config.allowedIps || []).length === 0 && !window.confirm(translate('Bundan sonra yalnızca listedeki adreslerden bağlanılabilecek. Devam edilsin mi?'))) return;
  state.config = await bridge.setConfig({ allowedIps: list });
  $('#allowed-ip').value = '';
  renderAccess();
  toast(`${rule} izin listesine eklendi`, 'success', 2500);
});

$('#blocked-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = normalizeId($('#blocked-id').value);
  if (!/^\d{9}$/.test(id)) {
    toast('Lütfen 9 haneli bir Xenon ID girin', 'error');
    return;
  }
  const list = [...new Set([...(state.config.blockedIds || []), id])];
  state.config = await bridge.setConfig({ blockedIds: list });
  $('#blocked-id').value = '';
  renderAccess();
  toast(`${formatId(id)} engellendi`, 'success', 2000);
});

/** Host banner: give a connected device permanent access. */
function renderTrustButtons(list) {
  const box = $('#host-trust');
  box.hidden = !bridge.setTrusted || !state.vault || !list.length;
  $('#host-trust-list').replaceChildren(...list.map((s) => {
    const row = document.createElement('div');
    row.className = 'trust-row';
    row.innerHTML = '<span class="raw-value"></span><button type="button" class="btn btn-ghost btn-sm"></button>';
    row.querySelector('span').textContent = s.name || formatId(s.deviceId || '');
    const b = row.querySelector('button');
    b.textContent = s.trusted ? 'Güveniliyor ✓' : 'Kalıcı erişim ver';
    b.disabled = Boolean(s.trusted) || !s.deviceId;
    b.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!window.confirm(translate(`${s.name || 'Bu cihaz'} bundan sonra şifre sormadan bu bilgisayara bağlanabilsin mi? Ayarlar › Erişim kontrolü'nden geri alınabilir.`))) return;
      if (!(await host.trustSession(s.peerId))) toast('Kalıcı erişim verilemedi', 'error');
    });
    return row;
  }));
}

// Invitation links -----------------------------------------------------------

async function copyInvite(withPassword) {
  const links = inviteLinks(state.config.id, withPassword ? state.password : '');
  await copy(links.web, 'Davet bağlantısı');
  $('#invite-menu').hidden = true;
}

$('#invite-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('#invite-menu').hidden = !$('#invite-menu').hidden;
});
document.addEventListener('click', () => { $('#invite-menu').hidden = true; });
$('#invite-copy').addEventListener('click', () => copyInvite(false));
function renderInviteQr() {
  const links = inviteLinks(state.config.id, $('#qr-with-password').checked ? state.password : '');
  $('#qr-box').innerHTML = qrSvg(links.web);
}
$('#invite-qr').addEventListener('click', () => {
  $('#invite-menu').hidden = true;
  $('#qr-with-password').checked = false;
  renderInviteQr();
  $('#qr-dialog').showModal();
});
$('#qr-with-password').addEventListener('change', renderInviteQr);
$('#qr-close').addEventListener('click', () => $('#qr-dialog').close());
$('#invite-copy-pw').addEventListener('click', () => copyInvite(true));

/** Fills in the connection form from an invitation link. */
function handleInvite(link) {
  const invite = parseInvite(link);
  if (!invite) return;
  if (!$('#session').hidden) showHomeDuringSessions();
  showView('home');
  $('#partner-id').value = formatId(invite.id);
  const field = $('#partner-password');
  delete field.dataset.saved;
  delete field.dataset.key;
  field.value = invite.password;
  const action = bridge.isBrowser && !bridge.isAndroid
    ? { label: 'Uygulamada aç', fn: () => { location.href = inviteLinks(invite.id, invite.password).app; } }
    : null;
  toast(`Davet: ${formatId(invite.id)}. Bağlanmak için "Bağlan"a basın.`, 'info', 10000, action);
  $('#connect-btn').focus();
}

// Video codec -------------------------------------------------------------------

function renderCodecSetting() {
  const select = $('#codec-select');
  const supported = new Set((window.RTCRtpReceiver?.getCapabilities?.('video')?.codecs || []).map((c) => c.mimeType.split('/')[1].toUpperCase()));
  for (const option of select.options) {
    if (option.value !== 'auto') option.disabled = !supported.has(option.value.toUpperCase());
  }
  select.value = state.config.codec || 'auto';
}

$('#codec-select').addEventListener('change', async (e) => {
  state.config = await bridge.setConfig({ codec: e.target.value });
  toast('Kodek tercihi kaydedildi; yeni bağlantılarda geçerli', 'success', 2500);
});

/* Connection details ------------------------------------------------------------- */

const ROUTE_TEXT = { lan: 'Yerel ağ (doğrudan)', direct: 'İnternet, doğrudan (eşten eşe)', relay: 'Aktarma sunucusu (TURN)' };
const QUALITY_TEXT = { good: 'İyi', fair: 'Orta', poor: 'Zayıf' };

function renderNetPanel() {
  const s = state.lastStats;
  if (!s) {
    $('#net-details').replaceChildren();
    $('#net-advice').textContent = 'Ölçülüyor…';
    return;
  }
  const rows = [
    ['Kalite', QUALITY_TEXT[s.quality] || '—'],
    ['Bağlantı', ROUTE_TEXT[s.route] || '—'],
    ['Gecikme', s.rtt !== null ? `${s.rtt} ms` : '—'],
    ['Paket kaybı', `%${s.lossPct}`],
    ['Titreşim', s.jitter !== null ? `${s.jitter} ms` : '—'],
    ['Görüntü', `${s.width}×${s.height} · ${s.fps} fps`],
    ['Bant genişliği', `${(s.kbps / 1000).toFixed(2)} Mbps`],
    ['Kodek', s.codec || '—'],
    ['Donma', String(s.freezes)],
  ];
  $('#net-details').replaceChildren(...rows.flatMap(([k, v]) => {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    return [dt, dd];
  }));
  let advice = 'Bağlantı iyi.';
  if (s.quality === 'poor') advice = 'Bağlantı zayıf: görüntü kalitesini "Düşük bant" yapın ya da daha iyi bir ağ kullanın.';
  else if (s.quality === 'fair') advice = 'Bağlantı orta: takılma olursa kaliteyi "Dengeli" ya da "Düşük bant" yapın.';
  if (s.route === 'relay') advice += ' Görüntü aktarma sunucusu üzerinden geliyor; doğrudan bağlantı kurulamadı.';
  $('#net-advice').textContent = advice;
}

$('#stats-btn').addEventListener('click', () => {
  $('#net-panel').hidden = !$('#net-panel').hidden;
  if (!$('#net-panel').hidden) renderNetPanel();
});

$('#keys-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('#keys-menu').hidden = !$('#keys-menu').hidden;
});
document.addEventListener('click', () => { $('#keys-menu').hidden = true; });
/** Ctrl+Alt+Del only where the remote computer has the lock screen service. */
function renderSecureUi() {
  const s = activeTab?.secure;
  $('#keys-menu [data-sas]').hidden = !s?.available;
  // What the person at the other computer has to do for the lock screen to be usable from here.
  let help = 'Ekran koruyucu, fareyi oynattığınızda kendiliğinden kapanır. Kilitliyse: uzak bilgisayarda Ayarlar › "Kilit ekranında erişim" açılırsa kilit ekranı buradan kullanılabilir; açık değilse bilgisayarın başındaki birinin kilidi açması gerekir.';
  if (s?.state === 'needs-admin') {
    help = 'Kilit ekranı hizmeti orada kurulu, ama Xenon Remote yönetici olarak çalışmıyor. O bilgisayarda bir kez Ayarlar › "Yönetici olarak çalıştır"ı açın; sonra kilit ekranı buradan kullanılabilir.';
  } else if (s?.state === 'not-installed') {
    help = 'Kilit ekranını buradan kullanmak için o bilgisayarda bir kez Ayarlar › "Kilit ekranında erişim" › Aç deyin (Windows yönetici izni ister) ve uygulamayı yönetici olarak çalıştırın. O zamana kadar kilidi bilgisayarın başındaki birinin açması gerekir.';
  }
  $('#remote-locked-help').textContent = help;
}

$('#keys-menu [data-sas]').addEventListener('click', () => {
  if (!remoteControl) {
    toast('Uzak cihaz kontrole izin vermiyor', 'error');
    return;
  }
  activeTab?.viewer.sendSas();
  $('#remote-video').focus();
});

for (const item of document.querySelectorAll('#keys-menu [data-keys]')) {
  item.addEventListener('click', () => {
    if (!remoteControl) {
      toast('Uzak cihaz kontrole izin vermiyor', 'error');
      return;
    }
    for (const ev of comboEvents(item.dataset.keys)) viewer.sendInput(ev);
    $('#remote-video').focus();
  });
}
for (const item of document.querySelectorAll('#keys-menu [data-nav]')) {
  item.addEventListener('click', () => {
    if (!remoteControl) {
      toast('Uzak cihaz kontrole izin vermiyor', 'error');
      return;
    }
    viewer.sendInput({ t: 'nav', a: item.dataset.nav });
    $('#remote-video').focus();
  });
}

$('#shot-btn').addEventListener('click', async () => {
  const video = $('#remote-video');
  if (!video.videoWidth) return;
  try {
    const path = await saveBytes(bridge, timestampName('Xenon-ekran', 'png'), await captureFrame(video));
    const action = bridge.revealFile && path ? { label: 'Klasörü aç', fn: () => bridge.revealFile(path) } : null;
    toast('Ekran görüntüsü kaydedildi', 'success', 6000, action);
  } catch (err) {
    console.warn('[xenon] screenshot failed', err);
    toast('Ekran görüntüsü kaydedilemedi', 'error');
  }
});

for (const type of ['click', 'keydown']) {
  $('#server-status').addEventListener(type, (e) => {
    if (type === 'keydown' && e.key !== 'Enter') return;
    showView('settings');
  });
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'F11' && !$('#session').hidden) {
    e.preventDefault();
    $('#fullscreen-btn').click();
  }
});

/* Boot --------------------------------------------------------------- */

async function boot() {
  state.config = await bridge.getConfig();
  applyLanguage(state.config.language);
  applyTheme(state.config.theme);
  const info = await bridge.appInfo().catch(() => ({}));
  state.deviceName = state.config.deviceName || info.hostname || '';
  // The build number tells test builds of the same version apart.
  $('#app-version').textContent = [info.version ? `v${info.version}` : '', BUILD.build ? `(#${BUILD.build} · ${BUILD.commit})` : ''].filter(Boolean).join(' ');
  state.appVersion = info.version && /^\d/.test(info.version) ? info.version : '';
  state.loginScreen = Boolean(info.loginScreen);

  await renderInputModule();
  if (bridge.isAndroid) {
    // The user enables the accessibility service in system settings: re-check on return.
    document.addEventListener('visibilitychange', () => { if (!document.hidden) renderInputModule(); });
    $('#input-module-actions').hidden = false;
    $('#input-open-settings').addEventListener('click', () => bridge.openInputSettings());
    $('#input-app-settings').addEventListener('click', () => bridge.openAppSettings());
  }

  // The ID lives on the device so it is shown even before a server is found.
  if (!/^\d{9}$/.test(state.config.id || '')) state.config = await bridge.setConfig({ id: generateDeviceId() });
  $('#my-id').textContent = formatId(state.config.id);

  // Phones (Android app) and plain browsers can connect but not share a screen.
  // Android is allowed to host (share its screen) so a PC can connect to it;
  // whether the WebView can actually capture is decided when a session starts.
  const isAndroid = info.platform === 'android';
  state.platform = info.platform || '';
  state.canHost = bridge.canHost !== false && (isAndroid || Boolean(navigator.mediaDevices?.getDisplayMedia));
  document.body.classList.toggle('viewer-only', !state.canHost);
  document.body.classList.toggle('touch', matchMedia('(pointer: coarse)').matches);
  // Android TV box (no touch, no mouse): move between controls with the remote's arrows.
  if (bridge.isAndroid && !matchMedia('(pointer: coarse)').matches && !matchMedia('(pointer: fine)').matches) enableTvNavigation();
  $('#internet-access').checked = state.config.internetAccess !== false;
  // The web client itself does not need a link to the web client.
  $('.web-card').hidden = Boolean(bridge.isBrowser && !bridge.isAndroid);

  renderUnattended();
  initUpdates().catch((err) => console.warn('[xenon] updates unavailable', err));
  showLastCrash();
  initStartup().catch((err) => console.warn('[xenon] autostart unavailable', err));
  initAdminMode().catch((err) => console.warn('[xenon] admin mode unavailable', err));
  renderSecureCard().then(offerSecure).catch(() => {});
  renderPrinterCard().catch(() => {});
  state.sessionSecret = await deriveSecret(state.config.id, state.password);

  state.network = await bridge.getNetwork();
  renderPassword();
  renderSettings();
  renderDefaultPermissions();
  renderSessionSettings();
  renderCodecSetting();
  renderNetworkSettings();
  renderRecent();
  await loadScreens();
  createControllers();
  bridge.onNetwork(applyNetwork);
  renderConnection();
  reportStatus();
  // The OS vault (keychain) may be slow or ask for permission: never block startup on it.
  state.vaultReady = initVault().catch((err) => console.warn('[xenon] vault unavailable', err));
  renderAccess();
  // Invitation links: the app was opened with one, gets one later, or (web) the page URL has one.
  bridge.onDeepLink?.(handleInvite);
  const link = await bridge.takeDeepLink?.().catch(() => null);
  if (link) handleInvite(link);
  else if (location.hash.includes('connect=')) {
    handleInvite(location.href);
    history.replaceState(null, '', location.pathname + location.search); // the password does not stay in the address bar
  }
}

/* Updates ------------------------------------------------------------ */

const updateToasts = new Set();

function renderUpdate(status = {}) {
  const el = $('#update-status');
  const v = status.version ? `v${status.version}` : '';
  const texts = {
    idle: 'Henüz denetlenmedi',
    checking: 'Denetleniyor…',
    none: `Xenon Remote güncel${state.appVersion ? ` (v${state.appVersion})` : ''}`,
    available: `Yeni sürüm var: ${v}`,
    downloading: `${v} indiriliyor… %${status.progress || 0}`,
    ready: `${v} kuruluma hazır`,
    error: 'Güncelleme denetlenemedi. İnternet bağlantınızı kontrol edin.',
  };
  el.textContent = texts[status.state] || texts.idle;
  el.title = status.error || '';
  el.classList.toggle('ok', status.state === 'none');
  const action = $('#update-action');
  action.hidden = !['available', 'ready'].includes(status.state);
  action.textContent = status.state === 'ready'
    ? 'Yeniden başlat ve güncelle'
    : bridge.isAndroid ? 'Yeni APK\'yı indir' : 'İndirme sayfasını aç';
  // Tell the user once per version, wherever they are in the app.
  const key = `${status.state}:${status.version}`;
  if (['available', 'ready'].includes(status.state) && !updateToasts.has(key)) {
    updateToasts.add(key);
    toast(status.state === 'ready' ? `Xenon Remote ${v} hazır` : `Xenon Remote ${v} yayınlandı`, 'success', 15000,
      { label: action.textContent, fn: runUpdateAction });
  }
}

function runUpdateAction() {
  bridge.getUpdateStatus().then((status) => {
    if (status.state === 'ready' || bridge.isAndroid) bridge.installUpdate();
    else if (status.url) window.open(status.url, '_blank');
  });
}

/** Android: shows the report of the last crash so the user can send it. */
async function showLastCrash() {
  const text = await bridge.lastCrash?.().catch(() => null);
  if (!text) return;
  $('#crash-text').textContent = text;
  $('#crash-close').onclick = () => $('#crash-dialog').close();
  $('#crash-copy').onclick = () => copy(text, 'Hata raporu');
  $('#crash-dialog').showModal();
}

async function initUpdates() {
  if (!bridge.checkUpdate) return;
  $('#update-card').hidden = false;
  $('#auto-update').checked = state.config.autoUpdate !== false;
  $('#auto-update').addEventListener('change', async (e) => {
    state.config = await bridge.setConfig({ autoUpdate: e.target.checked });
  });
  $('#update-check').addEventListener('click', () => bridge.checkUpdate());
  $('#update-action').addEventListener('click', runUpdateAction);
  bridge.onUpdate(renderUpdate);
  renderUpdate(await bridge.getUpdateStatus());
  // The desktop main process checks by itself; the Android app checks here.
  if (bridge.isAndroid && state.config.autoUpdate !== false) setTimeout(() => bridge.checkUpdate(), 8000);
}

/** Shows whether remote input works on this device (Android: accessibility service). */
async function renderInputModule() {
  state.inputAvailable = await bridge.inputAvailable().catch(() => false);
  const status = $('#input-module-status');
  if (bridge.isAndroid) {
    status.textContent = state.inputAvailable ? 'Açık' : 'Kapalı';
    $('#input-module-hint').textContent = state.inputAvailable
      ? 'Bilgisayardan bu telefona dokunma, kaydırma, yazı ve Geri/Ana ekran tuşları gönderilebilir (yalnızca ekran paylaşımı sırasında).'
      : 'Bilgisayardan telefonu kontrol etmek için Erişilebilirlik › Yüklü uygulamalar › "Xenon Remote uzaktan kontrol" seçeneğini açın. Android 13 ve üzerinde seçenek gri ise önce Uygulama bilgisi › ⋮ › "Kısıtlanmış ayarlara izin ver" deyin.';
    $('#input-open-settings').hidden = state.inputAvailable;
  } else {
    status.textContent = state.inputAvailable ? 'Hazır' : 'Kullanılamıyor';
    $('#input-module-hint').textContent = state.inputAvailable
      ? 'Uzak kullanıcılara izin verdiğinizde fare ve klavye kontrolü sağlanır.'
      : 'Bu cihaz yalnızca ekran paylaşabilir. macOS\'ta Sistem Ayarları › Gizlilik › Erişilebilirlik iznini kontrol edin.';
    if (!state.inputAvailable && bridge.inputError) {
      const reason = await bridge.inputError().catch(() => null);
      if (reason) $('#input-module-hint').textContent += ` Hata: ${reason}`;
    }
  }
  status.className = state.inputAvailable ? 'status-ok' : 'status-bad';
}

/** Loads the unattended-access secret (bound to this device ID) from the OS vault. */
async function initVault() {
  state.vault = Boolean(await bridge.vaultAvailable?.());
  $('#remember-wrap').hidden = !state.vault;
  const stored = state.vault ? await bridge.getUnattended() : null;
  if (stored && stored.id === state.config.id) {
    state.unattended = hexToSecret(stored.secret);
    state.totp = isTotpSecret(stored.totp) ? stored.totp : null;
  }
  // Devices given permanent access (their keys are accepted like passwords).
  state.trusted = state.vault && bridge.getTrusted ? await bridge.getTrusted().catch(() => []) : [];
  listenOnInternet();
  renderUnattended();
  renderAccess();
}

boot().catch((err) => {
  console.error('[xenon] boot failed', err);
  toast('Uygulama başlatılamadı', 'error', 8000);
});

// Exposed for automated tests.
window.__xenon = {
  state,
  get signaling() { return signaling; },
  get nostr() { return nostr; },
  get host() { return host; },
  get viewer() { return activeTab?.viewer || pendingTab?.viewer || viewer; },
  get tabs() { return tabs; },
};
