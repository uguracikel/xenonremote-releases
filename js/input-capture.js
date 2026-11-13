/**
 * Captures mouse, wheel and keyboard events on the remote screen <video>
 * element and converts them to compact control messages:
 *   {t:'mm', x, y}            mouse move (x, y normalized 0..1)
 *   {t:'md'|'mu', b, x, y}    mouse button down / up (0 left, 1 middle, 2 right)
 *   {t:'wh', dx, dy}          wheel delta in pixels
 *   {t:'kd'|'ku', code}       key down / up (KeyboardEvent.code)
 *   {t:'tx', text}            typed text (phones: printable keys, any layout)
 */

/** Maps a client point to normalized coordinates of the visible video content. */
export function normalizePoint(clientX, clientY, rect, videoWidth, videoHeight) {
  if (!videoWidth || !videoHeight || !rect.width || !rect.height) return null;
  const scale = Math.min(rect.width / videoWidth, rect.height / videoHeight);
  const contentW = videoWidth * scale;
  const contentH = videoHeight * scale;
  const offsetX = (rect.width - contentW) / 2;
  const offsetY = (rect.height - contentH) / 2;
  const x = (clientX - rect.left - offsetX) / contentW;
  const y = (clientY - rect.top - offsetY) / contentH;
  const clamp = (v) => Math.min(1, Math.max(0, v));
  return { x: clamp(x), y: clamp(y), inside: x >= 0 && x <= 1 && y >= 0 && y <= 1 };
}

const LINE_HEIGHT_PX = 40;
const LONG_PRESS_MS = 550;
const DRAG_THRESHOLD_PX = 8;

/** A key that produces a character (with Shift/AltGr but no shortcut modifier). */
function isPrintable(e) {
  if (e.key.length !== 1 && !/^\p{L}$/u.test(e.key)) return false;
  return !(e.ctrlKey || e.metaKey || e.altKey) || e.getModifierState?.('AltGraph');
}

export function attachInputCapture(video, send, { isEnabled = () => true, textKeys = () => false } = {}) {
  const heldKeys = new Set();
  const heldButtons = new Set();
  let pendingMove = null;
  let frame = 0;

  const point = (e) => normalizePoint(e.clientX, e.clientY, video.getBoundingClientRect(), video.videoWidth, video.videoHeight);

  const flushMove = () => {
    frame = 0;
    if (pendingMove) send({ t: 'mm', x: pendingMove.x, y: pendingMove.y });
    pendingMove = null;
  };

  // Touch: tap = left click, long press = right click, drag = left drag.
  let touch = null;

  const onTouchDown = (e) => {
    const p = point(e);
    if (!p || !p.inside) return;
    e.preventDefault();
    video.setPointerCapture?.(e.pointerId);
    touch = { id: e.pointerId, x: e.clientX, y: e.clientY, start: p, dragging: false, done: false };
    touch.timer = setTimeout(() => {
      if (!touch || touch.dragging) return;
      touch.done = true;
      send({ t: 'mm', x: p.x, y: p.y });
      send({ t: 'md', b: 2, x: p.x, y: p.y });
      send({ t: 'mu', b: 2, x: p.x, y: p.y });
    }, LONG_PRESS_MS);
  };

  const onTouchMove = (e) => {
    if (!touch || touch.id !== e.pointerId || touch.done) return;
    if (!touch.dragging && Math.hypot(e.clientX - touch.x, e.clientY - touch.y) < DRAG_THRESHOLD_PX) return;
    const p = point(e);
    if (!p) return;
    if (!touch.dragging) {
      clearTimeout(touch.timer);
      touch.dragging = true;
      send({ t: 'mm', x: touch.start.x, y: touch.start.y });
      send({ t: 'md', b: 0, x: touch.start.x, y: touch.start.y });
    }
    send({ t: 'mm', x: p.x, y: p.y });
  };

  const onTouchUp = (e) => {
    if (!touch || touch.id !== e.pointerId) return;
    clearTimeout(touch.timer);
    const p = point(e) || touch.start;
    if (touch.dragging) {
      send({ t: 'mu', b: 0, x: p.x, y: p.y });
    } else if (!touch.done) {
      send({ t: 'mm', x: touch.start.x, y: touch.start.y });
      send({ t: 'md', b: 0, x: touch.start.x, y: touch.start.y });
      send({ t: 'mu', b: 0, x: touch.start.x, y: touch.start.y });
    }
    touch = null;
  };

  const onPointerMove = (e) => {
    if (!isEnabled()) return;
    if (e.pointerType === 'touch') {
      onTouchMove(e);
      return;
    }
    const p = point(e);
    if (!p) return;
    pendingMove = p;
    if (!frame) frame = requestAnimationFrame(flushMove);
  };

  const onPointerDown = (e) => {
    if (e.pointerType === 'touch') {
      if (isEnabled()) onTouchDown(e);
      return;
    }
    video.focus({ preventScroll: true });
    if (!isEnabled() || e.button > 2) return;
    const p = point(e);
    if (!p || !p.inside) return;
    e.preventDefault();
    video.setPointerCapture?.(e.pointerId);
    heldButtons.add(e.button);
    send({ t: 'md', b: e.button, x: p.x, y: p.y });
  };

  const onPointerUp = (e) => {
    if (e.pointerType === 'touch') {
      onTouchUp(e);
      return;
    }
    if (!heldButtons.has(e.button)) return;
    const p = point(e);
    heldButtons.delete(e.button);
    send(p ? { t: 'mu', b: e.button, x: p.x, y: p.y } : { t: 'mu', b: e.button });
  };

  const onWheel = (e) => {
    if (!isEnabled()) return;
    e.preventDefault();
    const factor = e.deltaMode === 1 ? LINE_HEIGHT_PX : e.deltaMode === 2 ? video.clientHeight : 1;
    send({ t: 'wh', dx: Math.round(e.deltaX * factor), dy: Math.round(e.deltaY * factor) });
  };

  const onKeyDown = (e) => {
    if (!isEnabled()) return;
    e.preventDefault();
    // Phones have no physical keyboard to inject into: printable keys become text.
    if (textKeys() && isPrintable(e)) {
      send({ t: 'tx', text: e.key });
      return;
    }
    if (e.repeat && heldKeys.has(e.code)) return; // the host OS repeats held keys itself
    heldKeys.add(e.code);
    send({ t: 'kd', code: e.code });
  };

  const onKeyUp = (e) => {
    if (!heldKeys.has(e.code)) return;
    e.preventDefault();
    heldKeys.delete(e.code);
    send({ t: 'ku', code: e.code });
  };

  const releaseAll = () => {
    if (touch) {
      clearTimeout(touch.timer);
      if (touch.dragging) send({ t: 'mu', b: 0 });
      touch = null;
    }
    for (const code of heldKeys) send({ t: 'ku', code });
    for (const b of heldButtons) send({ t: 'mu', b });
    heldKeys.clear();
    heldButtons.clear();
  };

  const onContextMenu = (e) => e.preventDefault();

  video.addEventListener('pointermove', onPointerMove);
  video.addEventListener('pointerdown', onPointerDown);
  video.addEventListener('pointerup', onPointerUp);
  video.addEventListener('pointercancel', onPointerUp);
  video.addEventListener('wheel', onWheel, { passive: false });
  video.addEventListener('keydown', onKeyDown);
  video.addEventListener('keyup', onKeyUp);
  video.addEventListener('blur', releaseAll);
  video.addEventListener('contextmenu', onContextMenu);

  return {
    releaseAll,
    detach() {
      releaseAll();
      if (frame) cancelAnimationFrame(frame);
      video.removeEventListener('pointermove', onPointerMove);
      video.removeEventListener('pointerdown', onPointerDown);
      video.removeEventListener('pointerup', onPointerUp);
      video.removeEventListener('pointercancel', onPointerUp);
      video.removeEventListener('wheel', onWheel);
      video.removeEventListener('keydown', onKeyDown);
      video.removeEventListener('keyup', onKeyUp);
      video.removeEventListener('blur', releaseAll);
      video.removeEventListener('contextmenu', onContextMenu);
    },
  };
}

/**
 * Forwards an on-screen (phone) keyboard: typed text is sent as {t:'tx'} so any
 * language works; Backspace/Enter are sent as key presses.
 */
export function attachMobileKeyboard(input, send, { isEnabled = () => true } = {}) {
  const press = (code) => {
    send({ t: 'kd', code });
    send({ t: 'ku', code });
  };
  const onBeforeInput = (e) => {
    if (!isEnabled()) return;
    e.preventDefault();
    if (e.inputType === 'deleteContentBackward') press('Backspace');
    else if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') press('Enter');
    else if (e.data) send({ t: 'tx', text: e.data.slice(0, 500) });
    input.value = '';
  };
  const onKeyDown = (e) => {
    if (!isEnabled()) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      press('Enter');
    } else if (e.key === 'Backspace' && !input.value) {
      e.preventDefault();
      press('Backspace');
    }
  };
  input.addEventListener('beforeinput', onBeforeInput);
  input.addEventListener('keydown', onKeyDown);
  return () => {
    input.removeEventListener('beforeinput', onBeforeInput);
    input.removeEventListener('keydown', onKeyDown);
  };
}
