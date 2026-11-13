import { normalizePoint } from './input-capture.js';

export const DRAW_COLORS = ['#ff3b30', '#ffd60a', '#34c759', '#0a84ff', '#ffffff'];
const SEND_EVERY_MS = 40;
const LOCAL_FADE_MS = 2500; // the remote screen shows the stroke by then

/**
 * Draw mode on the remote screen: strokes are drawn on a canvas over the
 * video and sent (normalized 0..1) so the host shows them on its monitor.
 * While it is on, mouse input is not sent to the remote device.
 */
export function attachDrawing(canvas, video, { send, onClear }) {
  const ctx = canvas.getContext('2d');
  const strokes = [];
  let enabled = false;
  let color = DRAW_COLORS[0];
  let current = null;
  let raf = 0;
  let seq = 0;

  const fit = () => {
    const r = canvas.getBoundingClientRect();
    canvas.width = Math.round(r.width * devicePixelRatio);
    canvas.height = Math.round(r.height * devicePixelRatio);
  };

  // Normalized point -> canvas pixels (same letterboxing as the video).
  const toCanvas = ([x, y]) => {
    const r = video.getBoundingClientRect();
    const c = canvas.getBoundingClientRect();
    const scale = Math.min(r.width / video.videoWidth, r.height / video.videoHeight);
    const w = video.videoWidth * scale;
    const h = video.videoHeight * scale;
    return [(r.left - c.left + (r.width - w) / 2 + x * w) * devicePixelRatio, (r.top - c.top + (r.height - h) / 2 + y * h) * devicePixelRatio];
  };

  const render = () => {
    raf = 0;
    const now = Date.now();
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = strokes.length - 1; i >= 0; i--) {
      const s = strokes[i];
      const age = s.doneAt ? now - s.doneAt : 0;
      if (age > LOCAL_FADE_MS) { strokes.splice(i, 1); continue; }
      ctx.globalAlpha = s.doneAt ? 1 - age / LOCAL_FADE_MS : 1;
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 4 * devicePixelRatio;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.beginPath();
      s.pts.map(toCanvas).forEach(([x, y], j) => (j ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      ctx.stroke();
    }
    if (strokes.length) raf = requestAnimationFrame(render);
  };
  const schedule = () => { if (!raf) raf = requestAnimationFrame(render); };

  const flush = (done = false) => {
    if (!current) return;
    const pts = current.pts.slice(current.sent);
    if (!pts.length && !done) return;
    current.sent = current.pts.length;
    send({ id: current.id, pts: pts.map(([x, y]) => [Math.round(x * 10000) / 10000, Math.round(y * 10000) / 10000]), color: current.color, done });
  };

  const point = (e) => normalizePoint(e.clientX, e.clientY, video.getBoundingClientRect(), video.videoWidth, video.videoHeight);

  const onDown = (e) => {
    if (!enabled || e.button > 0) return;
    const p = point(e);
    if (!p?.inside) return;
    e.preventDefault();
    canvas.setPointerCapture?.(e.pointerId);
    seq += 1;
    current = { id: `s${seq}`, color, pts: [[p.x, p.y]], sent: 0, timer: setInterval(() => flush(), SEND_EVERY_MS) };
    strokes.push(current);
    schedule();
  };
  const onMove = (e) => {
    if (!current) return;
    const p = point(e);
    if (!p) return;
    current.pts.push([p.x, p.y]);
    schedule();
  };
  const onUp = () => {
    if (!current) return;
    clearInterval(current.timer);
    flush(true);
    current.doneAt = Date.now();
    current = null;
    schedule();
  };

  canvas.addEventListener('pointerdown', onDown);
  canvas.addEventListener('pointermove', onMove);
  canvas.addEventListener('pointerup', onUp);
  canvas.addEventListener('pointercancel', onUp);
  const ro = new ResizeObserver(() => { fit(); schedule(); });
  ro.observe(canvas);

  return {
    get enabled() { return enabled; },
    setEnabled(on) {
      enabled = Boolean(on);
      canvas.classList.toggle('active', enabled);
      if (enabled) fit();
      else onUp();
    },
    setColor(c) { color = c; },
    clear() {
      strokes.length = 0;
      schedule();
      onClear();
    },
    detach() {
      onUp();
      ro.disconnect();
      canvas.removeEventListener('pointerdown', onDown);
      canvas.removeEventListener('pointermove', onMove);
      canvas.removeEventListener('pointerup', onUp);
      canvas.removeEventListener('pointercancel', onUp);
      strokes.length = 0;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    },
  };
}
