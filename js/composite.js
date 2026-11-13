/**
 * "All monitors": captures every screen separately and paints them into one
 * picture laid out like the real monitor arrangement, so the viewer sees (and
 * controls) all of them at once.
 */
export const ALL_SCREENS = 'all';

/** Monitor rectangles in one shared space, from display bounds (DIP) or side by side. */
export function layoutScreens(parts) {
  const withBounds = parts.every((p) => p.bounds && p.bounds.width && p.bounds.height);
  let rects;
  if (withBounds) {
    rects = parts.map((p) => ({ ...p.bounds }));
  } else {
    let x = 0;
    rects = parts.map((p) => {
      const r = { x, y: 0, width: p.width || 1280, height: p.height || 720 };
      x += r.width;
      return r;
    });
  }
  const minX = Math.min(...rects.map((r) => r.x));
  const minY = Math.min(...rects.map((r) => r.y));
  rects = rects.map((r) => ({ ...r, x: r.x - minX, y: r.y - minY }));
  const width = Math.max(...rects.map((r) => r.x + r.width));
  const height = Math.max(...rects.map((r) => r.y + r.height));
  return { rects, width, height };
}

/** Output size: sharp enough for the monitors' real pixels, at most `maxWidth` wide. */
export function compositeScale(layout, parts, maxWidth) {
  const density = Math.max(1, ...parts.map((p, i) => (p.width || 0) / layout.rects[i].width));
  return Math.min(density, maxWidth / layout.width);
}

export async function captureAllScreens(bridge, { fps = 30, maxWidth = 3840 } = {}) {
  const screens = (await bridge.listScreens()).filter((s) => s.sourceId !== ALL_SCREENS);
  if (!screens.length) throw new Error('no screens');
  await bridge.selectScreen(ALL_SCREENS);
  const parts = [];
  try {
    for (const s of screens) {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { mandatory: { chromeMediaSource: 'desktop', chromeMediaSourceId: s.sourceId, maxFrameRate: fps } },
      });
      const video = document.createElement('video');
      video.muted = true;
      video.srcObject = stream;
      await video.play().catch(() => {});
      if (!video.videoWidth) await new Promise((r) => { video.onloadedmetadata = r; setTimeout(r, 2000); });
      parts.push({ stream, video, bounds: s.bounds || null, width: video.videoWidth, height: video.videoHeight });
    }
  } catch (err) {
    parts.forEach((p) => p.stream.getTracks().forEach((t) => t.stop()));
    throw err;
  }
  const layout = layoutScreens(parts);
  const k = compositeScale(layout, parts, maxWidth);
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(2, Math.round((layout.width * k) / 2) * 2);
  canvas.height = Math.max(2, Math.round((layout.height * k) / 2) * 2);
  const ctx = canvas.getContext('2d');
  const paint = () => {
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    parts.forEach((p, i) => {
      const r = layout.rects[i];
      ctx.drawImage(p.video, r.x * k, r.y * k, r.width * k, r.height * k);
    });
  };
  paint();
  // A timer, not requestAnimationFrame: it keeps running while the window is hidden.
  const timer = setInterval(paint, Math.round(1000 / fps));
  const stream = canvas.captureStream(fps);
  const [track] = stream.getVideoTracks();
  const stop = () => {
    clearInterval(timer);
    parts.forEach((p) => p.stream.getTracks().forEach((t) => t.stop()));
  };
  track.addEventListener('ended', stop);
  // Any monitor's capture ending (e.g. unplugged) ends the composite.
  parts.forEach((p) => p.stream.getVideoTracks()[0]?.addEventListener('ended', () => {
    stop();
    track.stop();
    track.dispatchEvent(new Event('ended'));
  }));
  return { stream, track, stop };
}
