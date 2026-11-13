// Arrow-key (TV remote D-pad) navigation between buttons and fields, for
// Android TV boxes that have no touchscreen or mouse.

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])';
const DIRS = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0] };

function visible(el) {
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
}

function center(r) {
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
}

/** The nearest focusable element in direction (dx, dy) from `from`. */
export function nextInDirection(from, dx, dy, candidates) {
  const a = from.getBoundingClientRect();
  const ac = center(a);
  let best = null;
  let bestScore = Infinity;
  for (const el of candidates) {
    if (el === from) continue;
    const b = el.getBoundingClientRect();
    const bc = center(b);
    // Gap between the facing edges; the candidate must lie fully in that direction.
    const gap = dx > 0 ? b.left - (a.left + a.width)
      : dx < 0 ? a.left - (b.left + b.width)
        : dy > 0 ? b.top - (a.top + a.height)
          : a.top - (b.top + b.height);
    if (gap < -2) continue;
    const across = dx !== 0 ? Math.abs(bc.y - ac.y) : Math.abs(bc.x - ac.x);
    const score = Math.max(gap, 0) + across * 2; // prefer elements straight ahead
    if (score < bestScore) {
      bestScore = score;
      best = el;
    }
  }
  return best;
}

export function enableTvNavigation(root = document) {
  document.body.classList.add('tv');
  root.addEventListener('keydown', (e) => {
    const dir = DIRS[e.key];
    if (!dir || e.defaultPrevented) return;
    const active = document.activeElement;
    // Inside a text field left/right move the caret; the remote video takes keys itself.
    if (active && (active.id === 'remote-video' || (active.tagName === 'INPUT' && dir[0] !== 0 && active.type !== 'checkbox'))) return;
    const scope = document.querySelector('dialog[open]') || document;
    const candidates = [...scope.querySelectorAll(FOCUSABLE)].filter(visible);
    if (!candidates.length) return;
    const from = candidates.includes(active) ? active : null;
    const next = from ? nextInDirection(from, dir[0], dir[1], candidates) : candidates[0];
    if (!next) return;
    e.preventDefault();
    next.focus();
    next.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  });
}
