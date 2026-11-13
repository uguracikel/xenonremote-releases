/**
 * IP allow list: "192.168.1.20", "10.0.0.0/8", "2001:db8::5" (IPv6: exact
 * address only). An empty list allows every address.
 */

function ipv4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

/** Normalised rule text, or null when it is not a valid address or range. */
export function parseIpRule(text) {
  const t = String(text || '').trim().toLowerCase();
  if (!t) return null;
  const m = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(t);
  if (m) {
    const base = ipv4ToInt(m[1]);
    const bits = m[2] === undefined ? 32 : Number(m[2]);
    if (base === null || bits > 32) return null;
    return bits === 32 ? m[1] : `${m[1]}/${bits}`;
  }
  if (/^[0-9a-f:]+$/.test(t) && t.includes(':') && t.length <= 39) return t;
  return null;
}

/** IPv4 in IPv6 form ("::ffff:1.2.3.4") counts as the IPv4 address. */
function plainIp(ip) {
  const t = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = /^::ffff:([\d.]+)$/.exec(t);
  return mapped ? mapped[1] : t;
}

export function ipAllowed(ip, rules) {
  if (!rules || !rules.length) return true;
  const addr = plainIp(ip);
  const v4 = ipv4ToInt(addr);
  for (const rule of rules) {
    const r = parseIpRule(rule);
    if (!r) continue;
    if (r.includes(':')) {
      if (r === addr) return true;
      continue;
    }
    if (v4 === null) continue;
    const [base, bits = '32'] = r.split('/');
    const n = Number(bits);
    const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
    if (((v4 & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0)) return true;
  }
  return false;
}

/** The address the peer connection really talks to (from WebRTC statistics). */
export async function remoteAddress(pc) {
  const report = await pc.getStats();
  let pair = null;
  report.forEach((s) => {
    if (s.type === 'transport' && s.selectedCandidatePairId) pair = report.get(s.selectedCandidatePairId) || pair;
  });
  if (!pair) report.forEach((s) => { if (!pair && s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') pair = s; });
  const remote = pair && report.get(pair.remoteCandidateId);
  if (!remote) return null;
  return { ip: remote.address || remote.ip || '', type: remote.candidateType || '' };
}
