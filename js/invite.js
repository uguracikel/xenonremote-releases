// Invitation links: the web client with the ID (and optionally the one-time
// password) in the URL fragment, which is never sent to the web server, or
// xenon://connect/<id> for the installed app.

export const WEB_CLIENT = 'https://uguracikel.github.io/xenonremote-releases/';

export function inviteLinks(id, password = '') {
  const pw = password ? `&pw=${encodeURIComponent(password)}` : '';
  return {
    web: `${WEB_CLIENT}#connect=${id}${pw}`,
    app: `xenon://connect/${id}${password ? `?pw=${encodeURIComponent(password)}` : ''}`,
  };
}

/** { id, password } from either kind of link (or a bare "#connect=..." fragment); null if none. */
export function parseInvite(link) {
  const text = String(link || '').trim();
  let id = null;
  let pw = '';
  let m = /^xenon:\/\/connect\/(\d{9})(?:\/?\?(.*))?$/i.exec(text);
  if (m) {
    id = m[1];
    pw = new URLSearchParams(m[2] || '').get('pw') || '';
  } else {
    const hash = text.includes('#') ? text.slice(text.indexOf('#') + 1) : '';
    const params = new URLSearchParams(hash);
    m = /^(\d{9})$/.exec(params.get('connect') || '');
    if (m) {
      id = m[1];
      pw = params.get('pw') || '';
    }
  }
  if (!id) return null;
  return { id, password: pw.slice(0, 128) };
}
