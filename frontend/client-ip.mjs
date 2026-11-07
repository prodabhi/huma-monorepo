// The client's address for rate limits. Production: Caddy on the same machine proxies to 127.0.0.1 and replaces
// X-Forwarded-For with the real client, so trust its last entry only when the socket is loopback. Never CF-Connecting-IP.
// IPv6 is bucketed by /64 (one customer usually holds a whole /64).
import { isIP } from 'node:net';

const loopback = address => /^(::ffff:)?127\./.test(address) || address === '::1';

export function clientIP(req, env = process.env) {
  // On Vercel (VERCEL=1 in its functions) the socket is Vercel's own proxy; its edge sets X-Real-IP to the client and
  // overwrites anything the client sent, so that header is the address.
  if (env.VERCEL === '1') {
    const real = req.headers?.['x-real-ip'];
    if (typeof real === 'string' && isIP(real.trim())) return bucket(real.trim()) || 'unknown';
  }
  const socket = req.socket?.remoteAddress ?? '';
  let address = socket;
  if (loopback(socket)) {
    const forwarded = req.headers?.['x-forwarded-for'];
    const last = typeof forwarded === 'string' && forwarded.length <= 2048 ? forwarded.split(',').at(-1).trim() : '';
    if (isIP(last)) address = last;
  }
  return bucket(address) || 'unknown';
}

export function bucket(address) {
  address = String(address ?? '').replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '');
  const kind = isIP(address);
  if (kind === 4) return address;
  if (kind !== 6) return '';
  const [head, tail = ''] = address.toLowerCase().split('%')[0].split('::');
  const left = head ? head.split(':') : [], right = address.includes('::') && tail ? tail.split(':') : [];
  if (right.at(-1)?.includes('.') || left.at(-1)?.includes('.')) return address.toLowerCase(); // embedded IPv4: rare, keep whole
  const groups = address.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return groups.slice(0, 4).map(group => parseInt(group, 16).toString(16)).join(':') + '::/64';
}
