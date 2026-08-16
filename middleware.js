// Gatekeeper for the paid pages. Runs on Vercel's Edge Runtime BEFORE the
// static HTML is served, so a visitor without a valid token/cookie never
// receives the page bytes at all (unlike a client-side JS check, which can
// be bypassed by disabling JS or just viewing page source).
//
// Requires env var in Vercel: ACCESS_TOKEN_SECRET (same value used in
// api/paypal-capture.js to sign tokens).

export const config = {
  matcher: ['/members-11x6lq.html', '/c25k-tqmf8s.html', '/planner-tsrcgc.html'],
};

const PRODUCT_BY_PATH = {
  '/members-11x6lq.html': 'full',
  '/c25k-tqmf8s.html': 'c25k',
  '/planner-tsrcgc.html': 'planner',
};

const TEN_YEARS = 60 * 60 * 24 * 365 * 10; // matches "lifetime access"

async function sign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const product = PRODUCT_BY_PATH[url.pathname];
  if (!product) return; // not a gated path

  const secret = process.env.ACCESS_TOKEN_SECRET;
  if (!secret) {
    // Not configured yet (env var missing) — fail OPEN, not closed. Better
    // to temporarily behave like before this fix existed than to lock
    // everyone out of a page they may have just paid for because of a
    // deploy/config-ordering mistake.
    return;
  }

  const cookies = parseCookies(request.headers.get('cookie'));
  const cookieName = `rovex_access_${product}`;

  if (cookies[cookieName] === '1') {
    return; // already unlocked in this browser, let the static file serve
  }

  const token = url.searchParams.get('token');
  if (token) {
    const parts = token.split('.');
    if (parts.length === 3) {
      const [tokProduct, orderId, sig] = parts;
      if (tokProduct === product && orderId) {
        const expected = await sign(`${product}.${orderId}`, secret);
        if (expected === sig) {
          // Valid — set a long-lived cookie and redirect to a clean URL
          // (so the token isn't left sitting in the address bar / history).
          const cleanUrl = new URL(url);
          cleanUrl.searchParams.delete('token');
          const res = Response.redirect(cleanUrl.toString(), 302);
          res.headers.append(
            'Set-Cookie',
            `${cookieName}=1; Max-Age=${TEN_YEARS}; Path=/; Secure; HttpOnly; SameSite=Lax`
          );
          return res;
        }
      }
    }
  }

  // No valid token or cookie — send to self-serve recovery instead of a
  // flat "buy now" wall. Customers who purchased before this gate existed
  // have a bookmarked link but no token/cookie; recover.html re-verifies
  // their PayPal Order ID directly against PayPal (works for orders from
  // any date) and hands back a working link, so they don't get bounced to
  // checkout for something they already paid for.
  return Response.redirect(new URL(`/recover.html?product=${product}`, url.origin), 302);
}
