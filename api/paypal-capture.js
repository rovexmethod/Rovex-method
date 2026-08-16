// Verifies a PayPal order server-side (real payment, real amount) and
// mints a signed access token for the purchased product's gated page.
// Requires env vars in Vercel: PAYPAL_CLIENT_ID, PAYPAL_SECRET, ACCESS_TOKEN_SECRET

const crypto = require('crypto');

const PRODUCTS = {
  full:    { file: 'members-11x6lq.html', amount: '49.00' },
  planner: { file: 'planner-tsrcgc.html', amount: '17.99' },
  c25k:    { file: 'c25k-tqmf8s.html',    amount: '17.99' },
};

const PAYPAL_API = 'https://api-m.paypal.com';

function sign(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

async function getPayPalAccessToken() {
  const id = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_SECRET;
  const res = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });
  if (!res.ok) throw new Error('paypal_auth_failed');
  const data = await res.json();
  return data.access_token;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'method_not_allowed' });
    return;
  }

  const { orderId, product } = req.body || {};
  const config = PRODUCTS[product];
  if (!orderId || !config) {
    res.status(400).json({ ok: false, error: 'invalid_request' });
    return;
  }

  try {
    const accessToken = await getPayPalAccessToken();
    const orderRes = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderId}`, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    if (!orderRes.ok) {
      res.status(400).json({ ok: false, error: 'order_lookup_failed' });
      return;
    }
    const order = await orderRes.json();

    const capture = order.purchase_units && order.purchase_units[0] &&
      order.purchase_units[0].payments && order.purchase_units[0].payments.captures &&
      order.purchase_units[0].payments.captures[0];

    const status = (capture && capture.status) || order.status;
    const amount = (capture && capture.amount && capture.amount.value) ||
      (order.purchase_units && order.purchase_units[0] && order.purchase_units[0].amount && order.purchase_units[0].amount.value);
    const currency = (capture && capture.amount && capture.amount.currency_code) ||
      (order.purchase_units && order.purchase_units[0] && order.purchase_units[0].amount && order.purchase_units[0].amount.currency_code);

    // Defends against someone paying for the cheaper product and trying to
    // claim a more expensive one by reusing the endpoint with a different
    // `product` value than what was actually purchased.
    if (status !== 'COMPLETED' || amount !== config.amount || currency !== 'USD') {
      res.status(400).json({ ok: false, error: 'payment_not_verified' });
      return;
    }

    const sig = sign(`${product}.${orderId}`, process.env.ACCESS_TOKEN_SECRET);
    const token = `${product}.${orderId}.${sig}`;
    const url = `https://rovexmethod.com/${config.file}?token=${token}`;
    res.status(200).json({ ok: true, url });
  } catch (err) {
    console.error('paypal-capture error:', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
};
