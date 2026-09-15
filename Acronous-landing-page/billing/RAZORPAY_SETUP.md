# Razorpay setup — Acronous billing (single integration for all products)

All money flows through **one** Razorpay account. One secret, one webhook, one
place to reconcile. The catalog lives in `billing/plans.json`; the worker at
`api.acronous.com` enforces it. You are in the Razorpay dashboard now — do the
steps below in order. Nothing in the apps needs a dashboard plan created by
hand: the worker creates Razorpay **orders** on demand with the right amount.

## 0. Account + activation (do first, blocks real money)

1. Finish **KYC / activation** (Home → Activate). Until activation is complete
   you can only use **Test mode** — that is fine for everything in step 1–4.
2. Keep the mode toggle in mind: top bar **Test / Live**. Keys, webhooks and
   payment-method settings are **separate per mode** — repeat steps 1–4 in Live
   before launch.

## 1. Get API keys (Test mode first)

1. Go to **Settings → API Keys** (or Home → API keys).
2. **Generate Key** → download/copy the **Key ID** (`rzp_test_…`) and **Key
   Secret**. The secret is shown **once**.
3. Wire them into the worker (secret NEVER goes in code, browsers, or apps):
   ```sh
   cd "Acronous Ai"
   # Key ID is public — put it in wrangler.toml:
   #   RAZORPAY_KEY_ID = "rzp_test_XXXX"
   npx wrangler secret put RAZORPAY_KEY_SECRET   # paste the secret
   npx wrangler secret put RAZORPAY_WEBHOOK_SECRET  # step 4, can do later
   npx wrangler deploy cloudflare-worker.js --name acronous-ai
   ```
4. Smoke test: `GET https://api.acronous.com/v1/billing/status` should list
   all plans; `POST /v1/billing/order {"plan":"ai_plus_monthly"}` (signed in)
   should return an `order_id`. Until keys are set, order calls return **503**
   and everything stays on free tier — that is the safe default.

## 2. Enable payment methods (UPI / cards / international)

1. **Settings → Payment Methods** (Test mode shows all methods by default).
2. Turn ON, per method: **UPI** (incl. UPI Autopay for later), **Credit Card**,
   **Debit Card**, **Netbanking**, **Wallets**, **EMI**, and under cards enable
   **International** payments. This is what makes one checkout accept
   UPI + domestic + international cards with zero code changes.
3. **Settings → Checkout / Appearance** (optional): business name `Acronous`,
   logo, theme color `#6366f1`, and a support email (`billing@acronous.com`).
4. Currency is **INR** everywhere (orders are created with `currency: INR`).
   International cards are auto-converted by the customer's bank.

## 3. Test payments (before touching Live)

1. Stay in **Test mode**. Open `https://acronous.com/pricing.html`, sign in,
   click any paid plan → Razorpay test checkout opens.
2. Pay with test credentials:
   - **UPI**: use `success@razorpay` (verifies without a real collect request).
   - **Card**: `4111 1111 1111 1111`, any future expiry, any CVV.
3. After payment the page calls `/v1/billing/verify` → you should see
   “Payment verified”. Confirm in dashboard: **Payments** tab shows the test
   payment with receipt `acro_…` and notes `user=u:… plan=ai_plus_monthly`.
4. Confirm entitlement: `GET /v1/billing/status?product=acronous_ai` (same
   user) shows the subscription. Close-the-browser-mid-payment case is covered
   by the webhook (step 4).

## 4. Webhook (safety net — grants users who never return from Checkout)

1. **Settings → Webhooks → Add New Webhook**:
   - URL: `https://api.acronous.com/v1/billing/webhook`
   - Events: **`payment.captured`** and **`order.paid`**
   - Secret: generate one, then store it: `npx wrangler secret put RAZORPAY_WEBHOOK_SECRET`
   - Redeploy the worker after adding the secret.
2. The worker verifies `X-Razorpay-Signature` = HMAC-SHA256(raw body, secret)
   and grants from the order notes (`user`, `plan`). Wrong signatures are
   rejected with 401. Test from the dashboard with a sample event.

## 5. Go live (launch checklist)

- [ ] KYC activated, **Live mode** on.
- [ ] Live keys generated; `RAZORPAY_KEY_ID = "rzp_live_…"` in `wrangler.toml`,
      live secret via `wrangler secret put`; worker redeployed.
- [ ] Live webhook created (same URL/events) with its own secret stored.
- [ ] Payment methods ON in **Live** (they reset between modes).
- [ ] One real ₹99/₹149 purchase (Navigwiz AI Starter or AI Starter) on your
      own account → verify grant → refund it from **Payments → Refund** to
      confirm the refund path works.
- [ ] Settlement + notification emails configured (**Settings →
      Notifications**), so billing@acronous.com gets payment/settlement mail.

## 6. Day-to-day money ops

- **Find a payment**: Payments tab → search by receipt (`acro_…`), UTR, or
  email. Order notes always carry `user` (quota id) and `plan`.
- **Refunds**: Payments → ⋯ → Refund (5–7 business days to source). Policy is
  documented at `acronous.com/docs.html#refunds`.
- **Settlements**: Settlements tab → money lands in the registered bank
  account on Razorpay's schedule (T+2 typically after activation).
- **Disputes/chargebacks**: Disputes tab — respond with the order notes +
  KV grant timestamp as delivery proof.
- **Never** paste bank QR codes or account numbers into any app, page, or
  repo. If anyone asks why: QR/account exposure is what gets accounts drained
  and impersonated; Razorpay orders + HMAC verification is the robust
  replacement, and it is what every checkout here uses.

## 7. Prices (change code, not the dashboard)

Amounts are **not** configured in Razorpay — the worker sends
`amount = catalog INR × 100 paise` per order. To change a price, edit both:

1. `Acronous-landing-page/billing/plans.json` (storefront source of truth), and
2. `BILLING_CATALOG` in `Acronous Ai/cloudflare-worker.js`,
3. then mirror the numbers in `pricing.html`, `api.html`, the Flutter
   `lib/billing/plans.dart` files, and `Equyvo/src/lib/plans.ts`.

Current ladder: AI 0/149/**449**/999/2499 · Nav 0/99/**299**/699/1499 ·
Equyvo 0/49/**149**/**399**/799 · One bundle 699 · API packs 99→1k / 499→6k /
999→14k / 2499→40k credits.
