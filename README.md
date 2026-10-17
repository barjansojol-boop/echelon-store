# Echelon Store — Full-stack website starter

This is a real full-stack starter project, not just a static mockup. It includes a responsive storefront, customer registration/login, password hashing, a virtual Ω wallet, server-side card limits, product management, order checkout using Ω, customer requests, owner-only wallet/product/account/request controls, an audit ledger, and JSON data export.

## Important limitations
- Ω is virtual store credit only. This project does not process real money, bank cards, withdrawals, or payouts.
- Membership cards are virtual design concepts, not payment cards. Do not print or share real payment-card credentials.
- The project is not automatically published to the internet. You must deploy it to a Node.js host and configure persistent storage, HTTPS, secrets, backups, and monitoring.
- Before public launch, have a qualified developer review authentication, session storage, rate limiting, data protection, abuse prevention, and local legal requirements. For a production deployment, use a managed database and a durable session store.
- The default catalog includes user-supplied external links. Verify legality, destination safety, and terms before making products available. The Instagram listing has no provider URL until the owner supplies one.

## Requirements
- Node.js 20 or newer
- npm

## Local setup
1. Extract the ZIP.
2. Open a terminal in the extracted `echelon_full` folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env`.
5. Edit `.env`: set a unique random `SESSION_SECRET`, a different unique `OWNER_SETUP_KEY`, `OWNER_EMAIL`, `OWNER_NAME`, and a strong `OWNER_PASSWORD`. Do not use the example values.
6. Run `npm start`.
7. Open `http://localhost:3000`.

The first server start creates the owner account from `.env` if no owner exists. Keep `.env` private and never upload it to GitHub. The owner setup key is an initialization safeguard; it is not a public registration code. Customers register through the website and never receive owner permissions.

## Security design
- Passwords and optional wallet PINs are hashed with bcrypt.
- Customer and owner permissions are checked on the server for every protected action.
- Each user can create at most one Echelon card and one Atlas card. Database uniqueness constraints enforce the rule.
- Customers cannot call owner wallet/product endpoints successfully; owner authorization is server-enforced.
- Purchases calculate prices on the server and debit Ω in a database transaction. The browser cannot set a price or wallet balance.
- Wallet adjustments create ledger records.
- The owner cannot disable their own account through customer controls.
- HTTPS-only cookies are enabled when `NODE_ENV=production`.

## Deployment checklist
1. Choose a Node.js host that supports persistent storage, or modify the app to use a managed SQL database.
2. Set all `.env` values in the host's secret/environment settings. Set `NODE_ENV=production`, `PORT` as provided by the host, and `BASE_URL` to your HTTPS domain.
3. Ensure the database and session files are stored on persistent storage. Do not rely on ephemeral container filesystems.
4. Configure HTTPS, backups, log monitoring, dependency updates, and a restore test.
5. Keep secrets out of the repository. Do not commit `.env`, database files, or customer data.
6. Test account creation, sign-in, card limits, wallet changes, checkout, disabled accounts, and backup restore before launch.

## Useful routes
- `GET /api/health` — health check
- `GET /api/products` — public active products
- `GET /api/me` — signed-in user's wallet/cards/orders/ledger
- `/api/admin/*` — owner-protected management routes
- `GET /api/admin/export` — owner-only JSON export

## Updating product links
Sign in as owner and use the Owner dashboard's Product Manager. Use HTTPS links only. Review third-party links before activating them.
