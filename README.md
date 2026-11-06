# Lagos Close – multiplayer update

## Run
Requires **Node.js 22.5 or newer** (uses the built‑in `node:sqlite`). No npm packages are needed.

```
cd lagos-close
node --no-warnings server/server.js          # http://localhost:8080
```
Open `http://localhost:8080` in a browser (phone or desktop). The game **must be opened through this server**
(accounts, saves, shop, fishing pay, fuel and multiplayer all live on the server). Do not open `index.html` as a file.

Environment variables: `PORT` (default 8080), `DB_FILE` (default `server/lagos.db`), `ADMIN_TOKEN` (enables admin endpoints; unset = disabled).

Put the server behind HTTPS (Caddy, nginx, Cloudflare, …) when you host it publicly. WebSocket path is `/ws`.

## What lives where
* `index.html` – the whole game (single file, same architecture as before).
* `server/server.js` – accounts (email + password, scrypt), sessions, progress save, server‑authoritative shop / fishing pay / fuel,
  premium entitlements, WebSocket multiplayer (positions, animation, uniform, vehicles + vehicle claims).
* `server/seed-config.json` – first‑run configuration: premium characters, supermarket categories/products/prices, fishing species/values,
  fuel price/tank sizes, uniforms, job roles/pay. It is copied into the database; change it live with
  `PUT /api/admin/config?key=<name>` + header `x-admin-token` (body `{"value": ...}`), no code change needed.
* `assets/` – packed uploaded models (labo truck, gas station, TV, rod, bucket, carp, delivery box) and the four premium FBX characters.
* `tests/server.test.js` – backend tests: `node --no-warnings tests/server.test.js`.

## Premium characters / payments
Buttons say **Buy with real money – Coming Soon**. No payment provider is connected: nothing is purchased or unlocked, and in‑game money
is never used. Characters stay locked until the server holds an entitlement row. When you connect a payment provider, its verified webhook
should call `POST /api/admin/grant` (admin token) with `{userId, characterId, paymentRef}`.
Set prices in the config key `premiumCharacters` (`price: {amount, currency}`).
