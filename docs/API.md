# REST API

Base URL: the app origin, for example `http://127.0.0.1:3017`.

All JSON endpoints return `application/json` and disable caching. If SAML `requireAuth` is enabled, API routes require an authenticated session except `/api/auth`.

## Authentication

### `GET /api/auth`

Returns the current authenticated user state and SAML readiness.

### `GET /auth/saml/login`

Starts SAML login when SAML is configured.

### `POST /auth/saml/callback`

SAML assertion consumer service endpoint.

### `GET /auth/saml/metadata`

Returns service-provider metadata XML.

### `GET /auth/logout`

Clears the local app session and redirects to `/`.

## Settings

### `GET /api/settings/saml`

Returns public SAML settings. Secret/private values are redacted or omitted where appropriate.

### `POST /api/settings/saml`

Updates SAML settings.

Request body fields:

- `enabled`
- `requireAuth`
- `issuer`
- `callbackUrl`
- `entryPoint`
- `logoutUrl`
- `audience`
- `idpCert`
- `wantAssertionsSigned`
- `wantAuthnResponseSigned`
- `disableRequestedAuthnContext`

### `GET /api/settings/source`

Returns the configured log source with credential status only.

### `POST /api/settings/source`

Updates the log source.

Request body fields:

- `mode`: `http` or `s3-api`
- `bucketUrl`
- `bucketName`
- `region`
- `logPrefix`

AWS secrets are not accepted by this endpoint. Store them in the service environment file.

## Logs And Search

### `GET /api/stats`

Returns dashboard statistics.

Query parameters:

- `timeZone`: optional display timezone, default `UTC`

### `GET /api/facets`

Returns filter values:

- `categories`
- `eventNames`
- `operatingSystems`
- `gateways`
- `users`
- `ips`

When MariaDB is enabled, values come from `log_facets_cache`.

### `GET /api/search`

Searches event-list rows.

Query parameters:

- `q`: full-text or exact cached value search
- `category`
- `eventName`
- `os`
- `gateway`
- `start`: parseable timestamp/date
- `end`: parseable timestamp/date
- `limit`: max rows, capped at `10000`
- `cursor`: opaque cursor returned by a previous response
- `exactTotal=1`: force exact total count

Response fields:

- `searched`: indexed source record count
- `total`: exact count when available, otherwise `null`
- `totalIsExact`
- `limit`
- `hasMore`
- `nextCursor`
- `rows`

Search rows intentionally omit raw JSON and `searchText`. Fetch `/api/record` for detail.

### `GET /api/record`

Returns one event with redacted raw JSON and per-user reconnect detail.

Query parameters:

- `id`: event id from `/api/search`

### `POST /api/reload`

Requests a refresh.

When MariaDB split-ingest mode is active, this returns the latest database-backed stats and does not perform S3 ingestion in the web process. The worker performs ingestion.

## Reconnect Watch

### `GET /api/churn`

Returns the reconnect watch leaderboard.

Query parameters:

- `limit`: max users, capped at `50`

When MariaDB is enabled, values come from `churn_watch_cache`.

## Connected-User History

### `GET /api/connected-users`

Returns connected-user count history for licensing analysis.

Query parameters:

- `range`: `week`, `month`, or `year`

The MariaDB source reads `connected_user_counts`, retained for one year.

### `GET /api/connected-users/export`

Exports connected-user count history.

Query parameters:

- `range`: `week`, `month`, `year`, or `all`; default `year`
- `format`: `csv` or `json`; default `csv`

CSV columns:

- `sampled_at`
- `connected_users`
- `excluded_users`

## Operations

### `GET /api/health`

Returns operational health data:

- process memory and uptime
- key runtime configuration
- source configuration summary
- current app stats
- MariaDB table sizes
- materialized cache ages
- expected index presence
- recent in-process slow API/DB calls

### `GET /admin`

HTML admin health page backed by `/api/health`.

## Smoke Test

Run:

```bash
npm run smoke
```

Set a target URL:

```bash
SMOKE_BASE_URL=http://127.0.0.1:3017 npm run smoke
```
