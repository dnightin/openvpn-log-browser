# REST API

Base URL: the app origin, for example `http://127.0.0.1:3017`.

All JSON endpoints return `application/json` and disable caching. If SAML `requireAuth` is enabled, API routes require an authenticated session except `/api/auth`.

`POST /api/settings/saml` and `POST /api/settings/source` additionally require an admin credential regardless of `requireAuth`, since they control authentication and log-source configuration. See [README.md](../README.md#admin-access) for `ADMIN_SETUP_TOKEN` and `ADMIN_EMAILS`.

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

Updates SAML settings. Requires an admin credential (`X-Admin-Token` header matching `ADMIN_SETUP_TOKEN`, or a SAML session whose email is in `ADMIN_EMAILS`); returns `403` otherwise.

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

Updates the log source. Requires an admin credential, same as `POST /api/settings/saml`.

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

### `GET /api/query`

General-purpose event query endpoint for scripts, reporting, and analysis. Unlike `/api/search`, it supports multi-value filters, numeric ranges, arbitrary sort order, field selection, and CSV export. It is unauthenticated by the same policy as `/api/search` and `/api/stats` (gated only by SAML `requireAuth` if enabled).

Every normalized event field is available for output; most are also filterable and sortable.

| Field | Filterable | Sortable |
| --- | --- | --- |
| `id`, `sourceKey`, `lineNumber`, `date`, `sessionStartTime`, `sessionEndTime`, `userAgent` | no | yes |
| `timestamp` | via `start` / `end` | yes (default) |
| `durationSeconds`, `bytesIn`, `bytesOut` | via `<field>Min` / `<field>Max` | yes |
| `os` | yes (prefix match) | yes |
| `category`, `eventName`, `initiator`, `initiatorName`, `userName`, `deviceName`, `initiatorType`, `publicIp`, `operation`, `entityType`, `entityName`, `parentEntityName`, `sessionId`, `protocol`, `gateway`, `gatewayRegion`, `tunnelIp`, `tunnelIpV4`, `tunnelIpV6`, `disconnectReason`, `traceId` | yes (exact, multi-value) | yes |

Query parameters:

- `q`: full-text or exact cached value search, same engine as `/api/search`
- `<field>`: for any "exact, multi-value" field above, filters to matching rows. Comma-separated values are OR'd, e.g. `userName=abaker@wellesley.edu,cchen@wellesley.edu`
- `os`: comma-separated OS name prefixes, OR'd, e.g. `os=Windows,macOS`
- `start`, `end`: timestamp range, same as `/api/search`
- `durationSecondsMin`, `durationSecondsMax`, `bytesInMin`, `bytesInMax`, `bytesOutMin`, `bytesOutMax`: numeric range filters
- `sort`: any field name from the table above; default `timestamp`
- `order`: `asc` or `desc`; default `desc`
- `fields`: comma-separated field names to include in each row; default is all normalized fields. `id` is always included
- `includeRaw=1`: adds a `raw` property (redacted, same rules as `/api/record`) to each row
- `limit`: max rows per page, capped at `20000`; default `1000`
- `offset`: skip this many matching rows before returning results; works with any `sort`. Note: large offsets scan from the start of the result set, so prefer `cursor` for deep pagination through large result sets
- `cursor`: opaque cursor from a previous response's `nextCursor`. Only honored when `sort=timestamp&order=desc` (the default); ignored otherwise in favor of `offset`
- `format`: `json` (default) or `csv`

An unrecognized query parameter, unknown `sort`/`fields` value, or non-numeric range value returns `400` with an `error` message naming the problem.

Response fields (JSON):

- `searched`: indexed source record count
- `total`: exact count of rows matching the filters
- `limit`, `offset`
- `hasMore`
- `nextCursor`: set when `hasMore` is true and pagination is cursor-eligible (see above)
- `rows`: array of projected records

CSV responses use the same column set as `fields` (plus `raw` as a JSON-encoded column when `includeRaw=1`) and are served as an attachment.

Examples:

```bash
# Long-running sessions (6+ hours) for two users, sorted longest first
curl "http://127.0.0.1:3017/api/query?userName=abaker@wellesley.edu,cchen@wellesley.edu&eventName=client-disconnected&durationSecondsMin=21600&sort=durationSeconds&order=desc"

# CSV of who connected from Windows or macOS this month
curl -o windows-macos-connects.csv "http://127.0.0.1:3017/api/query?os=Windows,macOS&eventName=client-connected&start=2026-08-01&fields=timestamp,userName,deviceName,publicIp&format=csv"

# Paginate through everything for one gateway using cursor
curl "http://127.0.0.1:3017/api/query?gateway=us-east-1%20%2F%20gw-use1-01&limit=5000"
```

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
