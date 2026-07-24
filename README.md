# OpenVPN Log Search

Small web app for authorized CloudConnexa/OpenVPN audit logs stored as gzipped JSONL in S3.

The app is designed for operational log review, not long-term raw-log warehousing. It keeps the searchable log set in memory, optionally records aggregate connected-user counts in MySQL for licensing analysis, and avoids writing usernames, IPs, sessions, or raw event payloads to the database.

## Features

- Search all loaded log events, not only the currently displayed page.
- Filter by category, event type, operating system, gateway, date range, and row limit.
- Resize event-list columns; widths are remembered in browser storage.
- View active users/sessions after excluding reconnect-heavy users from active-session counts.
- Track connected users over time with week, month, and year ranges.
- Show a compact Reconnect Watch for users with excessive connect/disconnect churn.
- Click a Reconnect Watch username to put that user in the Search field and filter events.
- Open Event Detail only when needed. Click an event to show details; click the same event again, or the X, to hide details and return the event list to full width.
- Display timestamps in the timezone selected from `Menu` -> `Settings`.
- Configure optional SAML 2.0 SSO from environment variables or `Menu` -> `Settings`.
- Choose HTTP bucket listing or S3 API with IAM credentials from `Menu` -> `Settings`.
- Reload S3 logs incrementally by reusing unchanged objects while the server process stays running.
- Redact secret-like keys in raw event display.

## Run

```powershell
npm install
npm start
```

Then open `http://localhost:3000`.

Node.js 18 or newer is required for SAML 2.0 SSO support.

You can also verify ingestion without starting the web server:

```powershell
npm run ingest
```

By default the app reads from:

```text
https://<BUCKET-NAME>.s3.us-east-1.amazonaws.com/
```

If the current machine cannot list the bucket, run it from any authorized host with S3 access or place `.jsonl.gz` files under `data/raw/` and start again.

## Environment

```text
PORT=3000
RAW_DIR=data/raw
S3_CACHE_DIR=data/s3-cache
SETTINGS_DIR=data/settings
SAML_SETTINGS_PATH=data/settings/saml.json
SOURCE_SETTINGS_PATH=data/settings/source.json
FETCH_CONCURRENCY=32
LOAD_BATCH_DELAY_MS=0
AUTO_REFRESH_MINUTES=30
ACTIVE_SESSION_MAX_AGE_HOURS=6

# Log source.
S3_FETCH_MODE=http
S3_BUCKET_URL=https://<BUCKET-NAME>.s3.us-east-1.amazonaws.com/
S3_BUCKET_NAME=<BUCKET-NAME>
AWS_REGION=us-east-1
LOG_PREFIX=CloudConnexa/<CLOUD-ID>/

# Optional MySQL aggregate count storage.
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=openvpn_log_browser
MYSQL_PASSWORD=<password>
MYSQL_DATABASE=openvpn_log_browser

# Optional SAML 2.0 SSO.
SAML_ENABLED=false
SAML_REQUIRE_AUTH=false
SAML_SP_ENTITY_ID=openvpn-log-browser
SAML_CALLBACK_URL=https://logs.example.com/auth/saml/callback
SAML_ENTRY_POINT=https://idp.example.com/sso/saml
SAML_LOGOUT_URL=https://idp.example.com/slo/saml
SAML_IDP_CERT=<idp signing certificate>
SAML_AUDIENCE=
SAML_WANT_ASSERTIONS_SIGNED=true
SAML_WANT_RESPONSE_SIGNED=false
SAML_DISABLE_REQUESTED_AUTHN_CONTEXT=true
```

When MySQL/MariaDB is configured, the app uses it for two local caches:

- parsed, normalized log events keyed by S3 object fingerprint
- aggregate connected-user counts for licensing trend analysis

The parsed log index lets the app restart quickly without reparsing every `.jsonl.gz` object. S3 remains the source of truth; new or changed S3 objects are downloaded, parsed, and upserted into MariaDB.

When the parsed log index is available, search, stats, facets, record detail, and reconnect summaries are served from MariaDB instead of hydrating every event into Node.js memory.

The aggregate count history is stored in `connected_user_counts`. Samples older than 365 days are deleted automatically.

SAML settings can also be managed in the app from `Menu` -> `Settings`. The app exposes SP metadata at `/auth/saml/metadata` after SAML is configured.

## Log Source Settings

The setup menu supports two S3 fetch modes:

- `HTTP bucket listing` uses `S3_BUCKET_URL` and bucket policy/source-IP access.
- `S3 API with IAM credentials` uses `S3_BUCKET_NAME`, `AWS_REGION`, and the standard AWS SDK credential chain.

AWS secrets are not stored by the setup menu. If you use S3 API mode outside AWS, put credentials in the service environment file, for example:

```bash
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
```

If the app runs on EC2, prefer an instance role instead of access keys. The role or IAM user only needs `s3:ListBucket` for the bucket and `s3:GetObject` for the CloudConnexa log prefix.

Changing the log source in `Menu` -> `Settings` saves `data/settings/source.json`. Use Reload, restart the service, or wait for the next refresh to load from the new source.

## Refresh Behavior

The app refreshes logs in three ways:

- Click `Reload` in the UI.
- POST to `/api/reload`.
- Let the automatic 30-minute refresh run.

`AUTO_REFRESH_MINUTES` controls both the server background refresh interval and the browser idle refresh timer. The default is `30`. Set it to `0` to disable automatic refreshes.

For S3 sources, reloads are incremental. The app lists the bucket, compares each object's ETag, size, and last-modified timestamp, and downloads only new or changed objects. Unchanged objects reuse their in-memory parsed records while the server stays running, the MariaDB parsed-log index after a restart, or the local S3 object cache when an object needs to be reparsed.

The local S3 object cache is stored under `S3_CACHE_DIR`, which defaults to `data/s3-cache` inside the app directory. The cache stores gzipped log objects and `manifest.json`; protect this directory like VPN logs. It is ignored by Git.

After a service restart, the app hydrates from the MariaDB parsed-log index first, then refreshes S3 in the background. If MariaDB has no indexed copy of an unchanged object yet, the loader parses from the local S3 object cache where possible and only downloads objects missing from disk or changed in S3.

`FETCH_CONCURRENCY` controls how many new or changed S3 objects are downloaded in parallel. The default is `32`. Increase it only if the VM has spare CPU and memory; lower it if Node uses too much CPU or RSS during a cold load.

## Interface Notes

The main screen is split into a compact dashboard, filters, and the event list:

- `Active users` shows users and sessions whose latest connection-state event is connected and newer than `ACTIVE_SESSION_MAX_AGE_HOURS`.
- `Connected Users Over Time` shows aggregate connected-user counts. If MySQL is configured it reads the retained one-year count history; otherwise it derives the visible series from the loaded logs.
- `Reconnect Watch` shows the highest churn users in the last 24 hours. Each username is clickable and runs an event search for that user.
- The event table uses the full available width until an event is selected.
- Selecting an event opens the Event Detail pane. Selecting the same event again closes it.
- Event Detail includes normalized fields, a per-user reconnect summary, and redacted raw JSON.

Use `Menu` -> `Settings` for timezone and SAML configuration. The timezone selection affects displayed timestamps in the dashboard, table, and detail pane.

## MariaDB Storage

MySQL/MariaDB is optional. When configured, it creates and maintains a parsed log index:

```sql
log_s3_objects(source_hash, object_hash, object_key, fingerprint, parsed_at, record_count, ...)
log_events(id_hash, source_hash, object_hash, timestamp_dt, user_name, public_ip, raw_json, ...)
```

It also creates and maintains the aggregate count table:

```sql
CREATE TABLE IF NOT EXISTS connected_user_counts (
  sampled_at DATETIME NOT NULL PRIMARY KEY,
  connected_users INT NOT NULL,
  excluded_users INT NOT NULL
);
```

The app samples connected-user counts after log refreshes and deletes aggregate samples older than 365 days. This is intended for license-sizing trend analysis only.

The parsed log index contains normalized operational fields and raw event JSON so the app can search quickly after restart. Protect the MariaDB database as VPN log data.

## S3 Bucket Access

OpenVPN's CloudConnexa Log Streaming writes log files into an S3 bucket you own. Configure the bucket for CloudConnexa first using OpenVPN's current documentation:

- [Configure AWS S3 bucket for CloudConnexa Log Streaming](https://openvpn.net/cloud-docs/tutorials/configuration-tutorials/log-streaming/tutorial--configure-aws-s3-bucket-for-cloudconnexa-log-streaming.html)
- [About Log Streaming](https://openvpn.net/cloud-docs/owner/api---logs/api---logs---log-streaming/about-log-streaming.html)
- [Activate Log Streaming](https://openvpn.net/cloud-docs/owner/api---logs/api---logs---log-streaming/activate-log-streaming.html)
- [Customize the streamed log events](https://openvpn.net/cloud-docs/owner/api---logs/api---logs---log-streaming/customize-the-streamed-log-events.html)

The OpenVPN write policy and this browser's read policy are separate concerns:

- OpenVPN needs `s3:PutObject` and `s3:ListBucket` permissions so CloudConnexa can deliver logs.
- This browser only needs read-only access: `s3:ListBucket` on the bucket and `s3:GetObject` on the log objects.

Do not make the bucket public. Prefer one of these safer patterns:

- Run the browser on a VM with an IAM role that grants read-only access to only this bucket and prefix.
- If you must use a bucket policy with source IP restrictions, allow only a stable trusted egress IP or a narrow CIDR range.
- Keep the OpenVPN write statement scoped exactly as their docs specify, and keep your browser read statement separate.
- Use S3 Block Public Access unless you have a reviewed exception.
- Add lifecycle retention so VPN logs do not live forever.

Example read-only bucket-policy statement for this browser, restricted to one IP or CIDR:

```json
{
  "Sid": "AllowOpenVpnLogBrowserReadFromTrustedIp",
  "Effect": "Allow",
  "Principal": "*",
  "Action": [
    "s3:ListBucket"
  ],
  "Resource": "arn:aws:s3:::<BUCKET-NAME>",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": [
        "203.0.113.10/32",
        "198.51.100.0/24"
      ]
    },
    "StringLike": {
      "s3:prefix": [
        "CloudConnexa/<CLOUD-ID>/*"
      ]
    }
  }
}
```

```json
{
  "Sid": "AllowOpenVpnLogBrowserObjectReadFromTrustedIp",
  "Effect": "Allow",
  "Principal": "*",
  "Action": [
    "s3:GetObject"
  ],
  "Resource": "arn:aws:s3:::<BUCKET-NAME>/CloudConnexa/<CLOUD-ID>/*",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": [
        "203.0.113.10/32",
        "198.51.100.0/24"
      ]
    }
  }
}
```

Replace:

- `<BUCKET-NAME>` with your S3 bucket name.
- `<CLOUD-ID>` with your CloudConnexa Cloud ID/account folder.
- `203.0.113.10/32` with one trusted host IP, or `198.51.100.0/24` with a narrow trusted range. Remove whichever example you do not use.

Security note: IP-based bucket policies are useful for a small internal tool, but they are not identity. Anyone using that allowed egress path could potentially read objects permitted by this policy. For stronger security, combine source-IP conditions with an IAM principal or run the app on AWS with an instance role limited to this bucket prefix.

## Notes

- The app keeps logs in memory for fast filtering.
- S3 reloads keep a per-object parsed-record cache in memory, a MariaDB parsed-log index when configured, and a gzipped object cache under `data/s3-cache`.
- Search checks normalized fields and raw JSON across the full loaded log set.
- Connection logs are normalized into user, device, public IP, tunnel IP, OS, gateway, protocol, session ID, duration, transfer volume, and disconnect reason.
- The event list displays normalized operational fields and can be searched by username, IP, device, operation, gateway, trace ID, and other common fields.
- Display redacts secret-like keys such as `token`, `secret`, `password`, and `privateKey`.
- It does not redact ordinary operational fields such as username, email, timestamp, and IP address because those are the point of the admin search workflow.
- Log refresh can be triggered with the Reload button, the `/api/reload` endpoint, the server refresh interval, or the browser idle refresh timer.
