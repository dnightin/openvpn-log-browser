# OpenVPN Log Search

Small, dependency-free web app for authorized CloudConnexa/OpenVPN audit logs stored as gzipped JSONL in S3.

## Run

```powershell
node server.js
```

Then open `http://localhost:3000`.

You can also verify ingestion without starting the web server:

```powershell
node server.js --ingest
```

By default the app reads from:

```text
https://wc-openvpnlogs.s3.us-east-1.amazonaws.com/
```

If the current machine cannot list the bucket, run it on `ospf1` or place `.jsonl.gz` files under `data/raw/` and start again.

## Environment

```text
PORT=3000
S3_BUCKET_URL=https://wc-openvpnlogs.s3.us-east-1.amazonaws.com/
LOG_PREFIX=CloudConnexa/wellesley/
RAW_DIR=data/raw
```

## Notes

- The app keeps logs in memory for fast filtering.
- Search checks common fields and raw JSON.
- Connection logs are normalized into user, device, public IP, tunnel IP, OS, gateway, protocol, session ID, duration, transfer volume, and disconnect reason.
- Display redacts secret-like keys such as `token`, `secret`, `password`, and `privateKey`.
- It does not redact ordinary operational fields such as username, email, timestamp, and IP address because those are the point of the admin search workflow.
