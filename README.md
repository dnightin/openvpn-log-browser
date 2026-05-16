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
https://<BUCKET-NAME>.s3.us-east-1.amazonaws.com/
```

If the current machine cannot list the bucket, run it on `ospf1` or place `.jsonl.gz` files under `data/raw/` and start again.

## Environment

```text
PORT=3000
S3_BUCKET_URL=https://<BUCKET-NAME>.s3.us-east-1.amazonaws.com/
LOG_PREFIX=CloudConnexa/wellesley/
RAW_DIR=data/raw
AUTO_REFRESH_MINUTES=30
ACTIVE_SESSION_MAX_AGE_HOURS=72

# Optional MySQL aggregate count storage.
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=openvpn_log_browser
MYSQL_PASSWORD=<password>
MYSQL_DATABASE=openvpn_log_browser
```

When MySQL is configured, the app stores only aggregate licensing telemetry:

- sample timestamp
- connected user count
- excluded reconnect-heavy user count

The `connected_user_counts` table contains only those three columns.
No usernames, IPs, session IDs, raw logs, or event payloads are written to MySQL. Samples older than 365 days are deleted automatically.

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
- Search checks common fields and raw JSON.
- Connection logs are normalized into user, device, public IP, tunnel IP, OS, gateway, protocol, session ID, duration, transfer volume, and disconnect reason.
- Display redacts secret-like keys such as `token`, `secret`, `password`, and `privateKey`.
- It does not redact ordinary operational fields such as username, email, timestamp, and IP address because those are the point of the admin search workflow.
