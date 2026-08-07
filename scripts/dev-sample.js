const path = require("node:path");

// Isolated local dev/testing entry point: deliberately points at a bogus bucket so it
// can never reach the real S3 source, regardless of network/IP allowlisting. Only
// synthetic data placed under RAW_DIR is ever loaded.
process.env.PORT = process.env.PORT || "3991";
process.env.RAW_DIR = process.env.RAW_DIR || path.join(__dirname, "..", "data", "raw");
process.env.ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || "dev-token";
process.env.S3_BUCKET_URL = "https://invalid-bucket-do-not-use.example.invalid/";
process.env.S3_BUCKET_NAME = "invalid-bucket-do-not-use";
process.env.LOG_PREFIX = "none/";

require("../server.js");
