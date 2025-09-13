const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

/**
 * Helper: HMAC SHA256
 */
function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

/**
 * Helper: SHA256 Hash Hex
 */
function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * URL encode for x-www-form-urlencoded safely
 */
function urlencodeFormComponent(value) {
  return encodeURIComponent(value);
}

/**
 * Normalize newlines for SES friendliness
 */
function normalizeNewlines(v) {
  return typeof v === "string" ? v.replace(/\r\n/g, "\n") : v;
}

app.post("/sign-ses-request", (req, res) => {
  try {
    const {
      aws_access_key_id,
      aws_secret_access_key,
      aws_region,
      source,
      recipient,
      subject,
      body_text,
      body_html,
    } = req.body || {};

    if (!aws_access_key_id || !aws_secret_access_key || !aws_region) {
      return res.status(400).json({ error: "Missing AWS credentials or region" });
    }
    if (!source || !recipient || !subject) {
      return res.status(400).json({ error: "Missing source, recipient, or subject" });
    }

    const service = "ses";
    const host = `email.${aws_region}.amazonaws.com`;
    const endpoint = `https://${host}/`;

    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // e.g., 20250913T135959Z
    const dateStamp = amzDate.slice(0, 8); // e.g., 20250913

    // Build the x-www-form-urlencoded body with safe encoding
    const bodyParts = [
      `Action=SendEmail`,
      `Source=${urlencodeFormComponent(source)}`,
      `Destination.ToAddresses.member.1=${urlencodeFormComponent(recipient)}`,
      `Message.Subject.Data=${urlencodeFormComponent(subject)}`,
    ];

    const normalizedText = normalizeNewlines(body_text);
    const normalizedHtml = normalizeNewlines(body_html);

    if (normalizedText) {
      bodyParts.push(`Message.Body.Text.Data=${urlencodeFormComponent(normalizedText)}`);
    }

    if (normalizedHtml) {
      bodyParts.push(`Message.Body.Html.Data=${urlencodeFormComponent(normalizedHtml)}`);
    }

    const body = bodyParts.join("&");

    // Create canonical request
    const canonicalHeaders =
      `content-type:application/x-www-form-urlencoded\n` +
      `host:${host}\n` +
      `x-amz-date:${amzDate}\n`;

    const signedHeaders = "content-type;host;x-amz-date";

    const canonicalRequest = [
      "POST",
      "/",
      "",
      canonicalHeaders,
      signedHeaders,
      sha256Hex(body),
    ].join("\n");

    // Create string to sign
    const credentialScope = `${dateStamp}/${aws_region}/${service}/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      sha256Hex(canonicalRequest),
    ].join("\n");

    // Calculate signature
    const kDate = hmac(`AWS4${aws_secret_access_key}`, dateStamp);
    const kRegion = hmac(kDate, aws_region);
    const kService = hmac(kRegion, service);
    const kSigning = hmac(kService, "aws4_request");
    const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");

    const authorization =
      `AWS4-HMAC-SHA256 ` +
      `Credential=${aws_access_key_id}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, ` +
      `Signature=${signature}`;

    // Respond with signed headers and body
    // Note: Most HTTP clients set Host automatically; include it only if your client requires it.
    res.json({
      endpoint,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": amzDate,
        "Authorization": authorization,
        // "Host": host, // optional; uncomment only if your HTTP client doesn't set Host
      },
      body,
    });
  } catch (err) {
    console.error("Signing error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SES signer running on port ${PORT}`);
});
