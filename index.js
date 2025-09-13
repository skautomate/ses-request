const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

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
 * Ensures all special characters in text or HTML do not break query string
 */
function urlencodeFormComponent(value) {
  return encodeURIComponent(value);
}

app.post("/sign-ses-request", (req, res) => {
  const {
    aws_access_key_id,
    aws_secret_access_key,
    aws_region,
    source,
    recipient,
    subject,
    body_text,
    body_html,
  } = req.body;

  const service = "ses";
  const host = `email.${aws_region}.amazonaws.com`;
  const endpoint = `https://${host}/`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);

  // Build the x-www-form-urlencoded body with safe encoding
  const bodyParts = [
    `Action=SendEmail`,
    `Source=${urlencodeFormComponent(source)}`,
    `Destination.ToAddresses.member.1=${urlencodeFormComponent(recipient)}`,
    `Message.Subject.Data=${urlencodeFormComponent(subject)}`,
  ];

  if (body_text) {
    bodyParts.push(`Message.Body.Text.Data=${urlencodeFormComponent(body_text)}`);
  }

  if (body_html) {
    bodyParts.push(`Message.Body.Html.Data=${urlencodeFormComponent(body_html)}`);
  }

  const body = bodyParts.join("&");

  // Create canonical request
  const canonicalRequest = [
    "POST",
    "/",
    "",
    `content-type:application/x-www-form-urlencoded\nhost:${host}\nx-amz-date:${amzDate}\n`,
    "content-type;host;x-amz-date",
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

  const authorization = `AWS4-HMAC-SHA256 Credential=${aws_access_key_id}/${credentialScope}, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`;

  // Respond with signed headers and body
  res.json({
    endpoint,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Amz-Date": amzDate,
      "Authorization": authorization,
      "host": host,
    },
    body,
  });
});

app.listen(3000, () => {
  console.log("SES signer running on port 3000");
});
