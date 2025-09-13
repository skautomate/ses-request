const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
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

  const bodyParts = [
    "Action=SendEmail",
    `Source=${source}`,
    `Destination.ToAddresses.member.1=${recipient}`,
    `Message.Subject.Data=${subject}`,
  ];

  if (body_text) {
    bodyParts.push(`Message.Body.Text.Data=${body_text}`);
  }

  if (body_html) {
    bodyParts.push(`Message.Body.Html.Data=${body_html}`);
  }

  const body = bodyParts.join("&");

  const canonicalRequest = [
    "POST",
    "/",
    "",
    `content-type:application/x-www-form-urlencoded\nhost:${host}\nx-amz-date:${amzDate}\n`,
    "content-type;host;x-amz-date",
    crypto.createHash("sha256").update(body).digest("hex"),
  ].join("\n");

  const credentialScope = `${dateStamp}/${aws_region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");

  const kDate = hmac(`AWS4${aws_secret_access_key}`, dateStamp);
  const kRegion = hmac(kDate, aws_region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = crypto
    .createHmac("sha256", kSigning)
    .update(stringToSign)
    .digest("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${aws_access_key_id}/${credentialScope}, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`;

  res.json({
    endpoint,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Amz-Date": amzDate,
      Authorization: authorization,
    },
    body,
  });
});

app.listen(3000, () => {
  console.log("SES signer running on port 3000");
});
