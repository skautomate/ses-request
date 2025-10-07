const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function urlencodeFormComponent(value) {
  return encodeURIComponent(value);
}

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
      body_html,
      configuration_set_name,
      custom_headers,
      // --- 1. RECEIVE THE NEW PREHEADER ---
      preheader,
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
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.slice(0, 8);

    // --- 2. LOGIC TO ADD THE PREHEADER TO THE HTML ---
    let finalHtml = normalizeNewlines(body_html);
    if (preheader && finalHtml) {
        // This is the standard way to add a preheader. It's a hidden element
        // at the start of the body that email clients show in the preview.
        const preheaderHtml = `
          <div style="display: none; max-height: 0px; overflow: hidden;">
            ${preheader}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
          </div>
        `;
        // Insert it right after the opening <body> tag
        finalHtml = finalHtml.replace(/<body.*?>/i, `$&${preheaderHtml}`);
    }


    const bodyParts = [
      `Action=SendEmail`,
      `Source=${urlencodeFormComponent(source)}`,
      `Destination.ToAddresses.member.1=${urlencodeFormComponent(recipient)}`,
      `Message.Subject.Data=${urlencodeFormComponent(subject)}`,
    ];

    if (finalHtml) {
      bodyParts.push(`Message.Body.Html.Data=${urlencodeFormComponent(finalHtml)}`);
    }
    
    if (configuration_set_name) {
      bodyParts.push(`ConfigurationSetName=${urlencodeFormComponent(configuration_set_name)}`);
    }

    if (custom_headers && typeof custom_headers === 'object') {
        let headerIndex = 1;
        for (const [name, value] of Object.entries(custom_headers)) {
            bodyParts.push(`Headers.member.${headerIndex}.Name=${urlencodeFormComponent(name)}`);
            bodyParts.push(`Headers.member.${headerIndex}.Value=${urlencodeFormComponent(value)}`);
            headerIndex++;
        }
    }

    const body = bodyParts.join("&");

    // The rest of the signing logic remains exactly the same
    const canonicalHeaders =
      `content-type:application/x-www-form-urlencoded\n` +
      `host:${host}\n` +
      `x-amz-date:${amzDate}\n`;
    const signedHeaders = "content-type;host;x-amz-date";
    const canonicalRequest = ["POST", "/", "", canonicalHeaders, signedHeaders, sha256Hex(body)].join("\n");
    const credentialScope = `${dateStamp}/${aws_region}/${service}/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, sha256Hex(canonicalRequest)].join("\n");
    const kDate = hmac(`AWS4${aws_secret_access_key}`, dateStamp);
    const kRegion = hmac(kDate, aws_region);
    const kService = hmac(kRegion, service);
    const kSigning = hmac(kService, "aws4_request");
    const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");
    const authorization =
      `AWS4-HMAC-SHA256 Credential=${aws_access_key_id}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    res.json({
      endpoint,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": amzDate,
        "Authorization": authorization,
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
