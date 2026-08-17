// GET /api/download?email=...&exp=...&token=...
// Re-verifies the signed token issued by /api/submit, then streams the PDF
// straight out of the private R2 bucket. The file is never publicly listed
// or guessable — this route is the only way to reach it.

const FILE_KEY = "know-the-name.pdf";
const FILE_NAME = "Know-The-Name-Brand-Generic-Reference-RudyOnMars.pdf";

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const email = (url.searchParams.get("email") || "").toLowerCase();
  const exp = parseInt(url.searchParams.get("exp") || "0", 10);
  const token = url.searchParams.get("token") || "";

  if (!email || !exp || !token) {
    return new Response("Missing or invalid download link.", { status: 400 });
  }
  if (Date.now() > exp) {
    return new Response("This download link has expired. Please go back and re-submit your email.", { status: 403 });
  }

  const expected = await sign(email, exp, env.DOWNLOAD_SECRET);
  if (!timingSafeEqual(expected, token)) {
    return new Response("Invalid download link.", { status: 403 });
  }

  const object = await env.PDF_BUCKET.get(FILE_KEY);
  if (!object) {
    return new Response("File not found. Please contact support.", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", "application/pdf");
  headers.set("Content-Disposition", `attachment; filename="${FILE_NAME}"`);
  headers.set("Cache-Control", "no-store");

  return new Response(object.body, { headers });
}

async function sign(email, expiry, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${email}:${expiry}`));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
