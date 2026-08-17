// POST /api/submit
// Validates the lead, verifies Turnstile, pulls geolocation automatically
// from Cloudflare's edge (no extra field needed), stores the lead in D1,
// and returns a short-lived signed download URL.

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const name = (body.name || "").trim();
    const email = (body.email || "").trim().toLowerCase();
    const turnstileToken = body.turnstileToken || "";

    // --- basic validation -------------------------------------------------
    if (!name || name.length > 200) {
      return json({ success: false, error: "Please enter your name." }, 400);
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      return json({ success: false, error: "Please enter a valid email address." }, 400);
    }

    // --- verify Turnstile (spam protection) --------------------------------
    if (env.TURNSTILE_SECRET_KEY) {
      const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: turnstileToken,
          remoteip: request.headers.get("CF-Connecting-IP") || "",
        }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyData.success) {
        return json({ success: false, error: "Spam check failed. Please try again." }, 400);
      }
    }

    // --- automatic geolocation, straight from Cloudflare's edge ------------
    // No form field needed — this comes free with every request.
    const geo = request.cf || {};
    const city = geo.city || null;
    const region = geo.regionCode || geo.region || null;
    const country = geo.country || null;
    const postal = geo.postalCode || null;
    const timezone = geo.timezone || null;

    const now = new Date().toISOString();

    // --- store the lead in D1 ----------------------------------------------
    await env.DB.prepare(
      `INSERT INTO leads (name, email, city, region, country, postal, timezone, download_count, first_seen, last_seen)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8)
       ON CONFLICT(email) DO UPDATE SET
         name = excluded.name,
         city = excluded.city,
         region = excluded.region,
         country = excluded.country,
         postal = excluded.postal,
         timezone = excluded.timezone,
         download_count = download_count + 1,
         last_seen = excluded.last_seen`
    ).bind(name, email, city, region, country, postal, timezone, now).run();

    // --- issue a short-lived signed download token --------------------------
    const expiry = Date.now() + 15 * 60 * 1000; // 15 minutes
    const token = await sign(email, expiry, env.DOWNLOAD_SECRET);

    const downloadUrl = `/api/download?email=${encodeURIComponent(email)}&exp=${expiry}&token=${token}`;

    return json({ success: true, downloadUrl });

  } catch (err) {
    return json({ success: false, error: "Server error. Please try again shortly." }, 500);
  }
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

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
