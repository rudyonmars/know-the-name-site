// POST /api/submit
// No database, no storage bucket, no bindings of any kind — this only
// needs one plain environment variable (WEB3FORMS_ACCESS_KEY).
//
// Validates the lead, verifies Turnstile, pulls geolocation automatically
// from Cloudflare's edge (no extra field needed), forwards the lead to
// Web3Forms (free — every submission lands in your inbox), and returns
// the static download link.

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
    const city = geo.city || "Unknown";
    const region = geo.regionCode || geo.region || "Unknown";
    const country = geo.country || "Unknown";

    // --- forward the lead to Web3Forms (free — no database needed) ---------
    if (env.WEB3FORMS_ACCESS_KEY) {
      await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          access_key: env.WEB3FORMS_ACCESS_KEY,
          subject: "New Know The Name. download",
          from_name: "Know The Name landing page",
          name: name,
          email: email,
          location: `${city}, ${region}, ${country}`,
        }),
      });
      // Note: intentionally not blocking on Web3Forms' response — if their
      // service hiccups, the visitor should still get their download.
    }

    return json({ success: true, downloadUrl: "/know-the-name.pdf" });

  } catch (err) {
    return json({ success: false, error: "Server error. Please try again shortly." }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
