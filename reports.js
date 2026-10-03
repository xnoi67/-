// Vercel Serverless Function — /api/reports
// ต้องตั้ง Environment Variables: KV_REST_API_URL + KV_REST_API_TOKEN (หรือ UPSTASH_REDIS_REST_URL/TOKEN) และ REPORT_SALT (ข้อความสุ่มยาว ๆ)
const crypto = require("crypto");
const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SALT = process.env.REPORT_SALT || "";
const TYPES = ["power", "help", "flood", "fire"];
const H = x => crypto.createHmac("sha256", SALT).update(String(x)).digest("hex").slice(0, 32);
const clean = (s, n) => String(s || "").replace(/[\u0000-\u001f\u007f<>]/g, " ").trim().slice(0, n);

async function redis(cmds) {
  const r = await fetch(URL_ + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + TOK, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new Error("redis " + r.status);
  return (await r.json()).map(x => x.result);
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (!URL_ || !TOK || SALT.length < 16) return res.status(503).json({ error: "server not configured" });

  try {
    if (req.method === "GET") {
      const [list] = await redis([["LRANGE", "reports", 0, 299]]);
      const cut = Date.now() - 24 * 3600e3;
      const reports = (list || []).map(s => { try { return JSON.parse(s); } catch (e) { return null; } })
        .filter(r => r && r.t > cut);
      return res.status(200).json({ reports });
    }

    if (req.method !== "POST") return res.status(405).json({ error: "method" });

    // อนุญาตเฉพาะการส่งจากโดเมนเดียวกับเว็บ
    const origin = req.headers.origin || "";
    try { if (new URL(origin).host !== req.headers.host) throw 0; } catch (e) { return res.status(403).json({ error: "origin" }); }

    const b = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    if (!b || JSON.stringify(b).length > 2000) return res.status(413).json({ error: "size" });
    const lat = Number(b.lat), lon = Number(b.lon);
    if (!TYPES.includes(b.type) || !(lat >= -90 && lat <= 90) || !(lon >= -180 && lon <= 180)) return res.status(400).json({ error: "invalid" });
    if (!/^[0-9a-f-]{36}$/.test(String(b.dev))) return res.status(400).json({ error: "device" });
    if (b.website) return res.status(200).json({ ok: true }); // honeypot สำหรับบอท

    // จำกัดความถี่: ต่อ IP, ต่ออุปกรณ์, และรวมทั้งระบบ
    const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const ih = H("ip" + ip), dh = H("dev" + b.dev), hr = Math.floor(Date.now() / 3600e3);
    const rl = await redis([
      ["INCR", "rl:ip:" + ih], ["EXPIRE", "rl:ip:" + ih, 60],
      ["INCR", "rl:dev:" + dh], ["EXPIRE", "rl:dev:" + dh, 60],
      ["INCR", "rl:all:" + hr], ["EXPIRE", "rl:all:" + hr, 3600],
    ]);
    if (rl[0] > 5 || rl[2] > 3 || rl[4] > 600) return res.status(429).json({ error: "rate" });

    // เลขผู้ใช้: อุปกรณ์แรก = 1, ถัดไป = 2 ... อุปกรณ์เดิมได้เลขเดิมเสมอ
    let [u] = await redis([["HGET", "devs", dh]]);
    if (!u) {
      const [n] = await redis([["INCR", "devseq"]]);
      await redis([["HSETNX", "devs", dh, n]]);
      [u] = await redis([["HGET", "devs", dh]]);
    }

    const rep = { type: b.type, lat, lon, place: clean(b.place, 120), note: clean(b.note, 300), t: Date.now(), u: Number(u) };
    await redis([["LPUSH", "reports", JSON.stringify(rep)], ["LTRIM", "reports", 0, 499]]);
    return res.status(200).json({ ok: true, u: rep.u });
  } catch (e) {
    return res.status(500).json({ error: "server" });
  }
};
