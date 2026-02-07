import fs from "node:fs";
import path from "node:path";
import jwt from "jsonwebtoken";
import { URL } from "node:url";
import Busboy from "busboy";
import { put } from "@vercel/blob";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "password";

const DATA_PATH = path.join(process.cwd(), "data.json");

// كاش مؤقت (غير مضمون على Vercel)
let runtimeNewsCache = null;

function readNewsFromFile() {
  try {
    const raw = fs.readFileSync(DATA_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed.news) ? parsed.news : [];
  } catch {
    return [];
  }
}

function writeNewsToFile(newsArray) {
  try {
    fs.writeFileSync(DATA_PATH, JSON.stringify({ news: newsArray }, null, 2), "utf8");
  } catch {
    // على Vercel غالبًا هتفشل (read-only) فبنطنّش
  }
}

function getAllNews() {
  const fileNews = readNewsFromFile();
  const cacheNews = Array.isArray(runtimeNewsCache) ? runtimeNewsCache : [];

  const seen = new Set();
  const merged = [];

  for (const n of [...cacheNews, ...fileNews]) {
    if (!n?.id || seen.has(n.id)) continue;
    seen.add(n.id);
    merged.push(n);
  }

  merged.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return merged;
}

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

function badRequest(res, msg) {
  return json(res, 400, { ok: false, error: msg });
}

function unauthorized(res, msg = "Unauthorized") {
  return json(res, 401, { ok: false, error: msg });
}

function notFound(res) {
  return json(res, 404, { ok: false, error: "Not found" });
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function verifyJWT(req) {
  const auth = req.headers.authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return { ok: false };
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    return { ok: true, payload };
  } catch {
    return { ok: false };
  }
}

function makeId() {
  return "n_" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function safeFilename(name) {
  const base = String(name || "image").replace(/[^a-zA-Z0-9._-]/g, "_");
  return base.slice(0, 120);
}

export default async function handler(req, res) {
  cors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  const url = new URL(req.url, "http://localhost");

  // ✅ التطبيع: لو الريكويست جالك /api/upload أو /upload الاتنين يبقوا نفس المسار الداخلي
  const pathname = url.pathname || "/";
  const p = pathname.startsWith("/api/") ? pathname.slice(4) : pathname; // يشيل "/api"

  // ===== Health =====
  if (p === "/health" && req.method === "GET") {
    return json(res, 200, { ok: true, status: "up" });
  }

  // ===== Login =====
  if (p === "/login" && req.method === "POST") {
    let bodyText = "";
    try {
      bodyText = await readBody(req);
    } catch {
      return badRequest(res, "Failed to read body");
    }

    let body;
    try {
      body = JSON.parse(bodyText || "{}");
    } catch {
      return badRequest(res, "Body must be JSON");
    }

    const { username, password } = body || {};
    if (username !== ADMIN_USER || password !== ADMIN_PASSWORD) {
      return unauthorized(res, "Invalid credentials");
    }

    const token = jwt.sign({ sub: username, role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
    return json(res, 200, { ok: true, token });
  }

  // ===== Admin: upload image (multipart/form-data) =====
  if (p === "/upload" && req.method === "POST") {
    const v = verifyJWT(req);
    if (!v.ok) return unauthorized(res);

    const bb = Busboy({ headers: req.headers });
    let uploadPromise = null;

    bb.on("file", (fieldname, file, info) => {
      const { filename, mimeType } = info || {};
      const chunks = [];

      file.on("data", (d) => chunks.push(d));

      uploadPromise = new Promise((resolve, reject) => {
        file.on("end", async () => {
          try {
            const buffer = Buffer.concat(chunks);
            if (!buffer.length) return reject(new Error("Empty file"));

            const key = `uploads/${Date.now()}-${safeFilename(filename)}`;

            const blob = await put(key, buffer, {
              access: "public",
              addRandomSuffix: true,
              contentType: mimeType || undefined
            });

            resolve(blob);
          } catch (e) {
            reject(e);
          }
        });

        file.on("error", reject);
      });
    });

    bb.on("error", (e) => {
      console.error(e);
      return badRequest(res, "Upload parse error");
    });

    bb.on("finish", async () => {
      try {
        if (!uploadPromise) return badRequest(res, "No file provided (field: image)");
        const blob = await uploadPromise;
        return json(res, 200, { ok: true, url: blob.url });
      } catch (e) {
        console.error(e);
        return json(res, 500, { ok: false, error: e?.message || "Upload failed" });
      }
    });

    req.pipe(bb);
    return;
  }

  // ===== Public: list news =====
  if (p === "/news" && req.method === "GET") {
    const news = getAllNews();
    return json(res, 200, { ok: true, news });
  }

  // ===== Admin: add news =====
  if (p === "/news" && req.method === "POST") {
    const v = verifyJWT(req);
    if (!v.ok) return unauthorized(res);

    let bodyText = "";
    try {
      bodyText = await readBody(req);
    } catch {
      return badRequest(res, "Failed to read body");
    }

    let body;
    try {
      body = JSON.parse(bodyText || "{}");
    } catch {
      return badRequest(res, "Body must be JSON");
    }

    const text = String(body?.text || "").trim();
    const source = String(body?.source || "").trim();
    const imageUrl = String(body?.imageUrl || "").trim();

    if (!text) return badRequest(res, "text is required");

    const item = {
      id: makeId(),
      text,
      source,
      imageUrl,
      createdAt: new Date().toISOString()
    };

    if (!Array.isArray(runtimeNewsCache)) runtimeNewsCache = [];
    runtimeNewsCache.unshift(item);

    // محاولة كتابة للملف (قد تفشل على Vercel)
    try {
      const fileNews = readNewsFromFile();
      writeNewsToFile([item, ...fileNews]);
    } catch {}

    return json(res, 201, { ok: true, item });
  }

  // ===== Admin: delete news =====
  if (p.startsWith("/news/") && req.method === "DELETE") {
    const v = verifyJWT(req);
    if (!v.ok) return unauthorized(res);

    const id = p.split("/").pop();
    if (!id) return badRequest(res, "id is required");

    // حذف من الكاش
    if (Array.isArray(runtimeNewsCache)) {
      runtimeNewsCache = runtimeNewsCache.filter((n) => n.id !== id);
    }

    // محاولة حذف من data.json
    try {
      const fileNews = readNewsFromFile().filter((n) => n.id !== id);
      writeNewsToFile(fileNews);
    } catch {}

    return json(res, 200, { ok: true });
  }

  return notFound(res);
}
