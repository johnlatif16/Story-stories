import jwt from "jsonwebtoken";
import { URL } from "node:url";
import Busboy from "busboy";
import { put } from "@vercel/blob";
import admin from "firebase-admin";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "password";

// ---------- Firestore init (Admin SDK) ----------
function getFirestore() {
  if (!admin.apps.length) {
    // Option A (recommended): separate env vars
    if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
        }),
      });
    }
    // Option B: single FIREBASE_CONFIG JSON env var (string)
    else if (process.env.FIREBASE_CONFIG) {
      const cfg = JSON.parse(process.env.FIREBASE_CONFIG);
      // Expect cfg = { projectId, clientEmail, privateKey }
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: cfg.projectId,
          clientEmail: cfg.clientEmail,
          privateKey: String(cfg.privateKey || "").replace(/\\n/g, "\n"),
        }),
      });
    } else {
      throw new Error(
        "Missing Firestore credentials. Set FIREBASE_PROJECT_ID/FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY or FIREBASE_CONFIG"
      );
    }
  }
  return admin.firestore();
}

// ---------- helpers ----------
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

function safeFilename(name) {
  const base = String(name || "image").replace(/[^a-zA-Z0-9._-]/g, "_");
  return base.slice(0, 120);
}

// ---------- API handler ----------
export default async function handler(req, res) {
  cors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  const url = new URL(req.url, "http://localhost");

  // normalize: /api/... and /...
  const pathname = url.pathname || "/";
  const p = pathname.startsWith("/api/") ? pathname.slice(4) : pathname;

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
              contentType: mimeType || undefined,
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
    try {
      const db = getFirestore();

      // orderBy + limit: documented (:contentReference[oaicite:2]{index=2})
      const snap = await db.collection("news").orderBy("createdAt", "desc").limit(200).get();

      const news = snap.docs.map((d) => {
        const data = d.data();

        // createdAt ممكن يبقى Timestamp
        const createdAt =
          data?.createdAt?.toDate?.() instanceof Date ? data.createdAt.toDate().toISOString() : data?.createdAt;

        return { id: d.id, ...data, createdAt };
      });

      return json(res, 200, { ok: true, news });
    } catch (e) {
      console.error(e);
      return json(res, 500, { ok: false, error: e?.message || "Failed to load news" });
    }
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

    try {
      const db = getFirestore();

      // Add data: documented (:contentReference[oaicite:3]{index=3})
      const docRef = await db.collection("news").add({
        text,
        source,
        imageUrl,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return json(res, 201, {
        ok: true,
        item: { id: docRef.id, text, source, imageUrl, createdAt: new Date().toISOString() },
      });
    } catch (e) {
      console.error(e);
      return json(res, 500, { ok: false, error: e?.message || "Failed to add news" });
    }
  }

  // ===== Admin: delete news =====
  if (p.startsWith("/news/") && req.method === "DELETE") {
    const v = verifyJWT(req);
    if (!v.ok) return unauthorized(res);

    const id = p.split("/").pop();
    if (!id) return badRequest(res, "id is required");

    try {
      const db = getFirestore();
      await db.collection("news").doc(id).delete();
      return json(res, 200, { ok: true });
    } catch (e) {
      console.error(e);
      return json(res, 500, { ok: false, error: e?.message || "Failed to delete news" });
    }
  }

  return notFound(res);
}
