import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { nanoid } from "nanoid";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// مهم: في Vercel لازم تخدم public من المسار الصحيح (خارج api)
const PUBLIC_DIR = path.join(__dirname, "..", "public");
app.use(express.static(PUBLIC_DIR));

// على Vercel الكتابة تكون في /tmp فقط
const TMP_ROOT = "/tmp/news_site";
const UPLOADS_DIR = path.join(TMP_ROOT, "uploads");
const DATA_PATH = path.join(TMP_ROOT, "data.json");

// Serve uploaded files (مؤقتة)
app.use("/uploads", express.static(UPLOADS_DIR));

// --- Basic config / env ---
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || "";

// --- Ensure temp storage exists ---
function ensureStore() {
  if (!fs.existsSync(TMP_ROOT)) fs.mkdirSync(TMP_ROOT, { recursive: true });
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  if (!fs.existsSync(DATA_PATH)) {
    fs.writeFileSync(DATA_PATH, JSON.stringify({ posts: [] }, null, 2), "utf8");
  }
}
ensureStore();

function readDB() {
  ensureStore();
  return JSON.parse(fs.readFileSync(DATA_PATH, "utf8"));
}
function writeDB(db) {
  ensureStore();
  fs.writeFileSync(DATA_PATH, JSON.stringify(db, null, 2), "utf8");
}

// --- Auth helpers ---
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}

// --- Multer upload -> /tmp ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureStore();
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}_${nanoid(10)}${ext || ".jpg"}`);
  }
});

function fileFilter(req, file, cb) {
  const ok = ["image/jpeg", "image/png", "image/webp", "image/gif"].includes(file.mimetype);
  cb(ok ? null : new Error("Only images allowed"), ok);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 6 * 1024 * 1024 }
});

// --- API ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (!ADMIN_PASS_HASH) return res.status(500).json({ error: "Server not configured (ADMIN_PASS_HASH missing)" });
  if (username !== ADMIN_USER) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, ADMIN_PASS_HASH);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  return res.json({ token: signToken({ username }) });
});

app.get("/api/me", authRequired, (req, res) => {
  res.json({ user: { username: req.user.username } });
});

app.get("/api/posts", (req, res) => {
  const db = readDB();
  const posts = (db.posts || []).slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.post("/api/posts", authRequired, upload.single("image"), (req, res) => {
  const { title, body, sourceUrl } = req.body || {};
  if (!title) return res.status(400).json({ error: "Title is required" });

  const db = readDB();
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : "";

  const post = {
    id: nanoid(12),
    title: String(title),
    body: body ? String(body) : "",
    sourceUrl: sourceUrl ? String(sourceUrl) : "",
    imageUrl,
    createdAt: new Date().toISOString()
  };

  db.posts = db.posts || [];
  db.posts.unshift(post);
  writeDB(db);

  res.status(201).json({ post });
});

app.delete("/api/posts/:id", authRequired, (req, res) => {
  const { id } = req.params;
  const db = readDB();
  const before = db.posts?.length || 0;

  const post = (db.posts || []).find(p => p.id === id);
  db.posts = (db.posts || []).filter(p => p.id !== id);
  writeDB(db);

  // حذف الصورة المؤقتة (best-effort)
  if (post?.imageUrl?.startsWith("/uploads/")) {
    const filePath = path.join(UPLOADS_DIR, path.basename(post.imageUrl));
    fs.unlink(filePath, () => {});
  }

  res.json({ deleted: before - db.posts.length });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

// صفحات نظيفة بدون .html
app.get("/login", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "login.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "dashboard.html")));
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// مهم: على Vercel ما تعملش listen()
// صدّر app كـ handler
export default app;
