require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const cors = require("cors");
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

const app = express();

// ========================================================
// 📷 CONFIGURAR CLOUDINARY
// ========================================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

console.log("✅ Cloudinary configurado");

// ========================================================
// 📡 LOGS
// ========================================================
app.use((req, res, next) => {
  console.log(`➡️ ${req.method} ${req.url} - Origin: ${req.headers.origin}`);
  next();
});

// ========================================================
// 🔧 CORS
// ========================================================
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware JSON
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ========================================================
// 🔌 POSTGRES (🔥 AQUÍ ESTABA TU ERROR)
// ========================================================

// ❌ ANTES TENÍAS DB_USER, DB_PASSWORD, etc (ESO ROMPE RENDER)
// ✅ AHORA SOLO USAMOS DATABASE_URL (CORRECTO)

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect()
  .then(() => console.log("✅ DB conectada correctamente"))
  .catch(err => console.error("❌ Error conectando a DB:", err.message));

// ========================================================
// 🔐 AUTH MIDDLEWARE
// ========================================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  console.log("🔑 Auth header:", authHeader);

  if (!authHeader) {
    return res.status(401).json({ error: "Token requerido" });
  }

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("❌ Token inválido:", err.message);
    return res.status(401).json({ error: "Token inválido" });
  }
};

// ========================================================
// 📷 MULTER
// ========================================================
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Solo imágenes'));
    }
  }
});

// ========================================================
// ☁️ CLOUDINARY UPLOAD
// ========================================================
const uploadToCloudinary = (buffer, filename) => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: 'inmobiliaria',
        public_id: `${Date.now()}-${filename}`
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result.secure_url);
      }
    );
    stream.end(buffer);
  });
};

// ========================================================
// 👤 REGISTER
// ========================================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING id, name, email",
      [name, email, hashed]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🔐 LOGIN
// ========================================================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.status(400).json({ error: "Password incorrecta" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    const { password: _, ...userSafe } = user;

    res.json({ token, user: userSafe });

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 👥 USERS
// ========================================================
app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, role FROM users");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🏠 PROPERTIES (CREAR)
// ========================================================
app.post("/api/properties", authMiddleware, upload.array('images', 10), async (req, res) => {
  try {
    const { title, description, price } = req.body;

    let imageUrls = [];

    if (req.files && req.files.length > 0) {
      imageUrls = await Promise.all(
        req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
      );
    }

    const result = await pool.query(
      `INSERT INTO properties (title, description, price, images, user_id)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [
        title,
        description,
        price,
        JSON.stringify(imageUrls),
        req.user.id
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🏠 PROPERTIES (LISTAR)
// ========================================================
app.get("/api/properties", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM properties");

    const data = result.rows.map(p => ({
      ...p,
      images: p.images ? JSON.parse(p.images) : []
    }));

    res.json(data);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🧪 TEST DB
// ========================================================
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🚀 SERVER
// ========================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Servidor en http://localhost:${PORT}`);
});