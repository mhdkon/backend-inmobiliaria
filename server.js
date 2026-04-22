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

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten imágenes'));
    }
  }
});

const uploadToCloudinary = (fileBuffer, filename) => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        resource_type: 'auto',
        public_id: `inmobiliaria/${Date.now()}-${filename}`,
        folder: 'inmobiliaria'
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result.secure_url);
      }
    );
    stream.end(fileBuffer);
  });
};

// ========================================================
// 📡 LOGS
// ========================================================
app.use((req, res, next) => {
  console.log(`➡️ ${req.method} ${req.url} - Origin: ${req.headers.origin}`);
  next();
});

// ========================================================
// 🔧 CORS - PERMITIR MÚLTIPLES ORÍGENES
// ========================================================
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  process.env.FRONTEND_URL,        // Tu dominio de Netlify (si está definido)
].filter(Boolean);                 // Elimina valores undefined

app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origen (como Postman, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn(`❌ Origen bloqueado por CORS: ${origin}`);
      return callback(new Error('No permitido por CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ========================================================
// 🔌 POSTGRES - CONEXIÓN PARA RENDER (usando DATABASE_URL)
// ========================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log("✅ DB conectada correctamente"))
  .catch(err => console.error("❌ Error conectando a DB:", err.message));

// ========================================================
// 🔨 CREAR TABLAS AUTOMÁTICAMENTE
// ========================================================
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log("✅ Tabla 'users' verificada/creada");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS properties (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        description TEXT,
        price NUMERIC(10,2) NOT NULL,
        province VARCHAR(100),
        city VARCHAR(100),
        street VARCHAR(200),
        bedrooms INTEGER,
        bathrooms INTEGER,
        area NUMERIC(8,2),
        propertytype VARCHAR(50),
        occupied BOOLEAN DEFAULT FALSE,
        reo BOOLEAN DEFAULT FALSE,
        lat NUMERIC(10,6),
        lng NUMERIC(10,6),
        images TEXT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log("✅ Tabla 'properties' verificada/creada");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, property_id)
      )
    `);
    console.log("✅ Tabla 'favorites' verificada/creada");

    console.log("🎉 Todas las tablas están listas");
  } catch (err) {
    console.error("❌ Error creando tablas:", err.message);
  }
};

initDB();

// ========================================================
// 🔐 MIDDLEWARE DE AUTENTICACIÓN
// ========================================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
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
    return res.status(401).json({ error: "Token inválido" });
  }
};

// ========================================================
// 👤 REGISTRO
// ========================================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING id, name, email, role",
      [name, email, hashed]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: "El email ya está registrado" });
    }
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🔐 LOGIN
// ========================================================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Usuario no encontrado" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Password incorrecta" });
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 👥 USERS (solo admin)
// ========================================================
app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, role FROM users");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) {
      return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
    }
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    res.json({ message: "Usuario eliminado" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🏠 PROPIEDADES - CREAR
// ========================================================
app.post("/api/properties", authMiddleware, upload.array('images', 10), async (req, res) => {
  try {
    const {
      title, description, price, province, city, street,
      bedrooms, bathrooms, area, propertytype, occupied, reo,
      lat, lng
    } = req.body;

    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      imageUrls = await Promise.all(
        req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
      );
    }

    const result = await pool.query(
      `INSERT INTO properties (
        title, description, price, province, city, street,
        bedrooms, bathrooms, area, propertytype,
        occupied, reo, lat, lng, images, user_id
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      RETURNING *`,
      [
        title, description, price, province, city, street,
        bedrooms, bathrooms, area, propertytype,
        occupied, reo, lat, lng,
        imageUrls.length > 0 ? JSON.stringify(imageUrls) : null,
        req.user.id
      ]
    );

    const newProperty = result.rows[0];
    const userResult = await pool.query("SELECT id, name FROM users WHERE id = $1", [req.user.id]);
    const agent = userResult.rows[0] || null;

    res.json({
      ...newProperty,
      images: imageUrls,
      agent: agent ? { id: agent.id, name: agent.name } : null
    });
  } catch (err) {
    console.error("❌ Error creando propiedad:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🏠 PROPIEDADES - LISTAR CON FILTROS
// ========================================================
app.get("/api/properties", async (req, res) => {
  try {
    const {
      province, city, propertytype, priceMin, priceMax,
      bedrooms, bathrooms, occupied, reo
    } = req.query;

    let query = `
      SELECT p.*, u.id as agent_id, u.name as agent_name
      FROM properties p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE 1=1
    `;
    let values = [];

    if (province) {
      values.push(province);
      query += ` AND p.province = $${values.length}`;
    }
    if (city) {
      values.push(city);
      query += ` AND p.city = $${values.length}`;
    }
    if (propertytype) {
      values.push(propertytype);
      query += ` AND p.propertytype = $${values.length}`;
    }
    if (priceMin) {
      values.push(priceMin);
      query += ` AND p.price >= $${values.length}`;
    }
    if (priceMax) {
      values.push(priceMax);
      query += ` AND p.price <= $${values.length}`;
    }
    if (bedrooms) {
      values.push(bedrooms);
      query += ` AND p.bedrooms >= $${values.length}`;
    }
    if (bathrooms) {
      values.push(bathrooms);
      query += ` AND p.bathrooms >= $${values.length}`;
    }
    if (occupied !== undefined) {
      values.push(occupied === "true");
      query += ` AND p.occupied = $${values.length}`;
    }
    if (reo !== undefined) {
      values.push(reo === "true");
      query += ` AND p.reo = $${values.length}`;
    }

    const result = await pool.query(query, values);
    const properties = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      description: row.description,
      price: row.price,
      province: row.province,
      city: row.city,
      street: row.street,
      bedrooms: row.bedrooms,
      bathrooms: row.bathrooms,
      area: row.area,
      propertytype: row.propertytype,
      occupied: row.occupied,
      reo: row.reo,
      lat: row.lat,
      lng: row.lng,
      images: row.images ? JSON.parse(row.images) : [],
      user_id: row.user_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      agent: row.agent_id ? { id: row.agent_id, name: row.agent_name } : null
    }));

    res.json(properties);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ✏️ ACTUALIZAR PROPIEDAD
// ========================================================
app.put("/api/properties/:id", authMiddleware, upload.array('images', 10), async (req, res) => {
  try {
    const { id } = req.params;
    const fields = req.body;
    const validFields = [
      'title', 'description', 'price', 'province', 'city', 'street',
      'bedrooms', 'bathrooms', 'area', 'propertytype', 'occupied', 'reo',
      'lat', 'lng'
    ];

    const setClauses = [];
    const values = [];
    let paramIndex = 1;

    for (const field of validFields) {
      if (fields.hasOwnProperty(field)) {
        setClauses.push(`${field} = $${paramIndex}`);
        values.push(fields[field]);
        paramIndex++;
      }
    }

    if (req.files && req.files.length > 0) {
      const imageUrls = await Promise.all(
        req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
      );
      setClauses.push(`images = $${paramIndex}`);
      values.push(JSON.stringify(imageUrls));
      paramIndex++;
    }

    if (setClauses.length === 0) {
      return res.status(400).json({ error: "No hay campos para actualizar" });
    }

    values.push(id);
    const query = `
      UPDATE properties
      SET ${setClauses.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Propiedad no encontrada" });
    }

    const updatedProperty = result.rows[0];
    const userResult = await pool.query("SELECT id, name FROM users WHERE id = $1", [updatedProperty.user_id]);
    const agent = userResult.rows[0] || null;

    res.json({
      ...updatedProperty,
      images: updatedProperty.images ? JSON.parse(updatedProperty.images) : [],
      agent: agent ? { id: agent.id, name: agent.name } : null
    });
  } catch (err) {
    console.error("❌ Error en actualización:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ❌ ELIMINAR PROPIEDAD
// ========================================================
app.delete("/api/properties/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM properties WHERE id=$1", [req.params.id]);
    res.json({ message: "Eliminado" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ❤️ FAVORITOS
// ========================================================
app.post("/api/favorites/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO favorites (user_id, property_id) VALUES ($1,$2)",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Añadido a favoritos" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.id as agent_id, u.name as agent_name
       FROM favorites f
       JOIN properties p ON p.id = f.property_id
       LEFT JOIN users u ON p.user_id = u.id
       WHERE f.user_id = $1`,
      [req.user.id]
    );

    const favorites = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      description: row.description,
      price: row.price,
      province: row.province,
      city: row.city,
      street: row.street,
      bedrooms: row.bedrooms,
      bathrooms: row.bathrooms,
      area: row.area,
      propertytype: row.propertytype,
      occupied: row.occupied,
      reo: row.reo,
      lat: row.lat,
      lng: row.lng,
      images: row.images ? JSON.parse(row.images) : [],
      user_id: row.user_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      agent: row.agent_id ? { id: row.agent_id, name: row.agent_name } : null
    }));

    res.json(favorites);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🧪 TEST
// ========================================================
app.get("/test-db", async (req, res) => {
  res.json({ message: "OK" });
});

// ========================================================
// 🚀 SERVER
// ========================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor en http://localhost:${PORT}`);
});