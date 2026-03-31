require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const cors = require("cors");

const app = express();

// ========================================================
// 📡 LOGS para depuración
// ========================================================
app.use((req, res, next) => {
  console.log(`➡️ ${req.method} ${req.url} - Origin: ${req.headers.origin}`);
  next();
});

// ========================================================
// 🔧 CORS – Configuración correcta para Vite (puerto 5173)
// ========================================================
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware para parsear JSON y aumentar límite (para imágenes base64)
app.use(express.json({ limit: '10mb' }));

// ========================================================
// 🔌 POSTGRES
// ========================================================
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.connect()
  .then(() => console.log("✅ DB conectada"))
  .catch(err => console.error("❌ Error conectando a DB:", err.message));

// ========================================================
// 🔐 Middleware de autenticación
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
// 👤 REGISTRO
// ========================================================
app.post("/api/auth/register", async (req, res) => {
  console.log("📝 Recibido POST /api/auth/register", req.body);
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

    console.log("✅ Usuario registrado:", result.rows[0]);
    res.json(result.rows[0]);

  } catch (err) {
    console.error("❌ Error en registro:", err.message);
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
  console.log("🔐 POST /api/auth/login", req.body.email);
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ error: "Password incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    const { password: _, ...userWithoutPassword } = user;
    console.log("✅ Login exitoso:", user.email);
    res.json({ token, user: userWithoutPassword });

  } catch (err) {
    console.error("❌ Error en login:", err.message);
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
// 🏠 PROPIEDADES
// ========================================================
app.post("/api/properties", authMiddleware, async (req, res) => {
  try {
    const {
      title, description, price, province, city, street,
      bedrooms, bathrooms, area, propertytype, occupied, reo,
      lat, lng, images
    } = req.body;

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
        images ? JSON.stringify(images) : null,
        req.user.id
      ]
    );

    const newProperty = result.rows[0];
    const userResult = await pool.query(
      "SELECT id, name FROM users WHERE id = $1",
      [req.user.id]
    );
    const agent = userResult.rows[0] || null;

    res.json({
      ...newProperty,
      agent: agent ? { id: agent.id, name: agent.name } : null
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
      images: row.images,
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
// ✏️ ACTUALIZAR PROPIEDAD (dinámico)
// ========================================================
app.put("/api/properties/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const fields = req.body;

    // Lista de campos permitidos en la tabla properties
    const validFields = [
      'title', 'description', 'price', 'province', 'city', 'street',
      'bedrooms', 'bathrooms', 'area', 'propertytype', 'occupied', 'reo',
      'lat', 'lng', 'images'
    ];

    const setClauses = [];
    const values = [];
    let paramIndex = 1;

    for (const field of validFields) {
      if (fields.hasOwnProperty(field)) {
        let value = fields[field];
        // Convertir images a JSON string si existe
        if (field === 'images' && value !== undefined && value !== null) {
          value = JSON.stringify(value);
        }
        setClauses.push(`${field} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
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
    const userResult = await pool.query(
      "SELECT id, name FROM users WHERE id = $1",
      [updatedProperty.user_id]
    );
    const agent = userResult.rows[0] || null;

    res.json({
      ...updatedProperty,
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
      images: row.images,
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