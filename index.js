require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

// =========================
// 🔌 CONEXIÓN A POSTGRES
// =========================
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.connect()
  .then(() => console.log("✅ Base de datos conectada correctamente"))
  .catch(err => console.error("❌ Error DB:", err));

// =========================
// 🔐 JWT MIDDLEWARE
// =========================
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido" });
  }
};

// =========================
// 👤 REGISTER
// =========================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    res.json(result.rows[0]);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 🔐 LOGIN
// =========================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, user });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 🏠 CREAR PROPIEDAD
// =========================
app.post("/api/properties", authMiddleware, async (req, res) => {
  try {
    const {
      title,
      price,
      province,
      city,
      bedrooms,
      bathrooms,
      propertytype,
      occupied,
      reo
    } = req.body;

    if (!title || !price) {
      return res.status(400).json({ error: "Faltan datos obligatorios" });
    }

    const result = await pool.query(
      `INSERT INTO properties 
      (title, price, province, city, bedrooms, bathrooms, propertytype, occupied, reo, user_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING *`,
      [
        title,
        price,
        province,
        city,
        bedrooms,
        bathrooms,
        propertytype,
        occupied,
        reo,
        req.user.id
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 📥 OBTENER PROPIEDADES (CON FILTROS)
// =========================
app.get("/api/properties", async (req, res) => {
  try {
    const { province, city, propertytype } = req.query;

    let query = "SELECT * FROM properties WHERE 1=1";
    let values = [];

    if (province) {
      values.push(province);
      query += ` AND province = $${values.length}`;
    }

    if (city) {
      values.push(city);
      query += ` AND city = $${values.length}`;
    }

    if (propertytype) {
      values.push(propertytype);
      query += ` AND propertytype = $${values.length}`;
    }

    const result = await pool.query(query, values);

    res.json(result.rows);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// ✏️ ACTUALIZAR PROPIEDAD
// =========================
app.put("/api/properties/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, price } = req.body;

    const result = await pool.query(
      "UPDATE properties SET title=$1, price=$2 WHERE id=$3 RETURNING *",
      [title, price, id]
    );

    res.json(result.rows[0]);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// ❌ ELIMINAR PROPIEDAD
// =========================
app.delete("/api/properties/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query("DELETE FROM properties WHERE id=$1", [id]);

    res.json({ message: "Propiedad eliminada" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 🧪 TEST DB
// =========================
app.get("/test-db", async (req, res) => {
  try {
    await pool.query("SELECT NOW()");
    res.json({ message: "Base de datos conectada ✅" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 🚀 SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});