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
// 📡 LOGS DE PETICIONES (globales)
// ========================================================
app.use((req, res, next) => {
  console.log(`\n➡️ ${req.method} ${req.url} - Origin: ${req.headers.origin || 'no-origin'}`);
  next();
});

// ========================================================
// 🔧 CORS - PERMITIR TODOS LOS ORÍGENES (SOLO PRUEBAS)
// ========================================================
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ========================================================
// 🔌 POSTGRES - CONEXIÓN PARA RENDER
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
// 🔐 MIDDLEWARE DE AUTENTICACIÓN (con logs)
// ========================================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log(`🔐 Auth - Header recibido: ${authHeader ? authHeader.substring(0, 30) + '...' : 'NINGUNO'}`);
  
  if (!authHeader) {
    console.log("❌ No hay header Authorization");
    return res.status(401).json({ error: "Token requerido" });
  }
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log(`✅ Token válido para usuario ID: ${decoded.id}`);
    next();
  } catch (err) {
    console.log(`❌ Token inválido: ${err.message}`);
    return res.status(401).json({ error: "Token inválido" });
  }
};

// ========================================================
// 👤 REGISTRO
// ========================================================
app.post("/api/auth/register", async (req, res) => {
  console.log("📝 Registro - Body:", { ...req.body, password: '***' });
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
    console.log(`✅ Usuario registrado: ${email}`);
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: "El email ya está registrado" });
    }
    console.error("❌ Error en registro:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🔐 LOGIN
// ========================================================
app.post("/api/auth/login", async (req, res) => {
  console.log("🔑 Login - Body:", { ...req.body, password: '***' });
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Usuario no encontrado" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Password incorrecta" });
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    const { password: _, ...userWithoutPassword } = user;
    console.log(`✅ Login exitoso: ${email}`);
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
  console.log("👥 Obteniendo usuarios...");
  try {
    const result = await pool.query("SELECT id, name, email, role FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error en GET /users:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/users/:id", authMiddleware, async (req, res) => {
  console.log(`🗑️ Eliminando usuario ID: ${req.params.id}`);
  try {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) {
      return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
    }
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    res.json({ message: "Usuario eliminado" });
  } catch (err) {
    console.error("❌ Error eliminando usuario:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🏠 PROPIEDADES - CREAR
// ========================================================
app.post("/api/properties", authMiddleware, upload.array('images', 10), async (req, res) => {
  console.log("🏠 Creando nueva propiedad - Body fields:", Object.keys(req.body));
  console.log(`📸 Archivos recibidos: ${req.files ? req.files.length : 0}`);
  try {
    const {
      title, description, price, province, city, street,
      bedrooms, bathrooms, area, propertytype, occupied, reo,
      lat, lng
    } = req.body;

    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      console.log("📤 Subiendo imágenes a Cloudinary...");
      imageUrls = await Promise.all(
        req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
      );
      console.log(`✅ Subidas ${imageUrls.length} imágenes`);
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

    console.log(`✅ Propiedad creada con ID: ${newProperty.id}`);
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
  console.log("🏠 Listando propiedades con filtros:", req.query);
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

    console.log(`📦 Enviando ${properties.length} propiedades`);
    res.json(properties);
  } catch (err) {
    console.error("❌ Error listando propiedades:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ✏️ ACTUALIZAR PROPIEDAD (CORREGIDO CON LOGS EXTENSIVOS)
// ========================================================
app.put("/api/properties/:id", authMiddleware, upload.array('images', 10), async (req, res) => {
  console.log(`\n✏️ ACTUALIZANDO propiedad ID: ${req.params.id}`);
  console.log("📝 Body fields recibidos:", Object.keys(req.body));
  console.log("📸 Archivos recibidos:", req.files ? req.files.length : 0);
  
  try {
    const { id } = req.params;
    
    // 1. Verificar que la propiedad existe
    const propExists = await pool.query("SELECT * FROM properties WHERE id = $1", [id]);
    if (!propExists.rows.length) {
      console.log(`❌ Propiedad ${id} no encontrada`);
      return res.status(404).json({ error: "La propiedad no existe" });
    }
    const property = propExists.rows[0];
    
    // 2. Verificar permisos (solo dueño o admin)
    const isAdmin = req.user.role === 'admin';
    if (!isAdmin && property.user_id !== req.user.id) {
      console.log(`❌ Usuario ${req.user.id} no puede editar propiedad ${id} (dueño: ${property.user_id})`);
      return res.status(403).json({ error: "No tienes permiso para editar esta propiedad" });
    }
    
    // 3. Preparar campos a actualizar (solo los que vienen en el body)
    const fields = { ...req.body };
    const validFields = [
      'title', 'description', 'price', 'province', 'city', 'street',
      'bedrooms', 'bathrooms', 'area', 'propertytype', 'occupied', 'reo',
      'lat', 'lng'
    ];
    
    const setClauses = [];
    const values = [];
    let paramIndex = 1;
    
    for (const field of validFields) {
      if (fields[field] !== undefined) {
        setClauses.push(`${field} = $${paramIndex}`);
        values.push(fields[field]);
        paramIndex++;
        console.log(`   Campo a actualizar: ${field} = ${fields[field]}`);
      }
    }
    
    // 4. Manejo de imágenes: combinar existentes + nuevas
    //    Nota: el frontend debe enviar 'existingImages' como string JSON con las URLs viejas que quiere conservar
    let existingImages = [];
    if (fields.existingImages) {
      try {
        existingImages = JSON.parse(fields.existingImages);
        console.log(`🖼️ Imágenes existentes a conservar: ${existingImages.length}`);
      } catch(e) {
        console.warn("❌ Error parseando existingImages:", e.message);
        existingImages = [];
      }
    } else {
      // Si no se envía existingImages, se asume que se quieren conservar las actuales
      existingImages = property.images ? JSON.parse(property.images) : [];
      console.log(`🖼️ No se envió existingImages, conservando las ${existingImages.length} imágenes actuales`);
    }
    
    let newImages = [];
    if (req.files && req.files.length > 0) {
      console.log(`📤 Subiendo ${req.files.length} imágenes nuevas a Cloudinary...`);
      newImages = await Promise.all(
        req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
      );
      console.log(`✅ Subidas ${newImages.length} imágenes nuevas`);
    }
    
    const allImages = [...existingImages, ...newImages];
    if (allImages.length > 0) {
      setClauses.push(`images = $${paramIndex}`);
      values.push(JSON.stringify(allImages));
      paramIndex++;
      console.log(`🖼️ Total imágenes final: ${allImages.length}`);
    } else if (fields.existingImages === undefined && !req.files?.length) {
      console.log("ℹ️ No se modificará el campo images");
    }
    
    if (setClauses.length === 0) {
      console.log("⚠️ No hay campos para actualizar");
      return res.status(400).json({ error: "No hay campos para actualizar" });
    }
    
    values.push(id);
    const query = `
      UPDATE properties
      SET ${setClauses.join(', ')}, updated_at = NOW()
      WHERE id = $${paramIndex}
      RETURNING *
    `;
    
    console.log("📝 Ejecutando query:", query);
    console.log("📦 Valores:", values);
    
    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      console.log(`❌ No se pudo actualizar propiedad ${id}`);
      return res.status(404).json({ error: "Propiedad no encontrada después de actualizar" });
    }
    
    const updatedProperty = result.rows[0];
    const userResult = await pool.query("SELECT id, name FROM users WHERE id = $1", [updatedProperty.user_id]);
    const agent = userResult.rows[0] || null;
    
    console.log(`✅ Propiedad ${id} actualizada correctamente`);
    res.json({
      ...updatedProperty,
      images: updatedProperty.images ? JSON.parse(updatedProperty.images) : [],
      agent: agent ? { id: agent.id, name: agent.name } : null
    });
  } catch (err) {
    console.error("❌ Error en actualización:", err.message);
    console.error(err.stack);
    // Asegurar que siempre devolvemos JSON
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    }
  }
});

// ========================================================
// ❌ ELIMINAR PROPIEDAD
// ========================================================
app.delete("/api/properties/:id", authMiddleware, async (req, res) => {
  console.log(`🗑️ Eliminando propiedad ID: ${req.params.id}`);
  try {
    await pool.query("DELETE FROM properties WHERE id=$1", [req.params.id]);
    res.json({ message: "Eliminado" });
  } catch (err) {
    console.error("❌ Error eliminando propiedad:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ❤️ FAVORITOS - AÑADIR
// ========================================================
app.post("/api/favorites/:id", authMiddleware, async (req, res) => {
  console.log(`❤️ Añadiendo favorito propiedad ${req.params.id} para usuario ${req.user.id}`);
  try {
    await pool.query(
      "INSERT INTO favorites (user_id, property_id) VALUES ($1,$2)",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Añadido a favoritos" });
  } catch (err) {
    console.error("❌ Error añadiendo favorito:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ❤️ FAVORITOS - LISTAR
// ========================================================
app.get("/api/favorites", authMiddleware, async (req, res) => {
  console.log(`❤️ Listando favoritos de usuario ${req.user.id}`);
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

    console.log(`📦 Enviando ${favorites.length} favoritos`);
    res.json(favorites);
  } catch (err) {
    console.error("❌ Error listando favoritos:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// ❤️ FAVORITOS - ELIMINAR
// ========================================================
app.delete("/api/favorites/:id", authMiddleware, async (req, res) => {
  console.log(`💔 Eliminando favorito propiedad ${req.params.id} para usuario ${req.user.id}`);
  try {
    const propertyId = req.params.id;
    const userId = req.user.id;

    const result = await pool.query(
      "DELETE FROM favorites WHERE user_id = $1 AND property_id = $2 RETURNING *",
      [userId, propertyId]
    );

    if (result.rowCount === 0) {
      console.log(`⚠️ Favorito no encontrado`);
      return res.status(404).json({ error: "Favorito no encontrado" });
    }

    res.json({ message: "Favorito eliminado correctamente" });
  } catch (err) {
    console.error("❌ Error eliminando favorito:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// 🧪 TEST
// ========================================================
app.get("/test-db", async (req, res) => {
  console.log("🧪 Test endpoint llamado");
  res.json({ message: "OK" });
});

// ========================================================
// 🌍 MIDDLEWARE GLOBAL DE MANEJO DE ERRORES (asegura JSON)
// ========================================================
app.use((err, req, res, next) => {
  console.error("🔥 ERROR GLOBAL NO CAPTURADO:", err);
  if (!res.headersSent) {
    res.status(500).json({ error: "Error interno del servidor", details: err.message });
  }
});

// ========================================================
// 🚀 SERVER
// ========================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor en http://localhost:${PORT}`);
});