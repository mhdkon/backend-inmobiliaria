require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const cors = require("cors");
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

const app = express();

// Configurar Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configuracion de Multer
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten archivos de imagen'), false);
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

// Logs globales
app.use((req, res, next) => {
  console.log(`\n${req.method} ${req.url} - Origin: ${req.headers.origin || 'no-origin'}`);
  next();
});

// CORS
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parser con limites altos
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log("DB conectada correctamente"))
  .catch(err => console.error("Error conectando a DB:", err.message));

// Crear tablas
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
    console.log("Tabla 'users' verificada/creada");

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
    console.log("Tabla 'properties' verificada/creada");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, property_id)
      )
    `);
    console.log("Tabla 'favorites' verificada/creada");

    console.log("Todas las tablas estan listas");
  } catch (err) {
    console.error("Error creando tablas:", err.message);
  }
};

initDB();

// Middleware de autenticacion
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
    return res.status(401).json({ error: "Token invalido" });
  }
};

// Registro
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

// Login
app.post("/api/auth/login", async (req, res) => {
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
    res.json({ token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Users (admin)
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

// Propiedades - Crear
app.post("/api/properties", authMiddleware, (req, res) => {
  upload.array('images', 10)(req, res, async (err) => {
    if (err) {
      console.error("Multer error en CREATE:", err);
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: `El archivo excede el tamaño maximo de ${MAX_FILE_SIZE / (1024*1024)} MB` });
      }
      return res.status(400).json({ error: err.message });
    }

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
      console.error("Error creando propiedad:", err.message);
      res.status(500).json({ error: err.message });
    }
  });
});

// Propiedades - Listar
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
    console.error("Error listando propiedades:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Actualizar propiedad
app.put("/api/properties/:id", authMiddleware, (req, res) => {
  upload.array('images', 10)(req, res, async (err) => {
    if (err) {
      console.error("Multer error en UPDATE:", err);
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: `El archivo es demasiado grande. Tamaño maximo: ${MAX_FILE_SIZE / (1024*1024)} MB` });
      }
      if (err.message === 'Solo se permiten archivos de imagen (JPEG, PNG, etc.)') {
        return res.status(400).json({ error: err.message });
      }
      return res.status(400).json({ error: `Error al procesar archivos: ${err.message}` });
    }

    try {
      const { id } = req.params;
      
      const propExists = await pool.query("SELECT * FROM properties WHERE id = $1", [id]);
      if (propExists.rows.length === 0) {
        return res.status(404).json({ error: "La propiedad no existe" });
      }
      const property = propExists.rows[0];

      const isAdmin = req.user.role === 'admin';
      if (!isAdmin && property.user_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permiso para editar esta propiedad" });
      }

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
        }
      }

      let existingImages = [];
      if (fields.existingImages) {
        try {
          existingImages = JSON.parse(fields.existingImages);
        } catch(e) { existingImages = []; }
      } else {
        existingImages = property.images ? JSON.parse(property.images) : [];
      }

      let newImages = [];
      if (req.files && req.files.length > 0) {
        newImages = await Promise.all(
          req.files.map(file => uploadToCloudinary(file.buffer, file.originalname))
        );
      }

      const allImages = [...existingImages, ...newImages];
      if (allImages.length > 0) {
        setClauses.push(`images = $${paramIndex}`);
        values.push(JSON.stringify(allImages));
        paramIndex++;
      }

      if (setClauses.length === 0) {
        return res.status(400).json({ error: "No hay campos para actualizar" });
      }

      values.push(id);
      const query = `
        UPDATE properties
        SET ${setClauses.join(', ')}, updated_at = NOW()
        WHERE id = $${paramIndex}
        RETURNING *
      `;

      const result = await pool.query(query, values);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "No se pudo actualizar la propiedad" });
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
      console.error("Error en actualizacion:", err.message);
      res.status(500).json({ error: err.message });
    }
  });
});

// Eliminar propiedad completa
app.delete("/api/properties/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM properties WHERE id=$1", [req.params.id]);
    res.json({ message: "Eliminado" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================
// NUEVO ENDPOINT: Eliminar una imagen de una propiedad
// ========================================================
app.delete("/api/properties/:id/images", authMiddleware, async (req, res) => {
  try {
    const propertyId = req.params.id;
    const { imageUrl } = req.body;  // Se espera la URL de la imagen a eliminar

    if (!imageUrl) {
      return res.status(400).json({ error: "Se requiere imageUrl en el body" });
    }

    // Obtener la propiedad
    const result = await pool.query("SELECT images, user_id FROM properties WHERE id = $1", [propertyId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Propiedad no encontrada" });
    }
    const property = result.rows[0];

    // Verificar permisos (admin o dueno de la propiedad)
    const isAdmin = req.user.role === 'admin';
    if (!isAdmin && property.user_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permiso para modificar esta propiedad" });
    }

    let images = property.images ? JSON.parse(property.images) : [];
    const newImages = images.filter(url => url !== imageUrl);

    if (images.length === newImages.length) {
      return res.status(404).json({ error: "La imagen no existe en esta propiedad" });
    }

    // Actualizar la propiedad con el nuevo array de imagenes
    await pool.query(
      "UPDATE properties SET images = $1, updated_at = NOW() WHERE id = $2",
      [JSON.stringify(newImages), propertyId]
    );

    res.json({ message: "Imagen eliminada correctamente", images: newImages });
  } catch (err) {
    console.error("Error eliminando imagen:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Favoritos
app.post("/api/favorites/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO favorites (user_id, property_id) VALUES ($1,$2)",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Anadido a favoritos" });
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

app.delete("/api/favorites/:id", authMiddleware, async (req, res) => {
  try {
    const propertyId = req.params.id;
    const userId = req.user.id;
    const result = await pool.query(
      "DELETE FROM favorites WHERE user_id = $1 AND property_id = $2 RETURNING *",
      [userId, propertyId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Favorito no encontrado" });
    }
    res.json({ message: "Favorito eliminado" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Test
app.get("/test-db", async (req, res) => {
  res.json({ message: "OK" });
});

// Middleware global de errores
app.use((err, req, res, next) => {
  console.error("Error global no capturado:", err);
  if (!res.headersSent) {
    res.status(500).json({ error: "Error interno del servidor", details: err.message });
  }
});

// Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});