// controles.js
const db = require('./db');               // tu conexión PostgreSQL
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

// Configura Cloudinary (con tus credenciales de .env)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configura multer en memoria (para pasar el buffer a Cloudinary)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB por imagen
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Solo imágenes'), false);
  }
});

// Middleware para manejar 'images' field (máximo 10 archivos)
const uploadImages = upload.array('images', 10);

// Función auxiliar: subir un buffer a Cloudinary
const uploadToCloudinary = (buffer, folder = 'properties') => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder, resource_type: 'auto' },
      (error, result) => {
        if (error) reject(error);
        else resolve(result.secure_url);
      }
    );
    uploadStream.end(buffer);
  });
};

// =====================================================
// ACTUALIZAR PROPIEDAD (PUT /api/properties/:id)
// =====================================================
const updateProperty = async (req, res) => {
  // 1. Procesar multer manualmente con Promise para capturar errores de subida
  try {
    await new Promise((resolve, reject) => {
      uploadImages(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  } catch (multerError) {
    console.error('Multer error:', multerError);
    return res.status(400).json({ error: `Error en las imágenes: ${multerError.message}` });
  }

  const { id } = req.params;
  const { 
    title, description, price, province, city, street,
    bedrooms, bathrooms, area, propertytype, occupied, reo,
    lat, lng
  } = req.body;

  // Validar campos obligatorios
  if (!title || !price || !province || !city || !street) {
    return res.status(400).json({ error: 'Faltan campos requeridos (título, precio, provincia, ciudad, calle)' });
  }

  try {
    // 2. Verificar existencia de la propiedad
    const propExists = await db.query('SELECT * FROM properties WHERE id = $1', [id]);
    if (!propExists || !propExists.rows || propExists.rows.length === 0) {
      return res.status(404).json({ error: "La propiedad no existe" });
    }

    const property = propExists.rows[0];
    const userId = req.user.id;      // debe venir del middleware auth
    const userRole = req.user.role;

    // Permisos: solo el dueño o admin
    if (property.user_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: "No autorizado para editar esta propiedad" });
    }

    // 3. Obtener imágenes existentes (array de URLs)
    let existingImages = [];
    if (property.images) {
      try {
        existingImages = typeof property.images === 'string' ? JSON.parse(property.images) : property.images;
      } catch(e) { existingImages = []; }
    }

    // 4. Subir nuevas imágenes a Cloudinary si las hay
    let newImageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file => uploadToCloudinary(file.buffer));
      newImageUrls = await Promise.all(uploadPromises);
    }

    // Combinar imágenes existentes + nuevas
    const allImages = [...existingImages, ...newImageUrls];

    // 5. Actualizar en base de datos
    const result = await db.query(
      `UPDATE properties SET
        title = $1, description = $2, price = $3, province = $4, city = $5, street = $6,
        bedrooms = $7, bathrooms = $8, area = $9, propertytype = $10,
        occupied = $11, reo = $12, lat = $13, lng = $14, images = $15,
        updated_at = NOW()
      WHERE id = $16
      RETURNING *`,
      [
        title, description, price, province, city, street,
        bedrooms, bathrooms, area, propertytype,
        occupied === 'true' || occupied === true,
        reo === 'true' || reo === true,
        lat || null, lng || null,
        JSON.stringify(allImages),
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No se pudo actualizar la propiedad' });
    }

    // 6. Respuesta JSON exitosa
    return res.status(200).json({
      message: 'Propiedad actualizada correctamente',
      property: result.rows[0]
    });

  } catch (error) {
    console.error('Error en updateProperty:', error);
    return res.status(500).json({ error: `Error interno: ${error.message}` });
  }
};

// =====================================================
// CREAR PROPIEDAD (POST /api/properties)
// =====================================================
const createProperty = async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      uploadImages(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  } catch (multerError) {
    return res.status(400).json({ error: `Error en imágenes: ${multerError.message}` });
  }

  const { title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng } = req.body;
  const userId = req.user.id;

  if (!title || !price || !province || !city || !street) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file => uploadToCloudinary(file.buffer));
      imageUrls = await Promise.all(uploadPromises);
    }

    const result = await db.query(
      `INSERT INTO properties 
        (title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng, images, user_id, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
      RETURNING *`,
      [title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied === 'true' || occupied === true, reo === 'true' || reo === true, lat || null, lng || null, JSON.stringify(imageUrls), userId]
    );

    res.status(201).json({ message: 'Propiedad creada', property: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// =====================================================
// ELIMINAR PROPIEDAD (DELETE /api/properties/:id)
// =====================================================
const deleteProperty = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query('DELETE FROM properties WHERE id = $1 RETURNING id', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Propiedad no encontrada' });
    }
    res.json({ message: 'Propiedad eliminada' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Exporta todas las funciones
module.exports = {
  updateProperty,
  createProperty,
  deleteProperty,
  // ... otras funciones como getProperties, getPropertyById
};