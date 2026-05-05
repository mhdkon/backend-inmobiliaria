// controles.js
const db = require('./db');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Solo imágenes'), false);
  }
});

const uploadImages = upload.array('images', 10);

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

  if (!title || !price || !province || !city || !street) {
    return res.status(400).json({ error: 'Faltan campos requeridos (título, precio, provincia, ciudad, calle)' });
  }

  try {
    const propExists = await db.query('SELECT * FROM properties WHERE id = $1', [id]);
    if (!propExists || !propExists.rows || propExists.rows.length === 0) {
      return res.status(404).json({ error: "La propiedad no existe" });
    }

    const property = propExists.rows[0];
    const userId = req.user.id;
    const userRole = req.user.role;

    if (property.user_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: "No autorizado para editar esta propiedad" });
    }

    let existingImages = [];
    if (property.images) {
      try {
        existingImages = typeof property.images === 'string' ? JSON.parse(property.images) : property.images;
      } catch(e) { existingImages = []; }
    }

    let newImageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file => uploadToCloudinary(file.buffer));
      newImageUrls = await Promise.all(uploadPromises);
    }

    // Concatenar imágenes existentes con las nuevas (las eliminaciones se hacen vía endpoint aparte)
    const allImages = [...existingImages, ...newImageUrls];

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

// =====================================================
// NUEVO: ELIMINAR IMÁGENES DE UNA PROPIEDAD (DELETE /api/properties/:id/images)
// =====================================================
const deleteImageFromProperty = async (req, res) => {
  const { id } = req.params;
  const { imagesToDelete } = req.body;

  if (!imagesToDelete || !Array.isArray(imagesToDelete) || imagesToDelete.length === 0) {
    return res.status(400).json({ error: 'Se requiere un array imagesToDelete con las URLs a eliminar' });
  }

  try {
    // Verificar propiedad
    const propResult = await db.query('SELECT * FROM properties WHERE id = $1', [id]);
    if (propResult.rows.length === 0) {
      return res.status(404).json({ error: 'Propiedad no encontrada' });
    }
    const property = propResult.rows[0];
    const userId = req.user.id;
    const userRole = req.user.role;
    if (property.user_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: 'No autorizado para modificar esta propiedad' });
    }

    // Obtener array actual de imágenes
    let currentImages = [];
    if (property.images) {
      try {
        currentImages = typeof property.images === 'string' ? JSON.parse(property.images) : property.images;
      } catch(e) {
        currentImages = [];
      }
    }

    // Filtrar las que no están en imagesToDelete
    const newImages = currentImages.filter(imgUrl => !imagesToDelete.includes(imgUrl));

    // Opcional: eliminar de Cloudinary las imágenes borradas (se puede hacer extrayendo public_id)
    // Aquí no lo implementamos para no complicar, pero es recomendable.

    // Actualizar la base de datos
    await db.query(
      'UPDATE properties SET images = $1, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(newImages), id]
    );

    res.json({ message: 'Imágenes eliminadas correctamente', images: newImages });
  } catch (error) {
    console.error('Error en deleteImageFromProperty:', error);
    res.status(500).json({ error: error.message });
  }
};

// Exportar todas las funciones
module.exports = {
  updateProperty,
  createProperty,
  deleteProperty,
  deleteImageFromProperty,
  // si tienes más (getProperties, getPropertyById, etc.) agréguelas aquí
};