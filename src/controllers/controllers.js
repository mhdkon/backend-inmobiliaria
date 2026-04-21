const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const { normalizeImages } = require("../utils/utils");
const fs = require("fs");
const path = require("path");

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Faltan campos" });
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'user') RETURNING id, name, email, role",
      [name, email, hashed]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: "Email ya registrado" });
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Usuario no encontrado" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Password incorrecta" });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
};

const getUsers = async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, role FROM users ORDER BY id");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
};

const deleteUser = async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    res.json({ message: "Usuario eliminado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
};

const createProperty = async (req, res) => {
  try {
    let { title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng } = req.body;
    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      imageUrls = req.files.map(file => `/uploads/${file.filename}`);
    } else if (req.body.images) {
      let rawImages = req.body.images;
      if (typeof rawImages === 'string') {
        try { rawImages = JSON.parse(rawImages); } catch(e) {}
      }
      if (Array.isArray(rawImages)) imageUrls = rawImages;
      else if (rawImages && typeof rawImages === 'string') imageUrls = [rawImages];
    }
    const imagesToSave = imageUrls.length ? JSON.stringify(imageUrls) : null;
    const result = await pool.query(
      `INSERT INTO properties (title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng, images, user_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [title, description || '', price, province, city, street, bedrooms || 0, bathrooms || 0, area || 0, propertytype || 'casa', occupied || false, reo || false, lat || null, lng || null, imagesToSave, req.user.id]
    );
    const newProperty = result.rows[0];
    const userResult = await pool.query("SELECT id, name, email FROM users WHERE id = $1", [req.user.id]);
    const agent = userResult.rows[0] || null;
    res.json({
      ...newProperty,
      price: parseFloat(newProperty.price),
      images: normalizeImages(newProperty.images),
      agent: agent ? { id: agent.id, name: agent.name, email: agent.email } : null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
};

const getProperties = async (req, res) => {
  try {
    const { province, city, propertytype, priceMin, priceMax, bedrooms, bathrooms, occupied, reo, page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let query = `
      SELECT p.*, u.id as agent_id, u.name as agent_name, u.email as agent_email
      FROM properties p LEFT JOIN users u ON p.user_id = u.id WHERE 1=1
    `;
    let values = []; let paramCount = 1;
    if (province) { values.push(province); query += ` AND p.province = $${paramCount++}`; }
    if (city) { values.push(city); query += ` AND p.city = $${paramCount++}`; }
    if (propertytype) { values.push(propertytype); query += ` AND p.propertytype = $${paramCount++}`; }
    if (priceMin) { values.push(priceMin); query += ` AND p.price >= $${paramCount++}`; }
    if (priceMax) { values.push(priceMax); query += ` AND p.price <= $${paramCount++}`; }
    if (bedrooms) { values.push(bedrooms); query += ` AND p.bedrooms >= $${paramCount++}`; }
    if (bathrooms) { values.push(bathrooms); query += ` AND p.bathrooms >= $${paramCount++}`; }
    if (occupied !== undefined && occupied !== '') { values.push(occupied === "true"); query += ` AND p.occupied = $${paramCount++}`; }
    if (reo !== undefined && reo !== '') { values.push(reo === "true"); query += ` AND p.reo = $${paramCount++}`; }
    const countQuery = query.replace(/SELECT p\.\*, u\.id as agent_id, u\.name as agent_name, u\.email as agent_email/, "SELECT COUNT(*)");
    const countResult = await pool.query(countQuery, values);
    const total = parseInt(countResult.rows[0].count);
    query += ` ORDER BY p.created_at DESC LIMIT $${paramCount} OFFSET $${paramCount+1}`;
    values.push(parseInt(limit), offset);
    const result = await pool.query(query, values);
    const properties = result.rows.map(row => ({
      ...row, price: parseFloat(row.price), lat: row.lat ? parseFloat(row.lat) : null, lng: row.lng ? parseFloat(row.lng) : null,
      images: normalizeImages(row.images), agent: row.agent_id ? { id: row.agent_id, name: row.agent_name, email: row.agent_email } : null
    }));
    res.json({ data: properties, pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const getPropertyById = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT p.*, u.id as agent_id, u.name as agent_name, u.email as agent_email FROM properties p LEFT JOIN users u ON p.user_id = u.id WHERE p.id = $1`, [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Propiedad no encontrada" });
    const row = result.rows[0];
    res.json({
      ...row, price: parseFloat(row.price), lat: row.lat ? parseFloat(row.lat) : null, lng: row.lng ? parseFloat(row.lng) : null,
      images: normalizeImages(row.images), agent: row.agent_id ? { id: row.agent_id, name: row.agent_name, email: row.agent_email } : null
    });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const updateProperty = async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const userId = req.user.id, userRole = req.user.role;
    const propResult = await pool.query("SELECT user_id, images FROM properties WHERE id = $1", [propertyId]);
    if (propResult.rows.length === 0) return res.status(404).json({ error: "Propiedad no encontrada" });
    if (userRole !== 'admin' && propResult.rows[0].user_id !== userId) return res.status(403).json({ error: "No tienes permiso" });
    let currentImages = propResult.rows[0].images ? JSON.parse(propResult.rows[0].images) : [];
    let newImageUrls = req.files?.map(f => `/uploads/${f.filename}`) || [];
    let updatedImages = currentImages;
    if (req.body.images) {
      let raw = req.body.images;
      if (typeof raw === 'string') try { raw = JSON.parse(raw); } catch(e) {}
      if (Array.isArray(raw)) updatedImages = raw;
    }
    if (newImageUrls.length) updatedImages = [...updatedImages, ...newImageUrls];
    const imagesToSave = updatedImages.length ? JSON.stringify(updatedImages) : null;
    const { title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng } = req.body;
    const result = await pool.query(
      `UPDATE properties SET title=COALESCE($1,title), description=COALESCE($2,description), price=COALESCE($3,price), province=COALESCE($4,province), city=COALESCE($5,city), street=COALESCE($6,street), bedrooms=COALESCE($7,bedrooms), bathrooms=COALESCE($8,bathrooms), area=COALESCE($9,area), propertytype=COALESCE($10,propertytype), occupied=COALESCE($11,occupied), reo=COALESCE($12,reo), lat=COALESCE($13,lat), lng=COALESCE($14,lng), images=COALESCE($15,images), updated_at=NOW() WHERE id=$16 RETURNING *`,
      [title, description, price, province, city, street, bedrooms, bathrooms, area, propertytype, occupied, reo, lat, lng, imagesToSave, propertyId]
    );
    const updated = result.rows[0];
    const userResult = await pool.query("SELECT id, name, email FROM users WHERE id=$1", [updated.user_id]);
    res.json({ ...updated, price: parseFloat(updated.price), images: normalizeImages(updated.images), agent: userResult.rows[0] || null });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const deleteProperty = async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const userId = req.user.id, userRole = req.user.role;
    const propResult = await pool.query("SELECT user_id, images FROM properties WHERE id=$1", [propertyId]);
    if (propResult.rows.length === 0) return res.status(404).json({ error: "Propiedad no encontrada" });
    if (userRole !== 'admin' && propResult.rows[0].user_id !== userId) return res.status(403).json({ error: "No tienes permiso" });
    const images = propResult.rows[0].images ? JSON.parse(propResult.rows[0].images) : [];
    for (const img of images) {
      if (img.startsWith('/uploads/')) {
        const filePath = path.join(__dirname, "../../", img);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
    }
    await pool.query("DELETE FROM properties WHERE id=$1", [propertyId]);
    res.json({ message: "Propiedad eliminada" });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const addFavorite = async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const propExists = await pool.query("SELECT id FROM properties WHERE id=$1", [propertyId]);
    if (propExists.rows.length === 0) return res.status(404).json({ error: "La propiedad no existe" });
    await pool.query("INSERT INTO favorites (user_id, property_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [req.user.id, propertyId]);
    res.json({ message: "Añadido a favoritos" });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const getFavorites = async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.id as agent_id, u.name as agent_name, u.email as agent_email FROM favorites f JOIN properties p ON p.id=f.property_id LEFT JOIN users u ON p.user_id=u.id WHERE f.user_id=$1 ORDER BY f.created_at DESC`, [req.user.id]
    );
    const favorites = result.rows.map(row => ({ ...row, price: parseFloat(row.price), images: normalizeImages(row.images), agent: row.agent_id ? { id: row.agent_id, name: row.agent_name, email: row.agent_email } : null }));
    res.json(favorites);
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const removeFavorite = async (req, res) => {
  try {
    await pool.query("DELETE FROM favorites WHERE user_id=$1 AND property_id=$2", [req.user.id, parseInt(req.params.id)]);
    res.json({ message: "Eliminado de favoritos" });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
};

const uploadImages = async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: "No se enviaron archivos" });
    const urls = req.files.map(file => `/uploads/${file.filename}`);
    res.json({ urls });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error al subir archivos" }); }
};

module.exports = {
  register, login, getUsers, deleteUser, createProperty, getProperties, getPropertyById,
  updateProperty, deleteProperty, addFavorite, getFavorites, removeFavorite, uploadImages
};