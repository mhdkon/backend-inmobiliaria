const multer = require("multer");
const path = require("path");
const fs = require("fs");

const uploadDir = path.join(__dirname, "../../uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});

const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif|webp/;
  const ok = allowed.test(path.extname(file.originalname).toLowerCase()) && allowed.test(file.mimetype);
  ok ? cb(null, true) : cb(new Error("Solo imágenes (jpeg, png, gif, webp)"));
};

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });

const normalizeImages = (images) => {
  if (!images) return null;
  if (Array.isArray(images)) {
    const valid = images.filter(img => img && typeof img === 'string' && (img.startsWith('data:image') || img.startsWith('http') || img.startsWith('/uploads/')));
    return valid.length ? valid : null;
  }
  if (typeof images === 'string') {
    if (images.startsWith('[')) {
      try {
        const parsed = JSON.parse(images);
        if (Array.isArray(parsed)) {
          const valid = parsed.filter(img => img && typeof img === 'string' && (img.startsWith('data:image') || img.startsWith('http') || img.startsWith('/uploads/')));
          return valid.length ? valid : null;
        }
      } catch (e) {}
    } else if (images.startsWith('data:image')) {
      return [images];
    }
  }
  return null;
};

module.exports = { upload, uploadDir, normalizeImages };