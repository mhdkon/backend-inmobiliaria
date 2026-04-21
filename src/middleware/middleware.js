const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Token requerido" });
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Acceso denegado" });
  next();
};

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: "Demasiadas peticiones, intente más tarde" }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Demasiados intentos de login, espere 15 minutos" }
});

const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  if (err.message === "Solo imágenes (jpeg, png, gif, webp)") {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({ error: "Error interno del servidor" });
};

const logger = (req, res, next) => {
  console.log(`➡️ ${req.method} ${req.url}`);
  next();
};

module.exports = { authMiddleware, adminMiddleware, globalLimiter, loginLimiter, errorHandler, logger };