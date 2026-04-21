const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const path = require("path");
const { globalLimiter, loginLimiter, errorHandler, logger } = require("./middleware/middleware");
const routes = require("./routes/routes");

const app = express();

// ========================================================
// CONFIGURACIÓN DE SEGURIDAD (HELMET) - CORREGIDA PARA IMÁGENES
// ========================================================
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }, // Permite cargar imágenes desde otros orígenes
    crossOriginEmbedderPolicy: false, // Evita conflictos con COEP
}));

app.use(compression());
app.use(globalLimiter);
app.use(cors({ origin: process.env.CLIENT_URL || "http://localhost:5173", credentials: true }));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

// ========================================================
// SERVIR ARCHIVOS ESTÁTICOS (IMÁGENES) CON CABECERAS CORRECTAS
// ========================================================
app.use('/uploads', (req, res, next) => {
    // Forzar la cabecera CORP a cross-origin por si Helmet no la establece bien
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
});
app.use("/uploads", express.static(path.join(__dirname, "../uploads")));

if (process.env.NODE_ENV !== "production") app.use(logger);

// Aplicar limitador específico a la ruta de login
app.use("/api/auth/login", loginLimiter);

// Rutas de la API
app.use("/api", routes);

// Manejador global de errores (debe ir al final)
app.use(errorHandler);

module.exports = app;