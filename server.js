require("dotenv").config();
const app = require("./src/app");
const pool = require("./src/config/db");
const bcrypt = require("bcrypt");

const PORT = process.env.PORT || 3000;

const createDefaultAdmin = async () => {
  const adminEmail = process.env.ADMIN_EMAIL || "admin@inmobiliaria.com";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
  const adminName = process.env.ADMIN_NAME || "Administrador";
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [adminEmail]);
    if (result.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await pool.query("INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'admin')", [adminName, adminEmail, hashedPassword]);
      console.log(`✅ Usuario administrador creado: ${adminEmail}`);
    } else {
      console.log(`ℹ️ El administrador ${adminEmail} ya existe.`);
    }
  } catch (err) {
    console.error("❌ Error al crear administrador:", err.message);
  }
};

pool.connect()
  .then(async () => {
    console.log("✅ Conexión a PostgreSQL establecida");
    await createDefaultAdmin();
    app.listen(PORT, () => {
      console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
      console.log(`📡 API disponible en http://localhost:${PORT}/api`);
      console.log(`📁 Las imágenes se guardan en: ${__dirname}/uploads`);
    });
  })
  .catch(err => {
    console.error("❌ Error conectando a PostgreSQL:", err.message);
    process.exit(1);
  });