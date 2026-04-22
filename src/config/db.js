const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect()
  .then(() => console.log("✅ DB conectada correctamente"))
  .catch(err => console.error("❌ DB ERROR:", err.message));

module.exports = pool;