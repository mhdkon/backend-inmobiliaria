// createAdmin.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Necesario para Render
});

async function createAdmin() {
  const email = 'admistrador@gmail.com';
  const plainPassword = 'Admin225';
  const name = 'Administrador';
  const role = 'admin';

  try {
    // 1. Hashear la contraseña
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    // 2. Verificar si ya existe un usuario con ese email
    const checkQuery = 'SELECT id FROM users WHERE email = $1';
    const checkRes = await pool.query(checkQuery, [email]);

    if (checkRes.rows.length > 0) {
      // Actualizar el rol y la contraseña del usuario existente
      const updateQuery = `
        UPDATE users 
        SET password = $1, name = $2, role = $3 
        WHERE email = $4
        RETURNING id, email, role
      `;
      const updateRes = await pool.query(updateQuery, [hashedPassword, name, role, email]);
      console.log('✅ Usuario actualizado a administrador:', updateRes.rows[0]);
    } else {
      // Insertar nuevo administrador
      const insertQuery = `
        INSERT INTO users (name, email, password, role, created_at)
        VALUES ($1, $2, $3, $4, NOW())
        RETURNING id, email, role
      `;
      const insertRes = await pool.query(insertQuery, [name, email, hashedPassword, role]);
      console.log('✅ Administrador creado exitosamente:', insertRes.rows[0]);
    }
  } catch (error) {
    console.error('❌ Error al crear/actualizar administrador:', error.message);
  } finally {
    await pool.end();
  }
}

createAdmin();