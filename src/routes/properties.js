const express = require('express');
const router = express.Router();
const { 
  updateProperty, 
  createProperty, 
  deleteProperty, 
  deleteImageFromProperty,
  getProperties,
  getPropertyById 
} = require('../controllers/controllers');
const auth = require('../middleware/auth'); // tu middleware de autenticación

// ... otras rutas
router.delete('/:id/images', auth, deleteImageFromProperty);
router.put('/:id', auth, updateProperty);
router.post('/', auth, createProperty);
router.delete('/:id', auth, deleteProperty);
// etc.

module.exports = router;