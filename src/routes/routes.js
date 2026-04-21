const express = require("express");
const { authMiddleware, adminMiddleware } = require("../middleware/middleware");
const { upload } = require("../utils/utils");
const {
  register, login, getUsers, deleteUser, createProperty, getProperties, getPropertyById,
  updateProperty, deleteProperty, addFavorite, getFavorites, removeFavorite, uploadImages
} = require("../controllers/controllers");

const router = express.Router();

router.post("/auth/register", register);
router.post("/auth/login", login);
router.get("/users", authMiddleware, adminMiddleware, getUsers);
router.delete("/users/:id", authMiddleware, adminMiddleware, deleteUser);
router.post("/properties", authMiddleware, upload.array("images", 10), createProperty);
router.get("/properties", getProperties);
router.get("/properties/:id", getPropertyById);
router.put("/properties/:id", authMiddleware, upload.array("images", 10), updateProperty);
router.delete("/properties/:id", authMiddleware, deleteProperty);
router.post("/favorites/:id", authMiddleware, addFavorite);
router.get("/favorites", authMiddleware, getFavorites);
router.delete("/favorites/:id", authMiddleware, removeFavorite);
router.post("/upload", authMiddleware, upload.array("images", 10), uploadImages);

module.exports = router;