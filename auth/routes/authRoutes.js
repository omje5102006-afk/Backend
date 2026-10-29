const express = require("express");
const router = express.Router();
const c = require("../controller/authController");
const { protect, authorize } = require("../middleware/authMiddleware");

// Public
router.post("/register", c.register);
router.post("/login", c.login);              // sirf role: user
router.post("/admin/login", c.adminLogin);   // sirf role: admin

// Logged-in (user + admin)
router.post("/logout", protect, c.logout);
router.get("/me", protect, c.me);
router.get("/dashboard", protect, c.dashboard);

// Admin only
router.get("/users", protect, authorize("admin"), c.getAllUsers);
router.patch("/users/:id/role", protect, authorize("admin"), c.updateUserRole);
router.delete("/users/:id", protect, authorize("admin"), c.deleteUser);

module.exports = router;