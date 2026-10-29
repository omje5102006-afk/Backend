const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

// Login check: token valid hai, user exist karta hai, session abhi bhi active hai
const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Token missing" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (!user) return res.status(401).json({ message: "User not found" });

    if (decoded.v !== user.tokenVersion)
      return res.status(401).json({
        code: "SESSION_EXPIRED",
        message: "Aap kisi aur device pe login ho gaye",
      });

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Role check: role DB se aata hai (req.user), token se nahi
const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role))
    return res.status(403).json({ message: "Access denied: aapke paas permission nahi hai" });
  next();
};

module.exports = { protect, authorize };