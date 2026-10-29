const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const makeToken = (user) =>
  jwt.sign({ id: user._id, role: user.role, v: user.tokenVersion }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1d",
  });

const safeUser = (u) => ({ id: u._id, name: u.name, email: u.email, role: u.role });

// Register: role hamesha "user". Body se role kabhi mat lo.
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "Name, email aur password do" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password kam se kam 6 character ka ho" });

    const cleanEmail = email.toLowerCase().trim();
    if (await User.findOne({ email: cleanEmail }))
      return res.status(409).json({ message: "Email already registered" });

    const user = await User.create({
      name: name.trim(),
      email: cleanEmail,
      password: await bcrypt.hash(password, 10),
      role: "user",
    });

    res.status(201).json({ message: "Account created", token: makeToken(user), user: safeUser(user) });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ message: "Email already registered" });
    res.status(500).json({ message: err.message });
  }
};

// Login factory: allowedRole ke hisaab se user ya admin login
const loginAs = (allowedRole) => async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email aur password do" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ message: "Invalid credentials" });

    if (user.role !== allowedRole)
      return res.status(403).json({
        message:
          allowedRole === "admin"
            ? "Ye admin login hai, aap admin nahi ho"
            : "Admin ko /admin/login se login karna hoga",
      });

    // naya login = purane devices logout
    const updated = await User.findByIdAndUpdate(
      user._id,
      { $inc: { tokenVersion: 1 } },
      { new: true }
    );

    res.json({
      message: `${allowedRole} login successful`,
      token: makeToken(updated),
      user: safeUser(updated),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.login = loginAs("user");
exports.adminLogin = loginAs("admin");

exports.logout = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { $inc: { tokenVersion: 1 } });
    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.me = (req, res) => res.json({ user: safeUser(req.user) });

// Dashboard: role ke hisaab se alag response
exports.dashboard = (req, res) => {
  if (req.user.role === "admin")
    return res.json({ view: "admin", message: `Welcome Admin ${req.user.name}` });
  res.json({ view: "user", message: `Welcome ${req.user.name}` });
};

// ---- Admin only ----
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password -tokenVersion");
    res.json({ count: users.length, users });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.updateUserRole = async (req, res) => {
  try {
    const { role } = req.body;
    if (!["user", "admin"].includes(role))
      return res.status(400).json({ message: "Role 'user' ya 'admin' hi ho sakta hai" });
    if (req.params.id === String(req.user._id))
      return res.status(400).json({ message: "Apna role khud change nahi kar sakte" });

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role, $inc: { tokenVersion: 1 } },
      { new: true }
    ).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Role updated", user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    if (req.params.id === String(req.user._id))
      return res.status(400).json({ message: "Apne aap ko delete nahi kar sakte" });
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};