const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    //RBAC: default "user",admin sirf seedAdmin.js ya DB se banega
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    // Har login pe +1, purane token automatically invalid
    tokenVersion: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", userSchema);

module.exports = User;