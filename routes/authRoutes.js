// backend/routes/authRoutes.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { JWT_SECRET } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

function toPublicUser(user) {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return rest;
}

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
}

/**
 * POST /auth/register
 * body: { email, password, name?, age?, gender? }
 */
router.post("/register", async (req, res, next) => {
  try {
    const { email, password, name, age, gender } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const existing = await prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name: name || "New user",
        age: age || 18,
        gender: gender || null,
      },
    });

    const token = generateToken(user.id);

    return res.status(201).json({
      token,
      user: toPublicUser(user),
    });
  } catch (err) {
    console.error("Register error:", err);
    next(err);
  }
});

/**
 * POST /auth/login
 * body: { email, password }
 */
router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user.id);

    return res.json({
      token,
      user: toPublicUser(user),
    });
  } catch (err) {
    console.error("Login error:", err);
    next(err);
  }
});

module.exports = router;
