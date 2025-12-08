// backend/routes/profileRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

function toPublicUser(user) {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return rest;
}

/**
 * GET /me
 * – vraća public user za trenutno logiranog usera
 */
router.get("/me", requireAuth, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json(toPublicUser(user));
  } catch (err) {
    console.error("GET /me error:", err);
    next(err);
  }
});

/**
 * PUT /me
 * – update name, age, bio, gender, photoUrl
 */
router.put("/me", requireAuth, async (req, res, next) => {
  try {
    const { name, age, bio, gender, photoUrl } = req.body || {};

    const updated = await prisma.user.update({
      where: { id: req.userId },
      data: {
        ...(name !== undefined ? { name } : {}),
        ...(age !== undefined ? { age: Number(age) } : {}),
        ...(bio !== undefined ? { bio } : {}),
        ...(gender !== undefined ? { gender } : {}),
        ...(photoUrl !== undefined ? { photoUrl } : {}),
      },
    });

    return res.json(toPublicUser(updated));
  } catch (err) {
    console.error("PUT /me error:", err);
    next(err);
  }
});

/**
 * GET /me/stats
 * – broj swipeova, match-eva i poslanih poruka za usera
 */
router.get("/me/stats", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;

    const [likes, passes, superlikes, matches, sentMessages] =
      await Promise.all([
        prisma.swipe.count({
          where: { fromUserId: userId, direction: "like" },
        }),
        prisma.swipe.count({
          where: { fromUserId: userId, direction: "pass" },
        }),
        prisma.swipe.count({
          where: { fromUserId: userId, direction: "superlike" },
        }),
        prisma.match.count({
          where: {
            OR: [{ user1Id: userId }, { user2Id: userId }],
          },
        }),
        prisma.message.count({
          where: { fromUserId: userId },
        }),
      ]);

    return res.json({
      likes,
      passes,
      superlikes,
      matches,
      sentMessages,
    });
  } catch (err) {
    console.error("GET /me/stats error:", err);
    next(err);
  }
});

module.exports = router;
