// backend/routes/adminRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

/**
 * GET /admin/summary
 * – global stats: totalUsers, totalSwipes, totalMatches, totalMessages, newestUsers
 *
 * (Možeš dodati posebnu admin provjeru kasnije ako hoćeš.)
 */
router.get("/summary", requireAuth, async (req, res, next) => {
  try {
    const [totalUsers, totalSwipes, totalMatches, totalMessages, newestUsers] =
      await Promise.all([
        prisma.user.count(),
        prisma.swipe.count(),
        prisma.match.count(),
        prisma.message.count(),
        prisma.user.findMany({
          orderBy: { createdAt: "desc" },
          take: 10,
          select: {
            id: true,
            email: true,
            name: true,
            age: true,
            gender: true,
            createdAt: true,
          },
        }),
      ]);

    return res.json({
      totalUsers,
      totalSwipes,
      totalMatches,
      totalMessages,
      newestUsers,
    });
  } catch (err) {
    console.error("GET /admin/summary error:", err);
    next(err);
  }
});

module.exports = router;
