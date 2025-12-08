// backend/routes/debugRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

/**
 * POST /debug/reset-my-swipes
 * – briše SVE Swipes za trenutnog usera (samo za testiranje)
 */
router.post("/reset-my-swipes", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;

    const result = await prisma.swipe.deleteMany({
      where: { fromUserId: userId },
    });

    return res.json({
      success: true,
      deletedCount: result.count,
    });
  } catch (err) {
    console.error("POST /debug/reset-my-swipes error:", err);
    next(err);
  }
});

module.exports = router;
