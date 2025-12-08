// backend/routes/recommendationsRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

/**
 * GET /profiles/recommendations?gender=&minAge=&maxAge=
 * – preporuke za swipe ekran
 *
 * Trenutno NE filtrira već swipeane/matchane (infinite test),
 * samo osnovni filteri.
 */
router.get("/recommendations", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;
    const { gender, minAge, maxAge } = req.query;

    const where = {
      id: { not: userId },
    };

    if (gender) {
      where.gender = String(gender);
    }

    if (minAge || maxAge) {
      where.age = {};
      if (minAge) where.age.gte = Number(minAge);
      if (maxAge) where.age.lte = Number(maxAge);
    }

    const users = await prisma.user.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    const publicUsers = users.map((u) => {
      const { passwordHash, ...rest } = u;
      return rest;
    });

    return res.json(publicUsers);
  } catch (err) {
    console.error("GET /profiles/recommendations error:", err);
    next(err);
  }
});

module.exports = router;
