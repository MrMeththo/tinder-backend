// backend/routes/swipesRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

const DAILY_SWIPE_LIMIT = 50;

function startOfToday() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0);
}

/**
 * POST /swipes
 * body: { toUserId, direction } – direction ∈ like | pass | superlike
 */
router.post("/", requireAuth, async (req, res, next) => {
  try {
    const fromUserId = req.userId;
    const { toUserId, direction } = req.body || {};

    if (!toUserId || !direction) {
      return res
        .status(400)
        .json({ error: "toUserId and direction are required" });
    }

    if (!["like", "pass", "superlike"].includes(direction)) {
      return res.status(400).json({ error: "Invalid direction" });
    }

    // daily limit
    const today = startOfToday();
    const todayCount = await prisma.swipe.count({
      where: {
        fromUserId,
        createdAt: {
          gte: today,
        },
      },
    });

    if (todayCount >= DAILY_SWIPE_LIMIT) {
      return res.status(429).json({
        error: "Daily swipe limit reached",
        limit: DAILY_SWIPE_LIMIT,
      });
    }

    const swipe = await prisma.swipe.create({
      data: {
        fromUserId,
        toUserId,
        direction,
      },
    });

    // je li nastao match? (druga strana je već lajkala)
    const oppositeSwipe = await prisma.swipe.findFirst({
      where: {
        fromUserId: toUserId,
        toUserId: fromUserId,
        direction: {
          in: ["like", "superlike"],
        },
      },
    });

    if (!oppositeSwipe || direction === "pass") {
      return res.json({
        success: true,
        isMatch: false,
        swipeId: swipe.id,
      });
    }

    // kreiraj ili nađi postojeći Match
    const existingMatch = await prisma.match.findFirst({
      where: {
        OR: [
          { user1Id: fromUserId, user2Id: toUserId },
          { user1Id: toUserId, user2Id: fromUserId },
        ],
      },
    });

    let match = existingMatch;
    if (!match) {
      match = await prisma.match.create({
        data: {
          user1Id: fromUserId,
          user2Id: toUserId,
        },
      });
    }

    const otherUser = await prisma.user.findUnique({
      where: { id: toUserId },
    });

    const { passwordHash, ...otherPublic } = otherUser || {};

    return res.json({
      success: true,
      isMatch: true,
      matchId: match.id,
      otherUser: otherPublic,
    });
  } catch (err) {
    console.error("POST /swipes error:", err);
    next(err);
  }
});

/**
 * POST /swipes/undo
 * – undo zadnjeg swipa:
 *   briše zadnji Swipe + eventualni Match + njegove poruke
 */
router.post("/undo", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;

    const lastSwipe = await prisma.swipe.findFirst({
      where: { fromUserId: userId },
      orderBy: { createdAt: "desc" },
    });

    if (!lastSwipe) {
      return res.status(404).json({ error: "No swipes to undo" });
    }

    const { id: swipeId, toUserId } = lastSwipe;

    // postoji li match između ova dva usera?
    const match = await prisma.match.findFirst({
      where: {
        OR: [
          { user1Id: userId, user2Id: toUserId },
          { user1Id: toUserId, user2Id: userId },
        ],
      },
    });

    let removedMatchId = null;

    if (match) {
      await prisma.message.deleteMany({
        where: { matchId: match.id },
      });

      await prisma.match.delete({
        where: { id: match.id },
      });

      removedMatchId = match.id;
    }

    await prisma.swipe.delete({
      where: { id: swipeId },
    });

    return res.json({
      success: true,
      undoneSwipeId: swipeId,
      removedMatchId,
    });
  } catch (err) {
    console.error("POST /swipes/undo error:", err);
    next(err);
  }
});

module.exports = router;
