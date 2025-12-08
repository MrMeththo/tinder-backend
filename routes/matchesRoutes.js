// backend/routes/matchesRoutes.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("../middleware/authMiddleware");

const prisma = new PrismaClient();
const router = express.Router();

/**
 * GET /matches
 * – vraća listu matcheva za usera
 *   svaki: { id, createdAt, otherUser, lastMessage?, unreadCount }
 */
router.get("/", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;

    const matches = await prisma.match.findMany({
      where: {
        OR: [{ user1Id: userId }, { user2Id: userId }],
      },
      orderBy: { createdAt: "desc" },
      include: {
        user1: true,
        user2: true,
        messages: {
          orderBy: { createdAt: "desc" },
          take: 1,
        },
      },
    });

    const result = matches.map((m) => {
      const otherUser =
        m.user1Id === userId ? m.user2 : m.user1;

      const { passwordHash, ...otherPublic } = otherUser || {};

      const lastMessage = m.messages[0]
        ? {
            id: m.messages[0].id,
            matchId: m.messages[0].matchId,
            fromUserId: m.messages[0].fromUserId,
            toUserId: m.messages[0].toUserId,
            content: m.messages[0].text, // map text -> content
            createdAt: m.messages[0].createdAt,
          }
        : null;

      return {
        id: m.id,
        createdAt: m.createdAt,
        otherUser: otherPublic,
        lastMessage,
        unreadCount: 0, // za sada 0, može se kasnije dodati logika
      };
    });

    return res.json(result);
  } catch (err) {
    console.error("GET /matches error:", err);
    next(err);
  }
});

/**
 * GET /matches/:matchId/messages
 * – vraća sve poruke za match, sortirane po createdAt (ASC)
 *   response poruke imaju polje content (iz text)
 */
router.get("/:matchId/messages", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: "Match not found" });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const messages = await prisma.message.findMany({
      where: { matchId },
      orderBy: { createdAt: "asc" },
    });

    const result = messages.map((msg) => ({
      id: msg.id,
      matchId: msg.matchId,
      fromUserId: msg.fromUserId,
      toUserId: msg.toUserId,
      content: msg.text,
      createdAt: msg.createdAt,
    }));

    return res.json(result);
  } catch (err) {
    console.error("GET /matches/:matchId/messages error:", err);
    next(err);
  }
});

/**
 * POST /matches/:matchId/messages
 * body: { content }
 * – content se sprema kao text u bazi
 */
router.post("/:matchId/messages", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;
    const { content } = req.body || {};

    if (!content || !content.trim()) {
      return res.status(400).json({ error: "Content is required" });
    }

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: "Match not found" });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const toUserId =
      match.user1Id === userId ? match.user2Id : match.user1Id;

    const message = await prisma.message.create({
      data: {
        matchId,
        fromUserId: userId,
        toUserId,
        text: content,
      },
    });

    return res.status(201).json({
      id: message.id,
      matchId: message.matchId,
      fromUserId: message.fromUserId,
      toUserId: message.toUserId,
      content: message.text,
      createdAt: message.createdAt,
    });
  } catch (err) {
    console.error("POST /matches/:matchId/messages error:", err);
    next(err);
  }
});

/**
 * DELETE /matches/:matchId
 * – user može block/remove match (mora biti user1 ili user2)
 *   briše sve Message + Match
 */
router.delete("/:matchId", requireAuth, async (req, res, next) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: "Match not found" });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await prisma.message.deleteMany({
      where: { matchId },
    });

    await prisma.match.delete({
      where: { id: matchId },
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("DELETE /matches/:matchId error:", err);
    next(err);
  }
});

module.exports = router;
