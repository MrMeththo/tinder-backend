// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

let morgan = null;
try {
  morgan = require('morgan');
} catch (e) {
  console.warn('morgan not installed, skipping request logging');
}

const prisma = new PrismaClient();
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DAILY_SWIPE_LIMIT = Number(process.env.DAILY_SWIPE_LIMIT || 50);

// ---------- GLOBAL MIDDLEWARE ----------

app.use(helmet());
app.use(
  cors({
    origin: '*',
  })
);
app.use(express.json());

if (morgan) {
  app.use(morgan('tiny'));
}

// global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
});
app.use(globalLimiter);

// jači limit za auth rute
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
});
app.use('/auth', authLimiter);

// ---------- HELPERS ----------

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    age: user.age,
    bio: user.bio,
    gender: user.gender,
    photoUrl: user.photoUrl || null,
  };
}

function createToken(user) {
  return jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing auth token' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    console.error('authMiddleware error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function seedDemoUsers() {
  const demoUsers = [
    {
      email: 'ana@example.com',
      name: 'Ana',
      age: 26,
      bio: 'Volim putovanja, kavu i dobar razgovor.',
      gender: 'female',
    },
    {
      email: 'marko@example.com',
      name: 'Marko',
      age: 28,
      bio: 'Gym, travel, good food.',
      gender: 'male',
    },
    {
      email: 'lucija@example.com',
      name: 'Lucija',
      age: 24,
      bio: 'Tech, knjige i more.',
      gender: 'female',
    },
    {
      email: 'ivan@example.com',
      name: 'Ivan',
      age: 30,
      bio: 'Volim more i jedrenje.',
      gender: 'male',
    },
  ];

  const passwordHash = await bcrypt.hash('password123', 10);

  for (const demo of demoUsers) {
    await prisma.user.upsert({
      where: { email: demo.email },
      update: {},
      create: {
        email: demo.email,
        passwordHash,
        name: demo.name,
        age: demo.age,
        bio: demo.bio,
        gender: demo.gender,
      },
    });
  }

  console.log('Seeded demo users (ana/marko/lucija/ivan @ example.com, pass: password123)');
}

async function getTodaySwipeCount(userId) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const count = await prisma.swipe.count({
    where: {
      fromUserId: userId,
      createdAt: { gte: startOfDay },
    },
  });

  return count;
}

// ---------- AUTH ROUTES ----------

app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name, age, gender } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: 'Email and password are required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name: name || email.split('@')[0],
        age: age ? Number(age) : null,
        gender: gender || null,
      },
    });

    const token = createToken(user);

    return res.status(201).json({
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error('POST /auth/register error:', err);
    return res.status(500).json({ error: 'Failed to register' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = createToken(user);

    return res.json({
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error('POST /auth/login error:', err);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

// ---------- PROFILE / ME ----------

app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(publicUser(user));
  } catch (err) {
    console.error('GET /me error:', err);
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.put('/me', authMiddleware, async (req, res) => {
  try {
    const { name, age, bio, gender, photoUrl } = req.body;

    const data = {};

    if (typeof name === 'string' && name.trim().length > 0) {
      data.name = name.trim();
    }

    if (age === null) {
      data.age = null;
    } else if (age !== undefined && !Number.isNaN(Number(age))) {
      data.age = Number(age);
    }

    if (bio !== undefined) {
      data.bio = typeof bio === 'string' ? bio : '';
    }

    if (gender !== undefined) {
      data.gender =
        typeof gender === 'string' && gender.trim().length > 0
          ? gender.trim()
          : null;
    }

    if (photoUrl !== undefined) {
      const trimmed = typeof photoUrl === 'string' ? photoUrl.trim() : '';
      data.photoUrl = trimmed.length > 0 ? trimmed : null;
    }

    const updated = await prisma.user.update({
      where: { id: req.userId },
      data,
    });

    return res.json(publicUser(updated));
  } catch (err) {
    console.error('PUT /me error:', err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ---------- PROFILES / RECOMMENDATIONS ----------

// GET /profiles/recommendations?gender=&minAge=&maxAge=
app.get('/profiles/recommendations', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { gender, minAge, maxAge } = req.query;

    // isključi sebe
    const where = {
      id: { not: userId },
    };

    // opcionalni filteri
    if (gender && typeof gender === 'string' && gender !== 'male/female/other') {
      where.gender = gender;
    }

    if (minAge || maxAge) {
      where.age = {};
      if (minAge) where.age.gte = Number(minAge);
      if (maxAge) where.age.lte = Number(maxAge);
    }

    const candidates = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    return res.json(candidates.map(publicUser));
  } catch (err) {
    console.error('GET /profiles/recommendations error:', err);
    return res.status(500).json({ error: 'Failed to load profiles' });
  }
});

// ---------- SWIPES ----------

// POST /swipes { toUserId, direction }
app.post('/swipes', authMiddleware, async (req, res) => {
  try {
    const fromUserId = req.userId;
    const { toUserId, direction } = req.body;

    if (!toUserId || !['like', 'pass', 'superlike'].includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe payload' });
    }

    // daily limit
    const todayCount = await getTodaySwipeCount(fromUserId);
    if (todayCount >= DAILY_SWIPE_LIMIT) {
      return res.status(429).json({
        error: 'Daily swipe limit reached',
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

    // check for match
    let match = null;
    if (direction === 'like' || direction === 'superlike') {
      const reverse = await prisma.swipe.findFirst({
        where: {
          fromUserId: toUserId,
          toUserId: fromUserId,
          direction: { in: ['like', 'superlike'] },
        },
      });

      if (reverse) {
        match = await prisma.match.findFirst({
          where: {
            OR: [
              { user1Id: fromUserId, user2Id: toUserId },
              { user1Id: toUserId, user2Id: fromUserId },
            ],
          },
        });

        if (!match) {
          match = await prisma.match.create({
            data: {
              user1Id: fromUserId,
              user2Id: toUserId,
            },
          });
        }
      }
    }

    return res.json({
      swipeId: swipe.id,
      match: !!match,
      matchId: match ? match.id : null,
    });
  } catch (err) {
    console.error('POST /swipes error:', err);
    return res.status(500).json({ error: 'Failed to send swipe' });
  }
});

// POST /swipes/undo – undo zadnjeg swipa
app.post('/swipes/undo', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const lastSwipe = await prisma.swipe.findFirst({
      where: { fromUserId: userId },
      orderBy: { createdAt: 'desc' },
    });

    if (!lastSwipe) {
      return res.status(400).json({ error: 'No swipe to undo' });
    }

    // ako je od tog swipa nastao match, brišemo i match i poruke
    const match = await prisma.match.findFirst({
      where: {
        OR: [
          { user1Id: userId, user2Id: lastSwipe.toUserId },
          { user1Id: lastSwipe.toUserId, user2Id: userId },
        ],
      },
    });

    if (match) {
      await prisma.message.deleteMany({
        where: { matchId: match.id },
      });

      await prisma.match.delete({
        where: { id: match.id },
      });
    }

    await prisma.swipe.delete({
      where: { id: lastSwipe.id },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /swipes/undo error:', err);
    return res.status(500).json({ error: 'Failed to undo swipe' });
  }
});

// ---------- MATCHES & CHAT ----------

// GET /matches
app.get('/matches', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const matches = await prisma.match.findMany({
      where: {
        OR: [{ user1Id: userId }, { user2Id: userId }],
      },
      orderBy: { createdAt: 'desc' },
      include: {
        user1: true,
        user2: true,
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
      },
    });

    const result = matches.map((m) => {
      const otherUser = m.user1Id === userId ? m.user2 : m.user1;
      const lastMessage = m.messages[0] || null;

      return {
        id: m.id,
        createdAt: m.createdAt,
        otherUser: publicUser(otherUser),
        lastMessage: lastMessage
          ? {
              id: lastMessage.id,
              matchId: lastMessage.matchId,
              fromUserId: lastMessage.fromUserId,
              // API polje "content", DB polje "text"
              content: lastMessage.text,
              createdAt: lastMessage.createdAt,
            }
          : null,
        unreadCount: 0, // nemamo readAt u bazi, pa 0
      };
    });

    return res.json(result);
  } catch (err) {
    console.error('GET /matches error:', err);
    return res.status(500).json({ error: 'Failed to load matches' });
  }
});

// GET /matches/:matchId/messages
app.get('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not allowed' });
    }

    const messages = await prisma.message.findMany({
      where: { matchId },
      orderBy: { createdAt: 'asc' },
    });

    const mapped = messages.map((msg) => ({
      id: msg.id,
      matchId: msg.matchId,
      fromUserId: msg.fromUserId,
      // toUserId iz matcha – drugi user u matchu
      toUserId:
        msg.fromUserId === match.user1Id
          ? match.user2Id
          : match.user1Id,
      content: msg.text,
      createdAt: msg.createdAt,
    }));

    return res.json(mapped);
  } catch (err) {
    console.error('GET /matches/:matchId/messages error:', err);
    return res.status(500).json({ error: 'Failed to load messages' });
  }
});

// POST /matches/:matchId/messages
app.post('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;
    const { content } = req.body;

    if (!content || typeof content !== 'string') {
      return res.status(400).json({ error: 'Content is required' });
    }

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not allowed' });
    }

    const msg = await prisma.message.create({
      data: {
        matchId,
        fromUserId: userId,
        text: content.trim(), // DB kolona "text"
      },
    });

    const toUserId =
      userId === match.user1Id ? match.user2Id : match.user1Id;

    return res.status(201).json({
      id: msg.id,
      matchId: msg.matchId,
      fromUserId: msg.fromUserId,
      toUserId,
      content: msg.text,
      createdAt: msg.createdAt,
    });
  } catch (err) {
    console.error('POST /matches/:matchId/messages error:', err);
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// DELETE /matches/:matchId – remove/block
app.delete('/matches/:matchId', authMiddleware, async (req, res) => {
  const userId = req.userId;
  const { matchId } = req.params;

  try {
    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not allowed' });
    }

    await prisma.message.deleteMany({
      where: { matchId },
    });

    await prisma.match.delete({
      where: { id: matchId },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /matches/:matchId error:', err);
    return res.status(500).json({ error: 'Failed to remove match' });
  }
});

// ---------- STATS / ANALYTICS ----------

app.get('/me/stats', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const [totalLikes, totalPasses, totalSuperLikes, totalMatches, totalMessagesSent] =
      await Promise.all([
        prisma.swipe.count({
          where: { fromUserId: userId, direction: 'like' },
        }),
        prisma.swipe.count({
          where: { fromUserId: userId, direction: 'pass' },
        }),
        prisma.swipe.count({
          where: { fromUserId: userId, direction: 'superlike' },
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
      totalLikes,
      totalPasses,
      totalSuperLikes,
      totalMatches,
      totalMessagesSent,
    });
  } catch (err) {
    console.error('GET /me/stats error:', err);
    return res.status(500).json({ error: 'Failed to load stats' });
  }
});

// admin summary – global
app.get('/admin/summary', authMiddleware, async (req, res) => {
  try {
    const [totalUsers, totalSwipes, totalMatches, totalMessages] =
      await Promise.all([
        prisma.user.count(),
        prisma.swipe.count(),
        prisma.match.count(),
        prisma.message.count(),
      ]);

    const newestUsers = await prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      take: 10,
    });

    return res.json({
      totalUsers,
      totalSwipes,
      totalMatches,
      totalMessages,
      newestUsers: newestUsers.map(publicUser),
    });
  } catch (err) {
    console.error('GET /admin/summary error:', err);
    return res.status(500).json({ error: 'Failed to load summary' });
  }
});

// ---------- DEBUG ----------

app.post('/debug/reset-my-swipes', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const deleted = await prisma.swipe.deleteMany({
      where: { fromUserId: userId },
    });

    return res.json({ ok: true, deleted: deleted.count });
  } catch (err) {
    console.error('POST /debug/reset-my-swipes error:', err);
    return res.status(500).json({ error: 'Failed to reset swipes' });
  }
});

// ---------- ROOT & ERROR HANDLERS ----------

app.get('/', (req, res) => {
  return res.json({ ok: true, message: 'Tinder backend live' });
});

app.use((req, res) => {
  return res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Internal server error' });
});

// ---------- START ----------

async function start() {
  try {
    await seedDemoUsers();

    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}

start();

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});
