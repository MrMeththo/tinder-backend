// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

// morgan je opcionalan – ako nije instaliran, server će svejedno raditi
let morgan = null;
try {
  // npm install morgan  (ako želiš logove requesta)
  morgan = require('morgan');
} catch (err) {
  console.warn('morgan not installed, request logging disabled');
}

const prisma = new PrismaClient();
const app = express();

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const SWIPES_PER_DAY = Number(process.env.SWIPES_PER_DAY) || 50;

// --------- GLOBAL MIDDLEWARE ---------
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(helmet());

if (morgan) {
  app.use(morgan('combined'));
}

// rate limit za cijeli API (lagani)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 120,            // 120 requesta u minuti
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(apiLimiter);

// ---------- HELPER FUNKCIJE ----------

function createToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    age: user.age,
    gender: user.gender,
    bio: user.bio,
    photoUrl: user.photoUrl || null,
  };
}

async function seedDemoUsers() {
  const demoUsers = [
    {
      email: 'ana@example.com',
      name: 'Ana',
      gender: 'female',
      age: 25,
      bio: 'Gym, travel, good food.',
      photoUrl:
        'https://images.pexels.com/photos/415829/pexels-photo-415829.jpeg',
    },
    {
      email: 'marko@example.com',
      name: 'Marko',
      gender: 'male',
      age: 28,
      bio: 'Software developer and gamer.',
      photoUrl:
        'https://images.pexels.com/photos/614810/pexels-photo-614810.jpeg',
    },
    {
      email: 'lucija@example.com',
      name: 'Lucija',
      gender: 'female',
      age: 27,
      bio: 'Coffee lover, books, dogs.',
      photoUrl:
        'https://images.pexels.com/photos/415829/pexels-photo-415829.jpeg',
    },
    {
      email: 'ivan@example.com',
      name: 'Ivan',
      gender: 'male',
      age: 30,
      bio: 'Outdoors, hiking, good vibes.',
      photoUrl:
        'https://images.pexels.com/photos/91227/pexels-photo-91227.jpeg',
    },
  ];

  const password = 'password123';
  const passwordHash = await bcrypt.hash(password, 10);

  for (const u of demoUsers) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: {
        email: u.email,
        name: u.name,
        gender: u.gender,
        age: u.age,
        bio: u.bio,
        photoUrl: u.photoUrl,
        passwordHash,
      },
    });
  }

  console.log(
    'Seeded demo users (ana/marko/lucija/ivan @ example.com, password: password123)'
  );
}

async function getSwipesTodayCount(userId) {
  const since = new Date();
  since.setHours(0, 0, 0, 0); // od početka dana

  return prisma.swipe.count({
    where: {
      fromUserId: userId,
      createdAt: {
        gte: since,
      },
    },
  });
}

// ---------- AUTH MIDDLEWARE ----------

async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }

    const payload = jwt.verify(token, JWT_SECRET);

    req.userId = payload.sub;
    req.userEmail = payload.email;
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- ROUTES ----------

// Health-check (Render ping, monitoring, itd.)
app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return res.json({ status: 'ok' });
  } catch (err) {
    console.error('Health check failed:', err);
    return res.status(500).json({ status: 'error', error: 'DB check failed' });
  }
});

// ----- AUTH -----

// Registracija
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name, age, gender, bio, photoUrl } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name: name || email.split('@')[0],
        age: age ? Number(age) : null,
        gender: gender || null,
        bio: bio || '',
        photoUrl: photoUrl || null,
      },
    });

    const token = createToken(user);
    return res.status(201).json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('POST /auth/register error:', err);
    return res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = createToken(user);
    return res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('POST /auth/login error:', err);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

// ----- USER / PROFILE -----

// Trenutni user
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

// Update profila (uključuje i photoUrl)
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

// ----- RECOMMENDATIONS + FILTERI -----

app.get('/profiles/recommendations', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { gender, minAge, maxAge } = req.query;

    const where = {
      id: { not: userId },
    };

    // age filter
    const ageFilter = {};
    if (minAge !== undefined && minAge !== '') {
      const parsed = Number(minAge);
      if (Number.isNaN(parsed)) {
        return res.status(400).json({ error: 'Invalid minAge' });
      }
      ageFilter.gte = parsed;
    }

    if (maxAge !== undefined && maxAge !== '') {
      const parsed = Number(maxAge);
      if (Number.isNaN(parsed)) {
        return res.status(400).json({ error: 'Invalid maxAge' });
      }
      ageFilter.lte = parsed;
    }

    if (Object.keys(ageFilter).length > 0) {
      where.age = ageFilter;
    }

    if (typeof gender === 'string' && gender.trim().length > 0) {
      where.gender = gender.trim();
    }

    // isključi već swipane
    const alreadySwiped = await prisma.swipe.findMany({
      where: { fromUserId: userId },
      select: { toUserId: true },
    });

    const excluded = alreadySwiped.map((s) => s.toUserId);
    if (excluded.length > 0) {
      where.id = { notIn: [...excluded, userId] };
    }

    const candidates = await prisma.user.findMany({
      where,
      orderBy: { id: 'desc' },
      take: 50,
    });

    return res.json(candidates.map(publicUser));
  } catch (err) {
    console.error('GET /profiles/recommendations error:', err);
    return res
      .status(500)
      .json({ error: 'Failed to load profile recommendations' });
  }
});

// ----- SWIPES + UNDO + MATCH -----

app.post('/swipes', authMiddleware, async (req, res) => {
  try {
    const fromUserId = req.userId;
    const { toUserId, direction } = req.body;

    if (!toUserId || !direction) {
      return res
        .status(400)
        .json({ error: 'toUserId and direction are required' });
    }

    if (!['like', 'pass', 'superlike'].includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe direction' });
    }

    // dnevni limit
    const swipesToday = await getSwipesTodayCount(fromUserId);
    if (swipesToday >= SWIPES_PER_DAY) {
      return res.status(429).json({
        error: 'Daily swipe limit reached',
        swipesToday,
        limit: SWIPES_PER_DAY,
      });
    }

    // kreiraj swipe
    const swipe = await prisma.swipe.create({
      data: {
        fromUserId,
        toUserId,
        direction,
      },
    });

    let isMatch = false;
    let match = null;

    if (direction === 'like' || direction === 'superlike') {
      const reciprocal = await prisma.swipe.findFirst({
        where: {
          fromUserId: toUserId,
          toUserId: fromUserId,
          direction: { in: ['like', 'superlike'] },
        },
      });

      if (reciprocal) {
        // provjeri postoji li već match
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

        isMatch = true;
      }
    }

    return res.status(201).json({
      swipe,
      match: match || null,
      isMatch,
      swipesToday: swipesToday + 1,
      limit: SWIPES_PER_DAY,
    });
  } catch (err) {
    console.error('POST /swipes error:', err);
    return res.status(500).json({ error: 'Failed to process swipe' });
  }
});

// Undo zadnjeg swipa
app.post('/swipes/undo-last', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const lastSwipe = await prisma.swipe.findFirst({
      where: { fromUserId: userId },
      orderBy: { createdAt: 'desc' },
    });

    if (!lastSwipe) {
      return res.status(404).json({ error: 'No swipe to undo' });
    }

    // ako je napravio match, pokušaj obrisati i match
    await prisma.$transaction(async (tx) => {
      // moguće da match ne postoji, pa ignore error
      const match = await tx.match.findFirst({
        where: {
          OR: [
            {
              user1Id: lastSwipe.fromUserId,
              user2Id: lastSwipe.toUserId,
            },
            {
              user1Id: lastSwipe.toUserId,
              user2Id: lastSwipe.fromUserId,
            },
          ],
        },
      });

      if (match) {
        await tx.message.deleteMany({ where: { matchId: match.id } });
        await tx.match.delete({ where: { id: match.id } });
      }

      await tx.swipe.delete({ where: { id: lastSwipe.id } });
    });

    const swipesToday = await getSwipesTodayCount(userId);

    return res.json({
      undoneSwipeId: lastSwipe.id,
      swipesToday,
      limit: SWIPES_PER_DAY,
    });
  } catch (err) {
    console.error('POST /swipes/undo-last error:', err);
    return res.status(500).json({ error: 'Failed to undo swipe' });
  }
});

// ----- MATCHES + CHATS -----

// lista match-eva + basic info
app.get('/matches', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const matches = await prisma.match.findMany({
      where: {
        OR: [{ user1Id: userId }, { user2Id: userId }],
      },
      include: {
        user1: true,
        user2: true,
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    const result = matches.map((m) => {
      const otherUser = m.user1Id === userId ? m.user2 : m.user1;
      const lastMessage = m.messages[0] || null;

      return {
        id: m.id,
        otherUser: publicUser(otherUser),
        lastMessage: lastMessage
          ? {
              id: lastMessage.id,
              text: lastMessage.text,
              createdAt: lastMessage.createdAt,
              fromUserId: lastMessage.fromUserId,
            }
          : null,
      };
    });

    return res.json(result);
  } catch (err) {
    console.error('GET /matches error:', err);
    return res.status(500).json({ error: 'Failed to load matches' });
  }
});

// poruke za jedan match
app.get('/chats/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match || (match.user1Id !== userId && match.user2Id !== userId)) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const messages = await prisma.message.findMany({
      where: { matchId },
      orderBy: { createdAt: 'asc' },
    });

    return res.json(messages);
  } catch (err) {
    console.error('GET /chats/:matchId/messages error:', err);
    return res.status(500).json({ error: 'Failed to load messages' });
  }
});

// slanje poruke
app.post('/chats/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;
    const { text } = req.body;

    if (!text || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'Message text is required' });
    }

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match || (match.user1Id !== userId && match.user2Id !== userId)) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const message = await prisma.message.create({
      data: {
        matchId,
        fromUserId: userId,
        text: text.trim(),
      },
    });

    return res.status(201).json(message);
  } catch (err) {
    console.error('POST /chats/:matchId/messages error:', err);
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// ----- ANALYTICS / STATS -----

// globalni summary (možeš u appu koristiti za "admin" stats)
app.get('/analytics/summary', authMiddleware, async (req, res) => {
  try {
    const [totalUsers, totalSwipes, totalMatches, totalMessages] =
      await Promise.all([
        prisma.user.count(),
        prisma.swipe.count(),
        prisma.match.count(),
        prisma.message.count(),
      ]);

    return res.json({
      totalUsers,
      totalSwipes,
      totalMatches,
      totalMessages,
    });
  } catch (err) {
    console.error('GET /analytics/summary error:', err);
    return res.status(500).json({ error: 'Failed to load analytics' });
  }
});

// stats za trenutnog usera
app.get('/analytics/me', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const [swipesTotal, matchesCount, messagesSent, swipesToday] =
      await Promise.all([
        prisma.swipe.count({ where: { fromUserId: userId } }),
        prisma.match.count({
          where: {
            OR: [{ user1Id: userId }, { user2Id: userId }],
          },
        }),
        prisma.message.count({ where: { fromUserId: userId } }),
        getSwipesTodayCount(userId),
      ]);

    return res.json({
      swipesTotal,
      matchesCount,
      messagesSent,
      swipesToday,
      swipesLimit: SWIPES_PER_DAY,
    });
  } catch (err) {
    console.error('GET /analytics/me error:', err);
    return res.status(500).json({ error: 'Failed to load user stats' });
  }
});

// ----- 404 & ERROR HANDLER -----

app.use((req, res) => {
  return res.status(404).json({ error: 'Not found' });
});

// global error handler (za svaki slučaj)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Internal server error' });
});

// ---------- START SERVER ----------

async function start() {
  try {
    await seedDemoUsers();

    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  process.exit(0);
});
