require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { PrismaClient, SwipeDirection } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

// ---------- CONFIG ----------
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const DAILY_SWIPE_LIMIT = Number(process.env.DAILY_SWIPE_LIMIT || 50);
const PORT = process.env.PORT || 3000;

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Rate limiter for auth routes (protect from brute force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth requests. Please try again later.' },
});

// Rate limiter for swipes (prevent spam)
const swipeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many swipes, slow down a bit.' },
});

app.use('/auth', authLimiter);
app.use('/swipes', swipeLimiter);

// ---------- HELPERS ----------

// Hide passwordHash and keep only public fields
function publicUser(user) {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return rest;
}

// Basic email validation
function isValidEmail(email) {
  return typeof email === 'string' && /\S+@\S+\.\S+/.test(email);
}

// JWT auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing auth token' });
  }
  const token = authHeader.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    console.error('JWT error', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- SEED DEMO USERS ----------

async function seedDemoUsers() {
  const passwordHash = await bcrypt.hash('password123', 10);

  const demoUsers = [
    {
      email: 'ana@example.com',
      name: 'Ana',
      gender: 'female',
      age: 26,
      bio: 'I love coffee, books and sunsets.',
      photoUrl: null,
    },
    {
      email: 'marko@example.com',
      name: 'Marko',
      gender: 'male',
      age: 28,
      bio: 'Gym, travel, good food.',
      photoUrl: null,
    },
    {
      email: 'lucija@example.com',
      name: 'Lucija',
      gender: 'female',
      age: 24,
      bio: 'Designer & plant lover.',
      photoUrl: null,
    },
    {
      email: 'ivan@example.com',
      name: 'Ivan',
      gender: 'male',
      age: 30,
      bio: 'Software developer and gamer.',
      photoUrl: null,
    },
  ];

  for (const u of demoUsers) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: {
        ...u,
        passwordHash,
      },
    });
  }

  console.log('Seeded demo users (ana/marko/lucija/ivan @ example.com)');
}

// ---------- HEALTHCHECK ----------

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Tinder backend up' });
});

// ---------- AUTH ROUTES ----------

// Register new user
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, gender, age, bio } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (typeof password !== 'string' || password.length < 6) {
      return res
        .status(400)
        .json({ error: 'Password must be at least 6 characters' });
    }
    if (age !== undefined && age !== null) {
      const numAge = Number(age);
      if (Number.isNaN(numAge) || numAge < 18 || numAge > 99) {
        return res
          .status(400)
          .json({ error: 'Age must be between 18 and 99' });
      }
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
        name: name || '',
        bio: bio || '',
        gender: gender || null,
        age: age != null ? Number(age) : null,
      },
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: '30d',
    });

    return res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('POST /auth/register error', err);
    return res.status(500).json({ error: 'Failed to register' });
  }
});

// Login user
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash || '');
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: '30d',
    });

    return res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('POST /auth/login error', err);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

// Auth check (optional route)
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json(publicUser(user));
  } catch (err) {
    console.error('GET /auth/me error', err);
    return res.status(500).json({ error: 'Failed to load user' });
  }
});

// ---------- PROFILE ROUTES ----------

// Get current user's profile
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json(publicUser(user));
  } catch (err) {
    console.error('GET /me error', err);
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

// Update current user's profile
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
    console.error('PUT /me error', err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ---------- SMART RECOMMENDATIONS ----------

// Get recommended profiles for userId
app.get('/profiles/recommendations', async (req, res) => {
  try {
    const { userId, gender, minAge, maxAge } = req.query;

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ error: 'userId is required' });
    }

    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
    });
    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // All users this user has already swiped
    const swipes = await prisma.swipe.findMany({
      where: { fromUserId: userId },
      select: { toUserId: true },
    });
    const alreadySwipedIds = swipes.map((s) => s.toUserId);

    const minAgeNum = minAge ? Number(minAge) : undefined;
    const maxAgeNum = maxAge ? Number(maxAge) : undefined;

    const ageFilter = {};
    if (!Number.isNaN(minAgeNum)) ageFilter.gte = minAgeNum;
    if (!Number.isNaN(maxAgeNum)) ageFilter.lte = maxAgeNum;

    const where = {
      id: {
        not: userId,
        notIn: alreadySwipedIds,
      },
    };

    if (Object.keys(ageFilter).length > 0) {
      where.age = ageFilter;
    }

    if (
      typeof gender === 'string' &&
      gender.trim().length > 0 &&
      gender !== 'male/female/other'
    ) {
      where.gender = gender.trim();
    }

    // Base candidates
    const candidates = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    // If user hasn't liked anyone yet -> no smart sorting
    const likedSwipes = await prisma.swipe.findMany({
      where: {
        fromUserId: userId,
        direction: { in: [SwipeDirection.like, SwipeDirection.superlike] },
      },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });

    if (likedSwipes.length === 0) {
      return res.json(candidates.map(publicUser));
    }

    const likedIds = likedSwipes.map((s) => s.toUserId);
    const likedUsers = await prisma.user.findMany({
      where: { id: { in: likedIds } },
    });

    if (likedUsers.length === 0) {
      return res.json(candidates.map(publicUser));
    }

    // Calculate favorite gender and average age
    const genderCounts = {};
    let ageSum = 0;
    let ageCount = 0;

    for (const u of likedUsers) {
      if (u.gender) {
        genderCounts[u.gender] = (genderCounts[u.gender] || 0) + 1;
      }
      if (typeof u.age === 'number') {
        ageSum += u.age;
        ageCount += 1;
      }
    }

    let favoriteGender = null;
    let avgAge = null;

    if (Object.keys(genderCounts).length > 0) {
      favoriteGender = Object.entries(genderCounts).sort(
        (a, b) => b[1] - a[1]
      )[0][0];
    }

    if (ageCount > 0) {
      avgAge = ageSum / ageCount;
    }

    if (!favoriteGender && !avgAge) {
      return res.json(candidates.map(publicUser));
    }

    // Score candidates
    const scored = candidates
      .map((u) => {
        let score = 0;

        if (favoriteGender && u.gender === favoriteGender) {
          score += 2;
        }

        if (avgAge && typeof u.age === 'number') {
          const diff = Math.abs(u.age - avgAge);
          if (diff <= 2) score += 2;
          else if (diff <= 5) score += 1;
        }

        return { user: u, score };
      })
      .sort((a, b) => b.score - a.score)
      .map((x) => publicUser(x.user));

    return res.json(scored);
  } catch (err) {
    console.error('GET /profiles/recommendations error', err);
    return res.status(500).json({ error: 'Failed to load profiles' });
  }
});

// ---------- SWIPES + MATCHING ----------

// Count today's likes/superlikes for a user
async function countTodaySwipes(fromUserId) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const count = await prisma.swipe.count({
    where: {
      fromUserId,
      createdAt: { gte: startOfDay },
      direction: { in: [SwipeDirection.like, SwipeDirection.superlike] },
    },
  });
  return count;
}

// Create / update swipe, check for match
app.post('/swipes', async (req, res) => {
  try {
    const { fromUserId, toUserId, direction } = req.body;

    if (!fromUserId || !toUserId || !direction) {
      return res.status(400).json({ error: 'Missing swipe data' });
    }

    if (!Object.values(SwipeDirection).includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe direction' });
    }

    const [fromUser, toUser] = await Promise.all([
      prisma.user.findUnique({ where: { id: fromUserId } }),
      prisma.user.findUnique({ where: { id: toUserId } }),
    ]);

    if (!fromUser || !toUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const todaysSwipes = await countTodaySwipes(fromUserId);
    if (todaysSwipes >= DAILY_SWIPE_LIMIT) {
      return res.status(429).json({
        error: 'Daily swipe limit reached. Please come back tomorrow.',
        limit: DAILY_SWIPE_LIMIT,
      });
    }

    const existing = await prisma.swipe.findFirst({
      where: { fromUserId, toUserId },
    });

    let swipe;
    if (existing) {
      swipe = await prisma.swipe.update({
        where: { id: existing.id },
        data: { direction },
      });
    } else {
      swipe = await prisma.swipe.create({
        data: {
          fromUserId,
          toUserId,
          direction,
        },
      });
    }

    let match = null;
    if (direction === SwipeDirection.like || direction === SwipeDirection.superlike) {
      const opposite = await prisma.swipe.findFirst({
        where: {
          fromUserId: toUserId,
          toUserId: fromUserId,
          direction: { in: [SwipeDirection.like, SwipeDirection.superlike] },
        },
      });

      if (opposite) {
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
      success: true,
      swipeId: swipe.id,
      match: !!match,
      matchId: match ? match.id : null,
    });
  } catch (err) {
    console.error('POST /swipes error', err);
    return res.status(500).json({ error: 'Failed to send swipe' });
  }
});

// Undo last swipe helper
async function undoLastSwipeHandler(req, res) {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const lastSwipe = await prisma.swipe.findFirst({
      where: { fromUserId: userId },
      orderBy: { createdAt: 'desc' },
    });

    if (!lastSwipe) {
      return res.status(404).json({ error: 'No swipe to undo' });
    }

    await prisma.swipe.delete({ where: { id: lastSwipe.id } });

    if (
      lastSwipe.direction === SwipeDirection.like ||
      lastSwipe.direction === SwipeDirection.superlike
    ) {
      const match = await prisma.match.findFirst({
        where: {
          OR: [
            { user1Id: userId, user2Id: lastSwipe.toUserId },
            { user1Id: lastSwipe.toUserId, user2Id: userId },
          ],
        },
      });

      if (match) {
        await prisma.message.deleteMany({ where: { matchId: match.id } });
        await prisma.match.delete({ where: { id: match.id } });
      }
    }

    return res.json({ success: true, undoneSwipeId: lastSwipe.id });
  } catch (err) {
    console.error('POST /swipes/undo error', err);
    return res.status(500).json({ error: 'Failed to undo swipe' });
  }
}

// Undo routes
app.post('/swipes/undo', undoLastSwipeHandler);
app.post('/swipes/undo-last', undoLastSwipeHandler);

// ---------- MATCHES & MESSAGES ----------

// Get all matches for current user
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

    const now = Date.now();
    const ONLINE_WINDOW_MS = 5 * 60 * 1000; // 5 min

    const result = matches.map((m) => {
      const otherRaw = m.user1Id === userId ? m.user2 : m.user1;
      const lastActive = otherRaw.updatedAt || otherRaw.createdAt;
      const isOnline =
        lastActive && now - lastActive.getTime() < ONLINE_WINDOW_MS;

      const lastMessage = m.messages[0] || null;

      return {
        id: m.id,
        otherUser: {
          ...publicUser(otherRaw),
          isOnline,
        },
        createdAt: m.createdAt,
        lastMessage,
      };
    });

    return res.json(result);
  } catch (err) {
    console.error('GET /matches error', err);
    return res.status(500).json({ error: 'Failed to load matches' });
  }
});

// Get messages for specific match
app.get('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const matchId = req.params.matchId;

    const match = await prisma.match.findUnique({ where: { id: matchId } });
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }
    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not your match' });
    }

    const messages = await prisma.message.findMany({
      where: { matchId },
      orderBy: { createdAt: 'asc' },
    });

    return res.json(messages);
  } catch (err) {
    console.error('GET /matches/:matchId/messages error', err);
    return res.status(500).json({ error: 'Failed to load messages' });
  }
});

// Send message in match chat
app.post('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const matchId = req.params.matchId;
    const { text } = req.body;

    if (!text || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'Message text is required' });
    }

    const match = await prisma.match.findUnique({ where: { id: matchId } });
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }
    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not your match' });
    }

    const message = await prisma.message.create({
      data: {
        matchId,
        fromUserId: userId, // IMPORTANT: matches your Prisma model
        text: text.trim(),
      },
    });

    return res.status(201).json(message);
  } catch (err) {
    console.error('POST /matches/:matchId/messages error', err);
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// ---------- ANALYTICS / METRICS ----------

// Global summary
app.get('/analytics/summary', async (req, res) => {
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
    console.error('GET /analytics/summary error', err);
    return res.status(500).json({ error: 'Failed to load analytics' });
  }
});

// Per-user stats
app.get('/analytics/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const [swipesSent, swipesReceived, matchesCount, messagesSent] =
      await Promise.all([
        prisma.swipe.count({ where: { fromUserId: userId } }),
        prisma.swipe.count({ where: { toUserId: userId } }),
        prisma.match.count({
          where: {
            OR: [{ user1Id: userId }, { user2Id: userId }],
          },
        }),
        prisma.message.count({ where: { fromUserId: userId } }),
      ]);

    return res.json({
      user: publicUser(user),
      swipesSent,
      swipesReceived,
      matches: matchesCount,
      messagesSent,
    });
  } catch (err) {
    console.error('GET /analytics/user/:userId error', err);
    return res.status(500).json({ error: 'Failed to load user analytics' });
  }
});

// ---------- GLOBAL ERROR HANDLER ----------

app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'Internal server error' });
});

// ---------- START SERVER ----------

async function main() {
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

main();
