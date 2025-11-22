// server.js

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient, SwipeDirection } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// ---------- CONFIG ----------

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const DAILY_SWIPE_LIMIT = Number(process.env.DAILY_SWIPE_LIMIT || 50);

// ---------- HELPERS ----------

function publicUser(user) {
  if (!user) return null;
  const { password, passwordHash, ...rest } = user;
  return rest;
}

function createToken(user) {
  return jwt.sign({ userId: user.id }, JWT_SECRET, {
    expiresIn: '30d',
  });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = header.substring('Bearer '.length);

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    console.error('JWT error', err);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Tinder backend up' });
});

// ---------- AUTH ROUTES ----------

app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, gender, age, bio } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name: name || '',
        email,
        passwordHash,
        gender: gender || null,
        age: age ?? null,
        bio: bio || '',
      },
    });

    const token = createToken(user);

    return res.json({
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error('Register error', err);
    return res.status(500).json({ error: 'Register failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash || '');
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = createToken(user);

    return res.json({
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
    });
    return res.json(publicUser(user));
  } catch (err) {
    console.error('auth/me error', err);
    return res.status(500).json({ error: 'Failed to load user' });
  }
});

app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
    });
    return res.json(publicUser(user));
  } catch (err) {
    console.error('GET /me error', err);
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

// ---------- PROFILE UPDATE (/me PUT) ----------

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

// ---------- RECOMMENDATIONS / FILTERS ----------

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

    const profiles = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    return res.json(profiles.map(publicUser));
  } catch (err) {
    console.error('GET /profiles/recommendations error', err);
    return res.status(500).json({ error: 'Failed to load profiles' });
  }
});

// ---------- SWIPES & MATCHING ----------

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

app.post('/swipes', async (req, res) => {
  try {
    const { fromUserId, toUserId, direction } = req.body;

    if (!fromUserId || !toUserId || !direction) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    if (!Object.values(SwipeDirection).includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe direction' });
    }

    const todaySwipes = await countTodaySwipes(fromUserId);

    if (todaySwipes >= DAILY_SWIPE_LIMIT) {
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

    let isMatch = false;
    let match = null;

    if (
      direction === SwipeDirection.like ||
      direction === SwipeDirection.superlike
    ) {
      const opposite = await prisma.swipe.findFirst({
        where: {
          fromUserId: toUserId,
          toUserId: fromUserId,
          direction: {
            in: [SwipeDirection.like, SwipeDirection.superlike],
          },
        },
      });

      if (opposite) {
        isMatch = true;

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
      match: isMatch,
      matchId: match ? match.id : null,
    });
  } catch (err) {
    console.error('POST /swipes error', err);
    return res.status(500).json({ error: 'Failed to record swipe' });
  }
});

async function handleUndoLastSwipe(req, res) {
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

    return res.json({
      success: true,
      undoneSwipeId: lastSwipe.id,
    });
  } catch (err) {
    console.error('POST /swipes/undo error', err);
    return res.status(500).json({ error: 'Failed to undo swipe' });
  }
}

app.post('/swipes/undo', handleUndoLastSwipe);
app.post('/swipes/undo-last', handleUndoLastSwipe);

// ---------- MATCHES & CHATS ----------

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
      const other =
        m.user1Id === userId ? publicUser(m.user2) : publicUser(m.user1);

      const lastMessage = m.messages[0] || null;

      return {
        id: m.id,
        otherUser: other,
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

app.get('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const matchId = req.params.matchId;

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

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

app.post('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const matchId = req.params.matchId;
    const { text } = req.body;

    if (!text || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'Text required' });
    }

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not your match' });
    }

    const message = await prisma.message.create({
      data: {
        matchId,
        senderId: userId,
        text: text.trim(),
      },
    });

    return res.json(message);
  } catch (err) {
    console.error('POST /matches/:matchId/messages error', err);
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// ---------- SEED DEMO USERS ----------

async function seedDemoUsers() {
  const passwordHash = await bcrypt.hash('password123', 10);

  const demoUsers = [
    {
      email: 'ana@example.com',
      name: 'Ana',
      age: 25,
      gender: 'female',
      bio: 'Voli putovanja i dobru hranu.',
      photoUrl: null,
    },
    {
      email: 'marko@example.com',
      name: 'Marko',
      age: 28,
      gender: 'male',
      bio: 'Gym, travel, good food.',
      photoUrl: null,
    },
    {
      email: 'lucija@example.com',
      name: 'Lucija',
      age: 27,
      gender: 'female',
      bio: 'Marketing, coffee, more coffee.',
      photoUrl: null,
    },
    {
      email: 'ivan@example.com',
      name: 'Ivan',
      age: 30,
      gender: 'male',
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

  console.log(
    'Seeded demo users (ana/marko/lucija/ivan @ example.com)'
  );
}

// ---------- START SERVER ----------

const PORT = process.env.PORT || 3000;

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
