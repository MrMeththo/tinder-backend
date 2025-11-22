// server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

app.use(cors());
app.use(express.json());

// ---------- HELPERS ----------

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    age: user.age,
    bio: user.bio,
    gender: user.gender,
    photoUrl: user.photoUrl || null,
  };
}

function createToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Invalid Authorization header' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    console.error('JWT verify error', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Demo seed – upsert par usera
async function seedDemoUsers() {
  const demoUsers = [
    {
      name: 'Ana',
      email: 'ana@example.com',
      password: 'password123',
      age: 25,
      gender: 'female',
      bio: 'Volim putovanja i kavu.',
    },
    {
      name: 'Marko',
      email: 'marko@example.com',
      password: 'password123',
      age: 28,
      gender: 'male',
      bio: 'Programer iz Zagreba.',
    },
    {
      name: 'Lucija',
      email: 'lucija@example.com',
      password: 'password123',
      age: 23,
      gender: 'female',
      bio: 'Fitness, glazba i Netflix.',
    },
    {
      name: 'Ivan',
      email: 'ivan@example.com',
      password: 'password123',
      age: 30,
      gender: 'male',
      bio: 'Volim more i jedrenje.',
    },
  ];

  for (const demo of demoUsers) {
    const existing = await prisma.user.findUnique({
      where: { email: demo.email },
    });
    if (!existing) {
      const passwordHash = await bcrypt.hash(demo.password, 10);
      await prisma.user.create({
        data: {
          name: demo.name,
          email: demo.email,
          passwordHash,
          age: demo.age,
          gender: demo.gender,
          bio: demo.bio,
        },
      });
    }
  }

  console.log('Seeded demo users (ana/marko/lucija/ivan @ example.com)');
}

// ---------- ROUTES ----------

// simple health
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

// REGISTER
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, age, bio, gender } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: 'Name, email and password are required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'User with that email exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash,
        age: age ?? null,
        bio: bio ?? null,
        gender: gender ?? null,
      },
    });

    const token = createToken(user.id);

    return res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('Register error', err);
    return res.status(500).json({ error: 'Failed to register' });
  }
});

// LOGIN
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

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = createToken(user.id);
    return res.json({ token, user: publicUser(user) });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

// CURRENT USER
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
    console.error(err);
    return res.status(500).json({ error: 'Failed to get user' });
  }
});

// UPDATE PROFILE (name, age, bio, gender, photoUrl)
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
    console.error(err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// RECOMMENDATIONS + FILTERI
app.get('/profiles/recommendations', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { gender, minAge, maxAge } = req.query;

    const userSwipes = await prisma.swipe.findMany({
      where: { fromUserId: userId },
      select: { toUserId: true },
    });

    const excludedIds = [
      userId,
      ...userSwipes.map((s) => s.toUserId),
    ];

    const where = {
      id: { notIn: excludedIds },
    };

    if (typeof gender === 'string' && gender.trim().length > 0) {
      where.gender = gender.trim();
    }

    if (minAge || maxAge) {
      where.age = {};
      if (minAge) {
        const n = Number(minAge);
        if (!Number.isNaN(n)) {
          where.age.gte = n;
        }
      }
      if (maxAge) {
        const n = Number(maxAge);
        if (!Number.isNaN(n)) {
          where.age.lte = n;
        }
      }
    }

    const users = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    return res.json(users.map(publicUser));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to load recommendations' });
  }
});

// CREATE SWIPE (like / pass / superlike)
app.post('/swipes', authMiddleware, async (req, res) => {
  try {
    const fromUserId = req.userId;
    const { toUserId, direction } = req.body;

    if (!toUserId || !direction) {
      return res
        .status(400)
        .json({ error: 'toUserId and direction are required' });
    }

    const allowedDirections = ['like', 'pass', 'superlike'];
    if (!allowedDirections.includes(direction)) {
      return res.status(400).json({
        error: 'direction must be like, pass or superlike',
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

    if (direction === 'like' || direction === 'superlike') {
      const oppositeLike = await prisma.swipe.findFirst({
        where: {
          fromUserId: toUserId,
          toUserId: fromUserId,
          direction: {
            in: ['like', 'superlike'],
          },
        },
      });

      if (oppositeLike) {
        isMatch = true;

        const [user1Id, user2Id] =
          fromUserId < toUserId
            ? [fromUserId, toUserId]
            : [toUserId, fromUserId];

        await prisma.match.upsert({
          where: {
            user1Id_user2Id: { user1Id, user2Id },
          },
          update: {},
          create: { user1Id, user2Id },
        });
      }
    }

    return res.json({ match: isMatch, swipeId: swipe.id });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to create swipe' });
  }
});

// UNDO LAST SWIPE
app.post('/swipes/undo', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    const lastSwipe = await prisma.swipe.findFirst({
      where: { fromUserId: userId },
      orderBy: { createdAt: 'desc' },
    });

    if (!lastSwipe) {
      return res.status(400).json({ error: 'No swipes to undo' });
    }

    await prisma.swipe.delete({ where: { id: lastSwipe.id } });

    let removedMatch = false;

    if (lastSwipe.direction === 'like' || lastSwipe.direction === 'superlike') {
      const remainingAtoB = await prisma.swipe.findFirst({
        where: {
          fromUserId: userId,
          toUserId: lastSwipe.toUserId,
          direction: { in: ['like', 'superlike'] },
        },
      });
      const remainingBtoA = await prisma.swipe.findFirst({
        where: {
          fromUserId: lastSwipe.toUserId,
          toUserId: userId,
          direction: { in: ['like', 'superlike'] },
        },
      });

      if (!remainingAtoB || !remainingBtoA) {
        const [user1Id, user2Id] =
          userId < lastSwipe.toUserId
            ? [userId, lastSwipe.toUserId]
            : [lastSwipe.toUserId, userId];

        const match = await prisma.match.findUnique({
          where: {
            user1Id_user2Id: { user1Id, user2Id },
          },
        });

        if (match) {
          await prisma.message.deleteMany({
            where: { matchId: match.id },
          });
          await prisma.match.delete({ where: { id: match.id } });
          removedMatch = true;
        }
      }
    }

    return res.json({
      undone: true,
      removedMatch,
      lastSwipe: {
        id: lastSwipe.id,
        toUserId: lastSwipe.toUserId,
        direction: lastSwipe.direction,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to undo swipe' });
  }
});

// MATCHES LIST
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
        lastMessage,
      };
    });

    return res.json(result);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to load matches' });
  }
});

// MESSAGES IN MATCH
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
      return res.status(403).json({ error: 'Not part of this match' });
    }

    const messages = await prisma.message.findMany({
      where: { matchId },
      orderBy: { createdAt: 'asc' },
    });

    return res.json(messages);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to load messages' });
  }
});

// SEND MESSAGE
app.post('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { matchId } = req.params;
    const { text } = req.body;

    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Text is required' });
    }

    const match = await prisma.match.findUnique({
      where: { id: matchId },
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.user1Id !== userId && match.user2Id !== userId) {
      return res.status(403).json({ error: 'Not part of this match' });
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
    console.error(err);
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// ---------- START SERVER ----------

async function start() {
  try {
    await prisma.$connect();
    await seedDemoUsers();

    app.listen(PORT, () => {
      console.log(`API server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}

start();
