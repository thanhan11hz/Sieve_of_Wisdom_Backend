import Fastify from 'fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();

const fastify = Fastify({ logger: true });
const prisma = new PrismaClient();

// Register JWT
fastify.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'fallback_secret_key',
});

// Middleware Authenticate
fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.status(401).send({ status: 401, message: 'Unauthorized or Token expired' });
  }
});

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

// -----------------------------------------------------------------------------
// 1. AUTH ROUTES
// -----------------------------------------------------------------------------

// Register User (Cần username, email, password)
fastify.post('/api/auth/register', async (request, reply) => {
  const { username, email, password } = request.body as { 
    username?: string; 
    email?: string; 
    password?: string 
  };

  if (!username || !email || !password) {
    return reply.status(400).send({ message: 'Missing fields: username, email, password' });
  }

  // 1. Kiểm tra username đã tồn tại chưa (Dùng findUnique vì username có @unique)
  const existingUsername = await prisma.user.findUnique({ where: { username } });
  if (existingUsername) {
    return reply.status(400).send({ message: 'Username is already taken' });
  }

  // 2. Kiểm tra email đã tồn tại chưa (Dùng findFirst vì email KHÔNG có @unique trong Schema)
  const existingEmail = await prisma.user.findFirst({ where: { email } });
  if (existingEmail) {
    return reply.status(400).send({ message: 'Email is already taken' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: { 
      username,
      email,
      password: hashedPassword, 
      coin: 100 
    },
  });

  return reply.send({ message: 'User created successfully', user_id: user.id });
});

// Login (Chỉ cần username & password)
fastify.post('/api/auth/login', async (request, reply) => {
  const { username, password } = request.body as { username?: string; password?: string };

  if (!username || !password) {
    return reply.status(400).send({ message: 'Missing username or password' });
  }

  // Tìm theo username (findUnique hợp lệ vì username có @unique)
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return reply.status(401).send({ message: 'Invalid username or password' });
  }

  const accessToken = fastify.jwt.sign({ userId: user.id }, { expiresIn: '15m' });
  const refreshToken = fastify.jwt.sign({ userId: user.id }, { expiresIn: '30d' });

  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken },
  });

  return reply.send({
    user_id: user.id,
    username: user.username,
    email: user.email,
    coin: user.coin,
    access_token: accessToken,
    refresh_token: refreshToken,
  });
});

// Refresh Token
fastify.post('/api/auth/refresh', async (request, reply) => {
  const { refresh_token } = request.body as { refresh_token?: string };
  if (!refresh_token) return reply.status(400).send({ message: 'Missing refresh token' });

  try {
    const decoded = fastify.jwt.verify<{ userId: number }>(refresh_token);
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

    if (!user || user.refreshToken !== refresh_token) {
      return reply.status(401).send({ message: 'Invalid refresh token' });
    }

    const newAccessToken = fastify.jwt.sign({ userId: user.id }, { expiresIn: '15m' });
    const newRefreshToken = fastify.jwt.sign({ userId: user.id }, { expiresIn: '30d' });

    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: newRefreshToken },
    });

    return reply.send({
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    });
  } catch (err) {
    return reply.status(401).send({ message: 'Expired or invalid refresh token' });
  }
});

// -----------------------------------------------------------------------------
// 2. SYNC ROUTES
// -----------------------------------------------------------------------------
// Sync Category
fastify.get('/api/sync/category', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { last_updated } = request.query as { last_updated?: string };
    const lastUpdatedTimestamp = Number(last_updated || 0);

    const categories = await prisma.category.findMany({
      where: {
        updatedAt: { gt: new Date(lastUpdatedTimestamp) },
      },
    });

    const response = categories.map((c) => ({
      id: c.id,
      name: c.name,
      classification: c.classification,
      price: c.price,
    }));

    return reply.send(response);
  });

// Sync Access
fastify.post('/api/sync/access', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { user_id, category_ids } = request.body as { user_id: number; category_ids: number[] };

  if (!user_id || !Array.isArray(category_ids)) {
    return reply.status(400).send({ message: 'Invalid body params' });
  }

  const data = category_ids.map((catId) => ({ userId: user_id, categoryId: catId }));

  await prisma.access.createMany({
    data,
    skipDuplicates: true,
  });

  return reply.send({ success: true });
});

// Get User Access
fastify.get(
  '/api/sync/access',
  { onRequest: [fastify.authenticate] },
  async (request, reply) => {
    const { user_id } = request.query as {
      user_id?: string;
    };

    if (!user_id) {
      return reply.status(400).send({
        message: 'Missing user_id',
      });
    }

    const userId = Number(user_id);

    const accesses = await prisma.access.findMany({
      where: {
        userId,
      },
      select: {
        userId: true,
        categoryId: true,
      },
    });

    return reply.send(
      accesses.map((access) => ({
        user_id: access.userId,
        category_id: access.categoryId,
      }))
    );
  }
);

// Sync Coin
fastify.post('/api/sync/coin', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { user_id, coin } = request.body as { user_id: number; coin: number };

  if (user_id === undefined || coin === undefined) {
    return reply.status(400).send({ message: 'Missing user_id or coin' });
  }

  await prisma.user.update({
    where: { id: user_id },
    data: { coin },
  });

  return reply.send({ success: true });
});

// Sync Questions (Delta Sync & Ép kiểu BigInt -> Number)
fastify.get('/api/sync/questions', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { last_updated } = request.query as { last_updated?: string };
  const lastUpdatedTimestamp = Number(last_updated || 0);

  const questions = await prisma.question.findMany({
    where: {
      updatedAt: { gt: new Date(lastUpdatedTimestamp) },
    },
    include: {
      answers: true,
    },
  });

  const response = questions.map((q) => ({
    id: Number(q.id),
    category_id: q.categoryId,
    asking: q.asking,
    answers: q.answers.map((a) => a.answering),
  }));

  return reply.send(response);
});

// Start Server
const start = async () => {
  try {
    const port = Number(process.env.PORT) || 3000;
    await fastify.listen({ port, host: '0.0.0.0' });
    console.log(`Server is running at http://localhost:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();