import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-fintrack';

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Support foto profil besar

// --- ROOT ROUTE (Untuk cek apakah Vercel jalan) ---
app.get('/', (req: Request, res: Response) => {
  res.send('🚀 Backend FinTrack API Berjalan Normal di Vercel!');
});

// --- MIDDLEWARE KEAMANAN ---
const authenticateToken = (req: any, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Akses ditolak!" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next(); 
  } catch (error) {
    res.status(403).json({ error: "Token tidak valid!" });
  }
};

// ==========================================
// --- ROUTES AUTH & USER ---
// ==========================================

app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await prisma.user.create({ data: { name, email, password: hashedPassword } });
    res.status(201).json({ message: "User berhasil dibuat!" });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Email atau password salah!" });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.get('/api/auth/me', authenticateToken, async (req: any, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, name: true, email: true, role: true, avatar: true, phone: true }
    });
    if (!user) return res.status(404).json({ error: "User tidak ditemukan!" });
    res.json(user);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.put('/api/auth/profile', authenticateToken, async (req: any, res: Response) => {
  try {
    const { name, role, phone, avatar } = req.body;
    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: { name, role, phone, avatar },
      select: { id: true, name: true, email: true, role: true, phone: true, avatar: true }
    });
    res.json({ message: "Profil berhasil diperbarui!", user: updatedUser });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

// ==========================================
// --- ROUTES TRANSACTIONS ---
// ==========================================

app.get('/api/transactions', authenticateToken, async (req: any, res: Response) => {
  const data = await prisma.transaction.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' } });
  res.json(data);
});

app.post('/api/transactions', authenticateToken, async (req: any, res: Response) => {
  try {
    const newTx = await prisma.transaction.create({ data: { ...req.body, userId: req.user.id } });
    res.status(201).json(newTx);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.put('/api/transactions/:id', authenticateToken, async (req: any, res: Response) => {
  try {
    const updated = await prisma.transaction.update({
      where: { id: req.params.id, userId: req.user.id },
      data: req.body
    });
    res.json(updated);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/transactions/:id', authenticateToken, async (req: any, res: Response) => {
  await prisma.transaction.delete({ where: { id: req.params.id, userId: req.user.id } });
  res.json({ message: "Dihapus!" });
});

// ==========================================
// --- ROUTES SAVING GOALS ---
// ==========================================

app.get('/api/goals', authenticateToken, async (req: any, res: Response) => {
  const data = await prisma.goal.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' } });
  res.json(data);
});

app.post('/api/goals', authenticateToken, async (req: any, res: Response) => {
  try {
    const { name, target, term } = req.body;
    const newGoal = await prisma.goal.create({ 
      data: { name, target: parseFloat(target), term: parseInt(term), userId: req.user.id } 
    });
    res.status(201).json(newGoal);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/goals/:id', authenticate, async (req: any, res: Response) => {
  await prisma.goal.delete({ where: { id: req.params.id, userId: req.user.id } });
  res.json({ message: "Goal dihapus!" });
});

// ==========================================
// --- ROUTES BUDGET SETTINGS ---
// ==========================================

app.get('/api/budget', authenticateToken, async (req: any, res: Response) => {
  try {
    let budget = await prisma.budget.findUnique({ where: { userId: req.user.id } });
    if (!budget) budget = await prisma.budget.create({ data: { userId: req.user.id } });
    res.json(budget);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.put('/api/budget', authenticateToken, async (req: any, res: Response) => {
  try {
    const budget = await prisma.budget.upsert({
      where: { userId: req.user.id },
      update: req.body,
      create: { ...req.body, userId: req.user.id }
    });
    res.json(budget);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

// ==========================================
// --- ROUTES SUBSCRIPTIONS ---
// ==========================================

app.get('/api/subscriptions', authenticateToken, async (req: any, res: Response) => {
  const data = await prisma.subscription.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' } });
  res.json(data);
});

app.post('/api/subscriptions', authenticateToken, async (req: any, res: Response) => {
  try {
    const { name, amount, dueDate, category } = req.body;
    const newSub = await prisma.subscription.create({ 
      data: { name, amount: parseFloat(amount), dueDate, category, userId: req.user.id } 
    });
    res.status(201).json(newSub);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.put('/api/subscriptions/:id/toggle', authenticateToken, async (req: any, res: Response) => {
  try {
    const sub = await prisma.subscription.findUnique({ where: { id: req.params.id } });
    if (sub) {
      const updated = await prisma.subscription.update({
        where: { id: req.params.id },
        data: { isPaid: !sub.isPaid }
      });
      res.json(updated);
    }
  } catch (error: any) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/subscriptions/:id', authenticateToken, async (req: any, res: Response) => {
  await prisma.subscription.delete({ where: { id: req.params.id, userId: req.user.id } });
  res.json({ message: "Sub dihapus!" });
});

// Jalankan server untuk testing lokal
app.listen(PORT, () => console.log(`✅ Akses Servermu di Port ini: ${PORT}`));

// 👇 INI YANG PALING PENTING UNTUK VERCEL 👇
export default app;