const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_CODE = process.env.ADMIN_CODE || '';
if (ADMIN_CODE.length !== 32) {
  console.error('ҚАТЕ: Render Environment ішінде ADMIN_CODE дәл 32 таңба болуы керек.');
  process.exit(1);
}
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
if (JWT_SECRET.length < 32) {
  console.error('ҚАТЕ: JWT_SECRET кемінде 32 таңбадан тұруы керек.');
  process.exit(1);
}

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], messages: [], anonymousMessages: [] }, null, 2));
}
let db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
db.users ||= [];
db.messages ||= [];
db.anonymousMessages ||= [];
let saveQueue = Promise.resolve();
function saveDb() {
  const snapshot = JSON.stringify(db, null, 2);
  saveQueue = saveQueue.then(async () => {
    const tmp = DB_FILE + '.tmp';
    await fs.promises.writeFile(tmp, snapshot);
    await fs.promises.rename(tmp, DB_FILE);
  });
  return saveQueue;
}
function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt };
}
function makeUserToken(user) { return jwt.sign({ sub: user.id, role: 'user' }, JWT_SECRET, { expiresIn: '14d' }); }
function getBearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}
function requireAuth(req, res, next) {
  try {
    const p = jwt.verify(getBearer(req), JWT_SECRET);
    const user = db.users.find(u => u.id === p.sub);
    if (!user) return res.status(401).json({ error: 'Алдымен аккаунтқа кіріңіз.' });
    req.user = user;
    next();
  } catch { return res.status(401).json({ error: 'Алдымен аккаунтқа кіріңіз.' }); }
}
function requireAdmin(req, res, next) {
  try {
    const p = jwt.verify(getBearer(req), JWT_SECRET);
    if (p.role !== 'admin') throw new Error('forbidden');
    req.admin = true;
    next();
  } catch { return res.status(401).json({ error: 'Админ рұқсаты жоқ немесе сессия аяқталған.' }); }
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const attempts = new Map();
function rateLimit(key, max = 8, windowMs = 60000) {
  const now = Date.now();
  const list = (attempts.get(key) || []).filter(t => now - t < windowMs);
  if (list.length >= max) { attempts.set(key, list); return false; }
  list.push(now); attempts.set(key, list); return true;
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!rateLimit('reg:' + req.ip, 5)) return res.status(429).json({ error: 'Тым көп сұраныс. Кейін қайталаңыз.' });
    if (name.length < 2 || name.length > 24) return res.status(400).json({ error: 'Атыңыз 2–24 таңба болуы керек.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return res.status(400).json({ error: 'Email мекенжайын дұрыс жазыңыз.' });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Құпиясөз 8–72 таңба болуы керек.' });
    if (db.users.some(u => u.email === email)) return res.status(409).json({ error: 'Бұл email бұрын тіркелген.' });
    const user = { id: crypto.randomUUID(), name, email, passwordHash: await bcrypt.hash(password, 12), createdAt: new Date().toISOString() };
    db.users.push(user); await saveDb();
    res.status(201).json({ token: makeUserToken(user), user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Сервер қатесі.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!rateLimit('login:' + req.ip, 10)) return res.status(429).json({ error: 'Кіру әрекеті тым көп. Кейін қайталаңыз.' });
    const user = db.users.find(u => u.email === email);
    if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Email немесе құпиясөз қате.' });
    res.json({ token: makeUserToken(user), user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Сервер қатесі.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    if (!googleClient) return res.status(503).json({ error: 'Google авторизациясы серверде бапталмаған.' });
    const credential = String(req.body.credential || '');
    if (!credential) return res.status(400).json({ error: 'Google credential жоқ.' });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload || !payload.email || !payload.email_verified) return res.status(401).json({ error: 'Google аккаунтын растау мүмкін болмады.' });
    const email = payload.email.toLowerCase();
    let user = db.users.find(u => u.email === email);
    if (!user) {
      user = { id: crypto.randomUUID(), name: String(payload.name || email.split('@')[0]).slice(0, 24), email, passwordHash: null, createdAt: new Date().toISOString(), provider: 'google' };
      db.users.push(user); await saveDb();
    }
    res.json({ token: makeUserToken(user), user: publicUser(user) });
  } catch (e) { console.error('Google auth:', e.message); res.status(401).json({ error: 'Google арқылы кіру сәтсіз аяқталды.' }); }
});

app.post('/api/admin/login', (req, res) => {
  const code = String(req.body.code || '');
  if (!rateLimit('admin:' + req.ip, 5, 60000)) return res.status(429).json({ error: 'Тым көп әрекет. Кейін қайталаңыз.' });
  if (code !== ADMIN_CODE) return res.status(401).json({ error: 'Админ коды қате.' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
});
app.get('/api/admin/students', requireAdmin, (req, res) => {
  res.json({ students: db.users.map(publicUser).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});
app.post('/api/admin/students/:id/reset-password', requireAdmin, async (req, res) => {
  try {
    const password = String(req.body.password || '');
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Жаңа құпиясөз 8–72 таңба болуы керек.' });
    const student = db.users.find(u => u.id === req.params.id);
    if (!student) return res.status(404).json({ error: 'Оқушы табылмады.' });
    student.passwordHash = await bcrypt.hash(password, 12);
    await saveDb();
    res.json({ ok: true, message: 'Оқушының құпиясөзі жаңартылды.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Құпиясөзді жаңарту мүмкін болмады.' }); }
});

app.post('/api/anonymous/session', (req, res) => {
  const oldToken = String(req.body.token || '');
  if (oldToken) {
    try {
      const p = jwt.verify(oldToken, JWT_SECRET);
      if (p.role === 'anonymous' && p.anonymousId) return res.json({ token: oldToken, anonymousId: p.anonymousId });
    } catch { /* issue a fresh anonymous session */ }
  }
  const anonymousId = 'ANON-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const token = jwt.sign({ role: 'anonymous', anonymousId }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, anonymousId });
});
app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.get('/api/messages', requireAuth, (req, res) => res.json({ messages: db.messages.slice(-100) }));
app.get('/api/health', (req, res) => res.json({ ok: true, users: db.users.length, chatMessages: db.anonymousMessages.length }));

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.anonymousToken;
    const p = jwt.verify(String(token || ''), JWT_SECRET);
    if (p.role !== 'anonymous' || !p.anonymousId) throw new Error('bad anonymous token');
    socket.anonymousId = p.anonymousId;
    next();
  } catch { next(new Error('Аноним сессия аяқталды. Бетті жаңартыңыз.')); }
});
io.on('connection', socket => {
  socket.emit('chat:history', db.anonymousMessages.slice(-100));
  socket.emit('chat:online', io.engine.clientsCount);
  socket.on('chat:send', async payload => {
    const text = String(payload?.text || '').trim();
    if (!text || text.length > 1000) return;
    if (!rateLimit('anonmsg:' + socket.anonymousId, 12, 10000)) {
      socket.emit('chat:error', { message: 'Тым жиі жазып жатырсыз. Сәл күтіңіз.' }); return;
    }
    const message = { id: crypto.randomUUID(), anonymousId: socket.anonymousId, text, createdAt: new Date().toISOString() };
    db.anonymousMessages.push(message);
    if (db.anonymousMessages.length > 1000) db.anonymousMessages = db.anonymousMessages.slice(-1000);
    try {
      await saveDb();
      io.emit('chat:message', message);
    } catch (e) { console.error(e); socket.emit('chat:error', { message: 'Хабарламаны сақтау мүмкін болмады.' }); }
  });
  socket.on('disconnect', () => io.emit('chat:online', io.engine.clientsCount));
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API жолы табылмады.' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => { if (err) next(err); });
});

server.listen(PORT, () => console.log(`KITOTEST сервері іске қосылды: порт ${PORT}`));
