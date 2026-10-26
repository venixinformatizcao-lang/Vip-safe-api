// VIP Central - API HTTPS + WebSocket + painel autenticado
const express = require('express');
const cors = require('cors');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;           // OBRIGATORIO em producao
const DEVICE_TOKEN = process.env.DEVICE_TOKEN;       // token que os apps enviam
const ADMIN_USER = process.env.ADMIN_USER || 'central';
const ADMIN_PASS = process.env.ADMIN_PASS;           // OBRIGATORIO em producao
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'alerts.json');

if (!JWT_SECRET || !DEVICE_TOKEN || !ADMIN_PASS) {
  console.error('Defina JWT_SECRET, DEVICE_TOKEN e ADMIN_PASS nas variaveis de ambiente.');
  process.exit(1);
}
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASS, 10);

// ---------- armazenamento simples em arquivo (trocar por Postgres em producao) ----------
let alerts = {};
try { alerts = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { alerts = {}; }
let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { try { fs.writeFileSync(DATA_FILE, JSON.stringify(alerts)); } catch (e) { console.error('persist', e.message); } }, 500);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '50kb' }));
app.use(cors({
  origin: (origin, cb) => (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) ? cb(null, true) : cb(new Error('Origem nao permitida')),
}));

// limitador simples por IP
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path, now = Date.now();
    const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
    arr.push(now); hits.set(k, arr);
    if (arr.length > max) return res.status(429).json({ error: 'Muitas requisicoes' });
    next();
  };
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ---------- WebSocket ----------
const server = http.createServer(app);
const wssCentral = new WebSocketServer({ noServer: true });
const centralClients = new Set();
function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const ws of centralClients) if (ws.readyState === 1) ws.send(data);
}

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws/central') return socket.destroy();
  try {
    jwt.verify(url.searchParams.get('token') || '', JWT_SECRET);
  } catch (e) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
  wssCentral.handleUpgrade(req, socket, head, ws => {
    centralClients.add(ws);
    ws.on('close', () => centralClients.delete(ws));
    ws.send(JSON.stringify({ type: 'SNAPSHOT', alerts: Object.values(alerts) }));
  });
});

// ---------- autenticacao do painel ----------
app.post('/api/login', rateLimit(10, 60_000), (req, res) => {
  const { user, pass } = req.body || {};
  if (!user || !pass || !safeEqual(user, ADMIN_USER) || !bcrypt.compareSync(String(pass), ADMIN_HASH))
    return res.status(401).json({ error: 'Credenciais invalidas' });
  const token = jwt.sign({ role: 'central', user }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});
function requireCentral(req, res, next) {
  try { req.auth = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Nao autorizado' }); }
}
function requireDevice(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (!t || !safeEqual(t, DEVICE_TOKEN)) return res.status(401).json({ error: 'Token do dispositivo invalido' });
  next();
}

// ---------- recepcao dos apps (VIP SAFE e VIP SOS) ----------
// Formato aceito (compativel com o VIP SAFE original):
// { type, client, phone, event_id, timestamp, location:{latitude,longitude,accuracy_m}, source }
const TYPES = ['SOS', 'LOCATION_UPDATE', 'CANCELLED', 'RESOLVED', 'CONNECTION_TEST'];
app.post('/api/alerts', rateLimit(120, 60_000), requireDevice, (req, res) => {
  const b = req.body || {};
  if (!TYPES.includes(b.type)) return res.status(400).json({ error: 'type invalido' });
  const client = String(b.client || 'VIP sem identificacao').slice(0, 80);
  if (b.type === 'CONNECTION_TEST') return res.status(200).json({ ok: true, test: true });

  const id = String(b.event_id || '').slice(0, 64);
  if (!id) return res.status(400).json({ error: 'event_id obrigatorio' });

  let a = alerts[id];
  if (!a) {
    if (b.type !== 'SOS') return res.status(404).json({ error: 'ocorrencia desconhecida' });
    a = alerts[id] = { id, client, phone: String(b.phone || '').slice(0, 30), source: String(b.source || 'app').slice(0, 20),
      status: 'ATIVO', createdAt: new Date().toISOString(), acknowledgedAt: null, closedAt: null, track: [] };
  }
  const loc = b.location;
  if (loc && Number.isFinite(+loc.latitude) && Number.isFinite(+loc.longitude)) {
    a.track.push({ t: new Date().toISOString(), lat: +loc.latitude, lon: +loc.longitude, acc: +loc.accuracy_m || null });
    if (a.track.length > 2000) a.track.shift();
  }
  if (b.type === 'CANCELLED') { a.status = 'CANCELADO_PELO_VIP'; a.closedAt = new Date().toISOString(); }
  if (b.type === 'RESOLVED')  { a.status = 'ENCERRADO'; a.closedAt = new Date().toISOString(); }
  persist();
  broadcast({ type: b.type === 'SOS' ? 'NEW_ALERT' : 'UPDATE', alert: a });
  res.status(201).json({ ok: true, event_id: id, status: a.status });
});

// ---------- API do painel ----------
app.get('/api/alerts', requireCentral, (req, res) => res.json(Object.values(alerts)));
app.post('/api/alerts/:id/ack', requireCentral, (req, res) => {
  const a = alerts[req.params.id]; if (!a) return res.sendStatus(404);
  a.acknowledgedAt = new Date().toISOString(); a.status = 'RECEBIDO_PELA_CENTRAL'; persist();
  broadcast({ type: 'UPDATE', alert: a }); res.json(a);
});
app.post('/api/alerts/:id/close', requireCentral, (req, res) => {
  const a = alerts[req.params.id]; if (!a) return res.sendStatus(404);
  a.closedAt = new Date().toISOString(); a.status = 'ENCERRADO'; persist();
  broadcast({ type: 'UPDATE', alert: a }); res.json(a);
});

app.get('/health', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

server.listen(PORT, () => console.log('VIP Central na porta ' + PORT));
