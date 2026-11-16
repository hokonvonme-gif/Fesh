require('dotenv').config();

const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const multer = require('multer');

// ─────────────────────────────────────────────
// MODELS
// ─────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  displayName: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  country: { type: String, trim: true, maxlength: 80, default: '' },
  program: { type: String, trim: true, maxlength: 120, default: '' },
  photoUrl: { type: String, default: '' },
  statusText: { type: String, trim: true, maxlength: 140, default: '' },
  statusMediaUrl: { type: String, default: '' },
  statusType: { type: String, enum: ['', 'text', 'image', 'video'], default: '' },
  statusAt: { type: Date },
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['private', 'group'], default: 'private' },
  title: { type: String, trim: true, default: '' },
  description: { type: String, trim: true, default: '' },
  // Communautés publiques (n'importe qui peut les rejoindre)
  isPublic: { type: Boolean, default: false },
  slug: { type: String, trim: true, index: true, sparse: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastMessage: {
    text: { type: String, default: '' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date },
  },
}, { timestamps: true });
conversationSchema.index({ participants: 1, updatedAt: -1 });

const messageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true, index: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['text', 'image', 'audio', 'file'], default: 'text' },
  text: { type: String, trim: true, maxlength: 5000, default: '' },
  mediaUrl: { type: String, default: '' },
  fileName: { type: String, default: '' },
  mimeType: { type: String, default: '' },
  durationMs: { type: Number, default: 0 },
}, { timestamps: true });
messageSchema.index({ conversationId: 1, createdAt: -1 });

const mediaSchema = new mongoose.Schema({
  data: { type: Buffer, required: true, select: false },
  fileName: { type: String, default: '' },
  mimeType: { type: String, default: 'application/octet-stream' },
  size: { type: Number, default: 0 },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const Media = mongoose.model('Media', mediaSchema);

const DEFAULT_COMMUNITIES = [
  { slug: 'international', title: 'Étudiants internationaux', description: 'Accueil et partage d’expériences' },
  { slug: 'arrival', title: 'Préparer son arrivée', description: 'Documents, voyage, démarches' },
  { slug: 'housing', title: 'Logement à Accra', description: 'Colocs, quartiers et bons plans' },
  { slug: 'admission', title: 'Admissions & visa', description: 'Étapes, dossiers et conseils' },
  { slug: 'daily-life', title: 'Vie à Accra', description: 'Transport, nourriture, budget' },
  { slug: 'engineering', title: 'Génie électrique', description: 'Cours, projets et entraide' },
];

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function createToken(userId) {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET manquant.');
  return jwt.sign({ sub: userId.toString() }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

function publicUser(user) {
  return {
    id: user._id,
    displayName: user.displayName,
    email: user.email,
    country: user.country,
    program: user.program,
    photoUrl: user.photoUrl || '',
    statusText: user.statusText || '',
    statusMediaUrl: user.statusMediaUrl || '',
    statusType: user.statusType || '',
    statusAt: user.statusAt || null,
  };
}

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ success: false, message: 'Authentification requise.' });
    }
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub).select('_id displayName email country program photoUrl statusText statusMediaUrl statusType statusAt');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Compte introuvable.' });
    }
    req.user = user;
    next();
  } catch (_error) {
    return res.status(401).json({ success: false, message: 'Jeton invalide ou expiré.' });
  }
}

// ─────────────────────────────────────────────
// APP + SOCKET.IO
// ─────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
app.set('trust proxy', 1); // Render / reverse proxy

const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map((o) => o.trim());

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origine non autorisée par CORS.'));
  },
}));
app.use(express.json({ limit: '2mb' }));

// Médias stockés dans MongoDB (pas de disque éphémère Render)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 }, // 12 MB (limite document MongoDB = 16 MB)
  fileFilter: (_req, file, cb) => {
    const ok = /^(image|audio|video|application)\//.test(file.mimetype) || file.mimetype === 'text/plain';
    cb(ok ? null : new Error('Type de fichier non autorisé.'), ok);
  },
});

app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const io = new Server(server, {
  cors: { origin: allowedOrigins.includes('*') ? '*' : allowedOrigins, methods: ['GET', 'POST'] },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Trop de tentatives. Réessaie dans quelques minutes.' },
});

// ─────────────────────────────────────────────
// NOTIFICATIONS E-MAIL (seulement si hors ligne + anti-spam)
// ─────────────────────────────────────────────
const NOTIFY_COOLDOWN_MS = Number(process.env.NOTIFY_COOLDOWN_MIN || 10) * 60 * 1000;
const lastNotified = new Map(); // "userId:chatId" -> timestamp

function isOnline(userId) {
  const room = io.sockets.adapter.rooms.get(`user:${userId}`);
  return !!room && room.size > 0;
}

function shouldNotify(userId, chatId) {
  if (isOnline(userId)) return false;
  const key = `${userId}:${chatId}`;
  const last = lastNotified.get(key) || 0;
  if (Date.now() - last < NOTIFY_COOLDOWN_MS) return false;
  lastNotified.set(key, Date.now());
  if (lastNotified.size > 5000) lastNotified.clear();
  return true;
}

async function notifyRecipientByEmail({ toEmail, toName, fromName, text, conversationTitle }) {
  if (!toEmail) return;
  const subject = conversationTitle
    ? `Fesh — nouveau message dans « ${conversationTitle} »`
    : `Fesh — message de ${fromName || 'un étudiant'}`;

  const relayUrl = process.env.RELAY_URL;
  if (relayUrl) {
    try {
      const res = await fetch(relayUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: toEmail, toName: toName || '', from: fromName || 'Fesh', subject, message: text, app: 'Fesh' }),
        redirect: 'follow',
      });
      console.log(`Relay notification → ${toEmail} status=${res.status}`);
    } catch (err) {
      console.error('Relay notification failed:', err.message);
    }
    return;
  }

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return;
  try {
    const port = Number(SMTP_PORT || 587);
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST, port, secure: port === 465, auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    const who = escapeHtml(fromName || 'Un étudiant');
    await transporter.sendMail({
      from: SMTP_FROM || `Fesh <${SMTP_USER}>`,
      to: toEmail,
      subject,
      text: `${fromName || 'Un étudiant'} t'a écrit sur Fesh :\n\n${text}\n\n—\nOuvre l'application Fesh pour répondre.`,
      html: `<p><strong>${who}</strong> t'a écrit sur <strong>Fesh</strong> :</p>
             <blockquote style="border-left:3px solid #00A884;padding-left:12px;color:#333;">${escapeHtml(text)}</blockquote>
             <p style="color:#666;font-size:13px;">Ouvre l'application Fesh pour répondre.</p>`,
    });
    console.log(`Email notification sent to ${toEmail}`);
  } catch (err) {
    console.error('Email notification failed:', err.message);
  }
}

// ─────────────────────────────────────────────
// MESSAGES (logique commune REST + Socket)
// ─────────────────────────────────────────────
async function createMessage({ conversation, sender, text, type = 'text', mediaUrl = '', fileName = '', mimeType = '', durationMs = 0 }) {
  const clean = String(text || '').trim();
  const msgType = ['text', 'image', 'audio', 'file'].includes(type) ? type : 'text';
  if (msgType === 'text') {
    if (!clean) throw httpError(400, 'Le message ne peut pas être vide.');
  } else if (!mediaUrl) {
    throw httpError(400, 'Média manquant.');
  }
  if (clean.length > 5000) throw httpError(400, 'Message trop long (5000 caractères max).');

  const preview = msgType === 'image' ? '📷 Photo' : msgType === 'audio' ? '🎤 Message vocal' : msgType === 'file' ? `📎 ${fileName || 'Fichier'}` : clean;

  const message = await Message.create({
    conversationId: conversation._id,
    senderId: sender._id,
    type: msgType,
    text: clean,
    mediaUrl,
    fileName,
    mimeType,
    durationMs: Number(durationMs) || 0,
  });

  conversation.lastMessage = { text: preview, senderId: sender._id, createdAt: message.createdAt };
  await conversation.save();

  const populated = await message.populate('senderId', 'displayName photoUrl');
  // JSON "plat" : évite d'envoyer des ObjectId/Buffer bruts via socket.io
  const payload = JSON.parse(JSON.stringify(populated));

  const participantIds = conversation.participants.map((p) => p.toString());
  for (const pid of participantIds) io.to(`user:${pid}`).emit('message:new', payload);

  // E-mail aux participants hors ligne (anti-spam)
  (async () => {
    try {
      const others = participantIds.filter((id) => id !== sender._id.toString() && shouldNotify(id, conversation._id.toString()));
      if (!others.length) return;
      const users = await User.find({ _id: { $in: others } }).select('email displayName');
      for (const u of users) {
        notifyRecipientByEmail({
          toEmail: u.email, toName: u.displayName, fromName: sender.displayName,
          text: clean, conversationTitle: conversation.type === 'group' ? conversation.title : '',
        }).catch(() => {});
      }
    } catch (err) {
      console.error('Notify error:', err.message);
    }
  })();

  return payload;
}

// ─────────────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const { displayName, email, password, country = '', program = '' } = req.body;
    if (!displayName || !email || !password) {
      return res.status(400).json({ success: false, message: 'Nom, e-mail et mot de passe obligatoires.' });
    }
    const normalizedEmail = String(email).trim().toLowerCase();
    if (!EMAIL_RE.test(normalizedEmail)) {
      return res.status(400).json({ success: false, message: 'Adresse e-mail invalide.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ success: false, message: 'Le mot de passe doit contenir au moins 8 caractères.' });
    }
    if (await User.findOne({ email: normalizedEmail })) {
      return res.status(409).json({ success: false, message: 'Cette adresse e-mail est déjà utilisée.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 12);
    const user = await User.create({
      displayName: String(displayName).trim(), email: normalizedEmail, passwordHash,
      country: String(country).trim(), program: String(program).trim(),
    });

    return res.status(201).json({
      success: true, message: 'Compte créé.',
      data: { user: publicUser(user), token: createToken(user._id) },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ success: false, message: 'Cette adresse e-mail est déjà utilisée.' });
    }
    next(error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'E-mail et mot de passe obligatoires.' });
    }
    const user = await User.findOne({ email: String(email).trim().toLowerCase() }).select('+passwordHash');
    if (!user || !(await bcrypt.compare(String(password), user.passwordHash))) {
      return res.status(401).json({ success: false, message: 'Identifiants incorrects.' });
    }
    return res.json({
      success: true, message: 'Connexion réussie.',
      data: { user: publicUser(user), token: createToken(user._id) },
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ success: true, data: { user: publicUser(req.user) } });
});

app.patch('/api/auth/me', authenticate, async (req, res, next) => {
  try {
    const { displayName, country, program, photoUrl, statusText, statusMediaUrl, statusType, clearStatus } = req.body;
    if (displayName !== undefined) {
      const name = String(displayName).trim();
      if (name.length < 2) return res.status(400).json({ success: false, message: 'Nom trop court.' });
      req.user.displayName = name.slice(0, 80);
    }
    if (country !== undefined) req.user.country = String(country).trim().slice(0, 80);
    if (program !== undefined) req.user.program = String(program).trim().slice(0, 120);
    if (photoUrl !== undefined) req.user.photoUrl = String(photoUrl).trim().slice(0, 500);
    if (clearStatus) {
      req.user.statusText = '';
      req.user.statusMediaUrl = '';
      req.user.statusType = '';
      req.user.statusAt = undefined;
    } else {
      if (statusText !== undefined) req.user.statusText = String(statusText).trim().slice(0, 140);
      if (statusMediaUrl !== undefined) req.user.statusMediaUrl = String(statusMediaUrl).trim().slice(0, 500);
      if (statusType !== undefined && ['', 'text', 'image', 'video'].includes(statusType)) {
        req.user.statusType = statusType;
      }
      if (statusText !== undefined || statusMediaUrl !== undefined || statusType !== undefined) {
        req.user.statusAt = new Date();
      }
    }
    await req.user.save();
    res.json({ success: true, data: { user: publicUser(req.user) } });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ROUTES — ANNUAIRE
// ─────────────────────────────────────────────
app.get('/api/users', authenticate, async (req, res, next) => {
  try {
    const q = String(req.query.q || '').trim().slice(0, 60);
    const filter = { _id: { $ne: req.user._id } };
    if (q) {
      const rx = new RegExp(escapeRegex(q), 'i');
      // L'e-mail n'est jamais renvoyé, mais une correspondance exacte permet de retrouver un ami.
      filter.$or = [{ displayName: rx }, { country: rx }, { program: rx }, { email: q.toLowerCase() }];
    }
    const users = await User.find(filter).select('displayName country program photoUrl').sort({ displayName: 1 }).limit(40);
    res.json({
      success: true,
      data: { users: users.map((u) => ({ id: u._id, displayName: u.displayName, country: u.country, program: u.program, photoUrl: u.photoUrl })) },
    });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ROUTES — CHATS
// ─────────────────────────────────────────────
const POPULATE_FIELDS = 'displayName photoUrl country program';

app.get('/api/chats', authenticate, async (req, res, next) => {
  try {
    const conversations = await Conversation.find({ participants: req.user._id })
      .populate('participants', POPULATE_FIELDS)
      .sort({ updatedAt: -1 })
      .limit(200);
    res.json({ success: true, data: { conversations } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/chats/private', authenticate, async (req, res, next) => {
  try {
    const { userId } = req.body;
    if (!mongoose.isValidObjectId(userId) || String(userId) === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Utilisateur invalide.' });
    }
    const other = await User.findById(userId).select('_id');
    if (!other) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });

    let conversation = await Conversation.findOne({
      type: 'private',
      participants: { $all: [req.user._id, other._id], $size: 2 },
    });
    let created = false;
    if (!conversation) {
      conversation = await Conversation.create({ type: 'private', participants: [req.user._id, other._id], createdBy: req.user._id });
      created = true;
    }
    const populated = await conversation.populate('participants', POPULATE_FIELDS);
    res.status(created ? 201 : 200).json({ success: true, data: { conversation: populated } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/chats/group', authenticate, async (req, res, next) => {
  try {
    const { title, participantIds = [] } = req.body;
    if (!title || !String(title).trim() || !Array.isArray(participantIds)) {
      return res.status(400).json({ success: false, message: 'Nom du groupe et liste des membres requis.' });
    }
    const ids = [...new Set([req.user._id.toString(), ...participantIds.map(String)])];
    if (ids.some((id) => !mongoose.isValidObjectId(id))) {
      return res.status(400).json({ success: false, message: 'Identifiant de membre invalide.' });
    }
    if (ids.length > 256) {
      return res.status(400).json({ success: false, message: 'Trop de membres (256 max).' });
    }
    const count = await User.countDocuments({ _id: { $in: ids } });
    if (count !== ids.length) {
      return res.status(400).json({ success: false, message: 'Un ou plusieurs membres sont introuvables.' });
    }
    const conversation = await Conversation.create({
      type: 'group', title: String(title).trim().slice(0, 80), participants: ids, createdBy: req.user._id,
    });
    const populated = await conversation.populate('participants', POPULATE_FIELDS);
    res.status(201).json({ success: true, data: { conversation: populated } });
  } catch (error) {
    next(error);
  }
});

app.get('/api/chats/:chatId/messages', authenticate, async (req, res, next) => {
  try {
    const conversation = await Conversation.findOne({ _id: req.params.chatId, participants: req.user._id });
    if (!conversation) {
      return res.status(404).json({ success: false, message: 'Conversation introuvable.' });
    }
    const messages = await Message.find({ conversationId: conversation._id })
      .populate('senderId', 'displayName photoUrl')
      .sort({ createdAt: -1 })
      .limit(100);
    res.json({ success: true, data: { messages: messages.reverse() } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/upload', authenticate, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'Aucun fichier reçu.' });
    const doc = await Media.create({
      data: req.file.buffer,
      fileName: req.file.originalname || 'file',
      mimeType: req.file.mimetype || 'application/octet-stream',
      size: req.file.size,
      uploadedBy: req.user._id,
    });
    const url = `/api/media/${doc._id}`;
    res.status(201).json({
      success: true,
      data: {
        url,
        fileName: doc.fileName,
        mimeType: doc.mimeType,
        size: doc.size,
      },
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/media/:id', async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Média introuvable.' });
    }
    const doc = await Media.findById(req.params.id).select('+data');
    if (!doc || !doc.data) {
      return res.status(404).json({ success: false, message: 'Média introuvable.' });
    }
    res.set({
      'Content-Type': doc.mimeType || 'application/octet-stream',
      'Content-Length': doc.size || doc.data.length,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Content-Disposition': `inline; filename="${encodeURIComponent(doc.fileName || 'file')}"`,
    });
    res.send(doc.data);
  } catch (error) {
    next(error);
  }
});

app.post('/api/chats/:chatId/messages', authenticate, async (req, res, next) => {
  try {
    const conversation = await Conversation.findOne({ _id: req.params.chatId, participants: req.user._id });
    if (!conversation) {
      return res.status(404).json({ success: false, message: 'Conversation introuvable.' });
    }
    const { text, type, mediaUrl, fileName, mimeType, durationMs } = req.body || {};
    const message = await createMessage({
      conversation,
      sender: req.user,
      text,
      type,
      mediaUrl,
      fileName,
      mimeType,
      durationMs,
    });
    res.status(201).json({ success: true, data: { message } });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ROUTES — COMMUNAUTÉS
// ─────────────────────────────────────────────
app.get('/api/communities', authenticate, async (req, res, next) => {
  try {
    const list = await Conversation.find({ isPublic: true }).select('title description slug participants').sort({ createdAt: 1 });
    res.json({
      success: true,
      data: {
        communities: list.map((c) => ({
          id: c._id, slug: c.slug, title: c.title, description: c.description,
          memberCount: c.participants.length,
          joined: c.participants.some((p) => p.equals(req.user._id)),
        })),
      },
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/communities/:id/join', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ success: false, message: 'Identifiant invalide.' });
    }
    const conversation = await Conversation.findOneAndUpdate(
      { _id: req.params.id, isPublic: true },
      { $addToSet: { participants: req.user._id } },
      { new: true },
    );
    if (!conversation) return res.status(404).json({ success: false, message: 'Communauté introuvable.' });
    const populated = await conversation.populate('participants', POPULATE_FIELDS);
    res.json({ success: true, data: { conversation: populated } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/communities/:id/leave', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ success: false, message: 'Identifiant invalide.' });
    }
    await Conversation.updateOne({ _id: req.params.id, isPublic: true }, { $pull: { participants: req.user._id } });
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// HEALTH + ERRORS
// ─────────────────────────────────────────────
app.get('/', (_req, res) => res.json({ success: true, name: 'Fesh API', health: '/health' }));
app.get('/health', (_req, res) => res.json({ success: true, status: 'ok', service: 'fesh-backend' }));

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route introuvable: ${req.method} ${req.originalUrl}` });
});

app.use((err, _req, res, _next) => {
  let status = err.status || 500;
  if (err.name === 'CastError') status = 400;
  if (status >= 500) console.error(err);
  const hide = status >= 500 && process.env.NODE_ENV === 'production';
  res.status(status).json({
    success: false,
    message: hide ? 'Erreur interne du serveur.' : (err.message || 'Erreur interne du serveur.'),
  });
});

// ─────────────────────────────────────────────
// SOCKET.IO
// ─────────────────────────────────────────────
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error('Authentification requise.'));
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub).select('_id displayName');
    if (!user) return next(new Error('Utilisateur introuvable.'));
    socket.user = user;
    next();
  } catch (_error) {
    next(new Error('Jeton invalide.'));
  }
});

io.on('connection', (socket) => {
  // Chaque utilisateur reçoit TOUS ses messages (liste de discussions en temps réel)
  socket.join(`user:${socket.user._id}`);

  socket.on('message:send', async (data = {}, callback = () => {}) => {
    try {
      const { chatId, text, type, mediaUrl, fileName, mimeType, durationMs } = data;
      const conversation = await Conversation.findOne({ _id: chatId, participants: socket.user._id });
      if (!conversation) return callback({ success: false, message: 'Accès refusé.' });
      const payload = await createMessage({
        conversation,
        sender: socket.user,
        text,
        type,
        mediaUrl,
        fileName,
        mimeType,
        durationMs,
      });
      callback({ success: true, data: payload });
    } catch (error) {
      callback({ success: false, message: error.status ? error.message : 'Impossible d’envoyer le message.' });
    }
  });

  // ── WebRTC signaling (1-1 calls) ─────────────────────────
  socket.on('call:invite', ({ toUserId, chatId, callType, offer } = {}) => {
    if (!toUserId) return;
    io.to(`user:${toUserId}`).emit('call:invite', {
      fromUserId: String(socket.user._id),
      fromName: socket.user.displayName,
      chatId,
      callType: callType === 'video' ? 'video' : 'audio',
      offer,
    });
  });

  socket.on('call:answer', ({ toUserId, answer } = {}) => {
    if (!toUserId) return;
    io.to(`user:${toUserId}`).emit('call:answer', {
      fromUserId: String(socket.user._id),
      answer,
    });
  });

  socket.on('call:ice', ({ toUserId, candidate } = {}) => {
    if (!toUserId || !candidate) return;
    io.to(`user:${toUserId}`).emit('call:ice', {
      fromUserId: String(socket.user._id),
      candidate,
    });
  });

  socket.on('call:hangup', ({ toUserId } = {}) => {
    if (!toUserId) return;
    io.to(`user:${toUserId}`).emit('call:hangup', {
      fromUserId: String(socket.user._id),
    });
  });

  socket.on('call:reject', ({ toUserId } = {}) => {
    if (!toUserId) return;
    io.to(`user:${toUserId}`).emit('call:reject', {
      fromUserId: String(socket.user._id),
    });
  });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
async function connectDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('La variable MONGODB_URI est absente.');
  if (!process.env.JWT_SECRET) throw new Error('La variable JWT_SECRET est absente.');
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 15000 });
  console.log(`MongoDB connected: ${mongoose.connection.name}`);
}

async function seedCommunities() {
  for (const c of DEFAULT_COMMUNITIES) {
    await Conversation.updateOne(
      { slug: c.slug },
      { $setOnInsert: { type: 'group', title: c.title, description: c.description, isPublic: true, participants: [] } },
      { upsert: true },
    );
  }
}

const PORT = process.env.PORT || 5000;

connectDatabase()
  .then(seedCommunities)
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => console.log(`Fesh API running on port ${PORT}`));
  })
  .catch((error) => {
    console.error('Impossible de démarrer :', error.message);
    process.exit(1);
  });
