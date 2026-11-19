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
  // Appareils pour les notifications push (FCM) + langue choisie dans l'app
  fcmTokens: {
    type: [new mongoose.Schema({
      token: { type: String, required: true },
      lang: { type: String, default: 'fr' },
      updatedAt: { type: Date, default: Date.now },
    }, { _id: false })],
    default: [],
    select: false,
  },
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['private', 'group'], default: 'private' },
  title: { type: String, trim: true, default: '' },
  description: { type: String, trim: true, default: '' },
  // Communautés publiques (n'importe qui peut les rejoindre)
  isPublic: { type: Boolean, default: false },
  slug: { type: String, trim: true, index: true, sparse: true },
  photoUrl: { type: String, default: '' },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastMessage: {
    text: { type: String, default: '' },
    type: { type: String, default: 'text' },
    durationMs: { type: Number, default: 0 },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    messageId: { type: mongoose.Schema.Types.ObjectId },
    createdAt: { type: Date },
  },
}, { timestamps: true });
conversationSchema.index({ participants: 1, updatedAt: -1 });

const messageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true, index: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['text', 'image', 'audio', 'file', 'location'], default: 'text' },
  text: { type: String, trim: true, maxlength: 5000, default: '' },
  mediaUrl: { type: String, default: '' },
  fileName: { type: String, default: '' },
  mimeType: { type: String, default: '' },
  durationMs: { type: Number, default: 0 },
  lat: { type: Number },
  lng: { type: Number },
  forwarded: { type: Boolean, default: false },
  // Aperçu du message cité (réponse)
  reply: {
    type: new mongoose.Schema({
      id: String, senderId: String, senderName: String, kind: String, text: String,
    }, { _id: false }),
    default: undefined,
  },
  reactions: {
    type: [new mongoose.Schema({
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      emoji: { type: String, maxlength: 16 },
    }, { _id: false })],
    default: [],
  },
  deleted: { type: Boolean, default: false },
  deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  // Coches : reçu / lu (par les destinataires)
  deliveredTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  // Vue unique (photo / vidéo / vocal)
  viewOnce: { type: Boolean, default: false },
  viewedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });
messageSchema.index({ conversationId: 1, createdAt: -1 });

// Statuts éphémères (24 h)
const statusSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['text', 'image', 'video'], required: true },
  text: { type: String, trim: true, maxlength: 200, default: '' },
  mediaUrl: { type: String, default: '' },
  bg: { type: String, default: '0' },
  expiresAt: { type: Date, required: true },
  viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });
statusSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const mediaSchema = new mongoose.Schema({
  data: { type: Buffer, required: true, select: false },
  fileName: { type: String, default: '' },
  mimeType: { type: String, default: 'application/octet-stream' },
  size: { type: Number, default: 0 },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  viewOnce: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const Media = mongoose.model('Media', mediaSchema);
const Status = mongoose.model('Status', statusSchema);

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
// NOTIFICATIONS PUSH (Firebase Cloud Messaging)
// ─────────────────────────────────────────────
let fcm = null;
(function initFirebase() {
  try {
    let raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw && process.env.FIREBASE_SERVICE_ACCOUNT_B64) {
      raw = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
    }
    if (!raw) {
      console.log('Push FCM désactivé (FIREBASE_SERVICE_ACCOUNT absent).');
      return;
    }
    const admin = require('firebase-admin');
    const cred = JSON.parse(raw);
    if (cred.private_key) cred.private_key = cred.private_key.replace(/\\n/g, '\n');
    admin.initializeApp({ credential: admin.credential.cert(cred) });
    fcm = admin.messaging();
    console.log('Push FCM activé.');
  } catch (err) {
    console.error('Init Firebase impossible :', err.message);
  }
})();

const LANGS = ['fr', 'en', 'es', 'pt', 'de', 'it'];
const PUSH_TXT = {
  fr: { voice: 'Message vocal', photo: 'Photo', file: 'Fichier', location: 'Position', once: 'Média à vue unique', msg: 'Nouveau message' },
  en: { voice: 'Voice message', photo: 'Photo', file: 'File', location: 'Location', once: 'View-once media', msg: 'New message' },
  es: { voice: 'Mensaje de voz', photo: 'Foto', file: 'Archivo', location: 'Ubicación', once: 'Contenido de una sola vez', msg: 'Mensaje nuevo' },
  pt: { voice: 'Mensagem de voz', photo: 'Foto', file: 'Arquivo', location: 'Localização', once: 'Mídia de visualização única', msg: 'Nova mensagem' },
  de: { voice: 'Sprachnachricht', photo: 'Foto', file: 'Datei', location: 'Standort', once: 'Einmal-Ansicht', msg: 'Neue Nachricht' },
  it: { voice: 'Messaggio vocale', photo: 'Foto', file: 'File', location: 'Posizione', once: 'Visualizzazione singola', msg: 'Nuovo messaggio' },
};
const COMMUNITY_TITLES = {"international": {"fr": "Étudiants internationaux", "en": "International students", "es": "Estudiantes internacionales", "pt": "Estudantes internacionais", "de": "Internationale Studierende", "it": "Studenti internazionali"}, "arrival": {"fr": "Préparer son arrivée", "en": "Prepare your arrival", "es": "Preparar la llegada", "pt": "Preparar a chegada", "de": "Ankunft vorbereiten", "it": "Preparare l’arrivo"}, "housing": {"fr": "Logement à Accra", "en": "Housing in Accra", "es": "Alojamiento en Accra", "pt": "Moradia em Accra", "de": "Wohnen in Accra", "it": "Alloggio ad Accra"}, "admission": {"fr": "Admissions & visa", "en": "Admissions & visa", "es": "Admisiones y visa", "pt": "Admissões e visto", "de": "Zulassung & Visum", "it": "Ammissioni e visto"}, "daily-life": {"fr": "Vie à Accra", "en": "Life in Accra", "es": "Vida en Accra", "pt": "Vida em Accra", "de": "Leben in Accra", "it": "Vita ad Accra"}, "engineering": {"fr": "Génie électrique", "en": "Electrical engineering", "es": "Ingeniería eléctrica", "pt": "Engenharia elétrica", "de": "Elektrotechnik", "it": "Ingegneria elettrica"}};

function pushBody(lang, msg) {
  const t = PUSH_TXT[lang] || PUSH_TXT.fr;
  if (msg.viewOnce) return t.once;
  switch (msg.type) {
    case 'audio': return t.voice;
    case 'image': return msg.text ? msg.text : t.photo;
    case 'file': return msg.fileName || t.file;
    case 'location': return t.location;
    default: return msg.text || t.msg;
  }
}

async function sendPushForMessage({ conversation, sender, message }) {
  if (!fcm) return;
  const senderId = sender._id.toString();
  const recipientIds = conversation.participants.map((p) => p.toString()).filter((id) => id !== senderId);
  if (!recipientIds.length) return;
  const users = await User.find({ _id: { $in: recipientIds } }).select('+fcmTokens');
  const byLang = new Map(); // lang -> [token]
  for (const u of users) {
    for (const d of u.fcmTokens || []) {
      const lang = LANGS.includes(d.lang) ? d.lang : 'fr';
      if (!byLang.has(lang)) byLang.set(lang, []);
      byLang.get(lang).push(d.token);
    }
  }
  if (!byLang.size) return;
  const isGroup = conversation.type === 'group';
  const firstName = String(sender.displayName || '').split(' ')[0];
  for (const [lang, tokens] of byLang) {
    const body = pushBody(lang, message);
    const groupTitle = conversation.slug && COMMUNITY_TITLES[conversation.slug]
      ? (COMMUNITY_TITLES[conversation.slug][lang] || conversation.title)
      : conversation.title;
    const title = isGroup ? groupTitle : sender.displayName;
    const text = (isGroup ? `${firstName}: ${body}` : body).slice(0, 160);
    for (let i = 0; i < tokens.length; i += 500) {
      const chunk = tokens.slice(i, i + 500);
      try {
        const res = await fcm.sendEachForMulticast({
          tokens: chunk,
          notification: { title, body: text },
          data: { type: 'message', chatId: conversation._id.toString(), messageId: message._id.toString(), title, body: text },
          android: {
            priority: 'high',
            notification: { channelId: 'fesh_messages', sound: 'default', defaultSound: true },
          },
          apns: { headers: { 'apns-priority': '10' }, payload: { aps: { sound: 'default' } } },
        });
        // nettoyage des appareils qui ne sont plus valides
        const dead = [];
        res.responses.forEach((r, idx) => {
          const code = r.error && r.error.code;
          if (code === 'messaging/registration-token-not-registered' || code === 'messaging/invalid-registration-token') dead.push(chunk[idx]);
        });
        if (dead.length) await User.updateMany({ 'fcmTokens.token': { $in: dead } }, { $pull: { fcmTokens: { token: { $in: dead } } } });
      } catch (err) {
        console.error('Push FCM erreur :', err.message);
      }
    }
  }
}

// Sérialisation d'un message : pas d'URL pour les médias à vue unique
function msgJson(doc) {
  const j = JSON.parse(JSON.stringify(doc));
  delete j.fcmTokens;
  if (j.viewOnce) {
    j.mediaUrl = '';
    j.fileName = '';
  }
  return j;
}

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
async function createMessage({ conversation, sender, text, type = 'text', mediaUrl = '', fileName = '', mimeType = '', durationMs = 0, lat, lng, forwarded = false, replyTo, viewOnce = false }) {
  const clean = String(text || '').trim();
  const msgType = ['text', 'image', 'audio', 'file', 'location'].includes(type) ? type : 'text';
  const latN = Number(lat);
  const lngN = Number(lng);
  if (msgType === 'text') {
    if (!clean) throw httpError(400, 'Le message ne peut pas être vide.');
  } else if (msgType === 'location') {
    if (!Number.isFinite(latN) || !Number.isFinite(lngN) || Math.abs(latN) > 90 || Math.abs(lngN) > 180) {
      throw httpError(400, 'Position invalide.');
    }
  } else if (!mediaUrl) {
    throw httpError(400, 'Média manquant.');
  }
  if (clean.length > 5000) throw httpError(400, 'Message trop long (5000 caractères max).');

  const preview = msgType === 'image' ? '📷 Photo' : msgType === 'audio' ? '🎤 Message vocal' : msgType === 'file' ? `📎 ${fileName || 'Fichier'}` : msgType === 'location' ? '📍 Position' : clean;

  // Message cité
  let reply;
  if (replyTo && mongoose.isValidObjectId(replyTo)) {
    const quoted = await Message.findOne({ _id: replyTo, conversationId: conversation._id }).populate('senderId', 'displayName');
    if (quoted && !quoted.deleted) {
      reply = {
        id: quoted._id.toString(),
        senderId: quoted.senderId && quoted.senderId._id ? quoted.senderId._id.toString() : '',
        senderName: quoted.senderId && quoted.senderId.displayName ? quoted.senderId.displayName : '',
        kind: quoted.type,
        text: quoted.type === 'text' ? quoted.text.slice(0, 200) : (quoted.type === 'file' ? quoted.fileName : ''),
      };
    }
  }

  const message = await Message.create({
    conversationId: conversation._id,
    senderId: sender._id,
    type: msgType,
    text: clean,
    mediaUrl,
    fileName,
    mimeType,
    durationMs: Number(durationMs) || 0,
    lat: msgType === 'location' ? latN : undefined,
    lng: msgType === 'location' ? lngN : undefined,
    forwarded: !!forwarded,
    reply,
    viewOnce: !!viewOnce && (msgType === 'image' || msgType === 'audio' || (msgType === 'file' && /^video\//.test(String(mimeType || '')))),
  });

  // Le média d'un message à vue unique n'est plus accessible sans jeton
  if (message.viewOnce) {
    const mid = /\/api\/media\/([a-f0-9]{24})/i.exec(mediaUrl || '');
    if (mid) await Media.updateOne({ _id: mid[1] }, { $set: { viewOnce: true } });
  }

  conversation.lastMessage = { text: message.viewOnce ? '🔒' : preview, type: msgType, durationMs: Number(durationMs) || 0, senderId: sender._id, messageId: message._id, createdAt: message.createdAt };
  await conversation.save();

  const populated = await message.populate('senderId', 'displayName photoUrl');
  // JSON "plat" : évite d'envoyer des ObjectId/Buffer bruts via socket.io
  const payload = msgJson(populated);

  const participantIds = conversation.participants.map((p) => p.toString());
  for (const pid of participantIds) io.to(`user:${pid}`).emit('message:new', payload);

  // Coches « reçu » pour les destinataires connectés + notification push pour tous
  for (const pid of participantIds) {
    if (pid !== sender._id.toString() && isOnline(pid)) markDelivered(pid, [conversation._id.toString()]).catch(() => {});
  }
  sendPushForMessage({ conversation, sender, message: message.toObject() }).catch((err) => console.error('Push error:', err.message));

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
    if (photoUrl !== undefined || displayName !== undefined) {
      statusAudience(req.user._id)
        .then((ids) => ids.forEach((id) => io.to(`user:${id}`).emit('user:updated', {
          userId: req.user._id.toString(), displayName: req.user.displayName, photoUrl: req.user.photoUrl || '',
        })))
        .catch(() => {});
    }
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
    const lastIds = conversations.map((c) => c.lastMessage && c.lastMessage.messageId).filter(Boolean);
    const lastMsgs = lastIds.length ? await Message.find({ _id: { $in: lastIds } }).select('deliveredTo readBy deleted deletedFor') : [];
    const lastMap = new Map(lastMsgs.map((m) => [m._id.toString(), m]));
    const me = req.user._id.toString();
    const previewOf = (m) => (m.viewOnce ? '🔒' : m.type === 'image' ? '📷 Photo' : m.type === 'audio' ? '🎤 Message vocal' : m.type === 'file' ? `📎 ${m.fileName || 'Fichier'}` : m.type === 'location' ? '📍 Position' : m.text || '');
    const out = await Promise.all(conversations.map(async (c) => {
      const j = JSON.parse(JSON.stringify(c));
      let lm = c.lastMessage && c.lastMessage.messageId ? lastMap.get(c.lastMessage.messageId.toString()) : null;
      if (lm && (lm.deletedFor || []).some((id) => id.toString() === me)) {
        // dernier message supprimé « pour moi » : on retombe sur le précédent message visible
        const prev = await Message.findOne({ conversationId: c._id, deletedFor: { $ne: req.user._id } }).sort({ createdAt: -1 });
        if (prev) {
          j.lastMessage = {
            text: prev.deleted ? '' : previewOf(prev), type: prev.deleted ? 'deleted' : prev.type, durationMs: prev.durationMs || 0,
            senderId: prev.senderId, messageId: prev._id, createdAt: prev.createdAt,
          };
          lm = prev;
        } else {
          j.lastMessage = { text: '', type: 'text' };
          lm = null;
        }
      } else if (lm && lm.deleted) {
        j.lastMessage = { ...j.lastMessage, text: '', type: 'deleted' };
      }
      j.lastDeliveredTo = lm ? (lm.deliveredTo || []).map(String) : [];
      j.lastReadBy = lm ? (lm.readBy || []).map(String) : [];
      return j;
    }));
    res.json({ success: true, data: { conversations: out } });
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
    const messages = await Message.find({ conversationId: conversation._id, deletedFor: { $ne: req.user._id } })
      .populate('senderId', 'displayName photoUrl')
      .sort({ createdAt: -1 })
      .limit(100);
    markDelivered(req.user._id, [conversation._id.toString()]).catch(() => {});
    res.json({ success: true, data: { messages: messages.reverse().map(msgJson) } });
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
    if (doc.viewOnce) {
      try {
        const p = jwt.verify(String(req.query.t || ''), process.env.JWT_SECRET);
        if (p.m !== doc._id.toString()) throw new Error('bad');
      } catch (_e) {
        return res.status(403).json({ success: false, message: 'Média à vue unique.' });
      }
    }
    const total = doc.data.length;
    const base = {
      'Content-Type': doc.mimeType || 'application/octet-stream',
      'Accept-Ranges': 'bytes',
      'Cache-Control': doc.viewOnce ? 'private, no-store' : 'public, max-age=31536000, immutable',
      'Content-Disposition': `inline; filename="${encodeURIComponent(doc.fileName || 'file')}"`,
    };
    // Lecture partielle (nécessaire pour les vidéos / la barre de lecture des vocaux)
    const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (m && (m[1] !== '' || m[2] !== '')) {
      let start = m[1] === '' ? Math.max(0, total - Number(m[2])) : Number(m[1]);
      let end = m[1] === '' || m[2] === '' ? total - 1 : Math.min(Number(m[2]), total - 1);
      if (start >= total || start > end) {
        res.status(416).set({ 'Content-Range': `bytes */${total}` }).end();
        return;
      }
      res.status(206).set({ ...base, 'Content-Range': `bytes ${start}-${end}/${total}`, 'Content-Length': end - start + 1 });
      res.end(doc.data.subarray(start, end + 1));
      return;
    }
    res.set({ ...base, 'Content-Length': total });
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
    const { text, type, mediaUrl, fileName, mimeType, durationMs, lat, lng, forwarded, replyTo, viewOnce } = req.body || {};
    const message = await createMessage({
      conversation,
      sender: req.user,
      text,
      type,
      mediaUrl,
      fileName,
      mimeType,
      durationMs,
      lat,
      lng,
      forwarded,
      replyTo,
      viewOnce,
    });
    res.status(201).json({ success: true, data: { message } });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// SUPPRESSION RÉELLE (libère l'espace dans la base)
// ─────────────────────────────────────────────
function mediaIdFromUrl(url) {
  const m = /\/api\/media\/([a-f0-9]{24})/i.exec(String(url || ''));
  return m ? m[1] : null;
}

// Supprime le fichier de la base s'il n'est plus utilisé nulle part
// (un message transféré peut partager le même fichier).
async function purgeMediaIfUnused(url) {
  try {
    const id = mediaIdFromUrl(url);
    if (!id) return;
    const re = new RegExp(`/api/media/${id}`);
    const used = await Promise.all([
      Message.exists({ mediaUrl: re }),
      Status.exists({ mediaUrl: re }),
      User.exists({ $or: [{ photoUrl: re }, { statusMediaUrl: re }] }),
      Conversation.exists({ photoUrl: re }),
    ]);
    if (used.some(Boolean)) return;
    await Media.deleteOne({ _id: id });
  } catch (err) {
    console.error('purgeMedia:', err.message);
  }
}

// Remet à jour l'aperçu de la liste après une suppression définitive
async function refreshConversationLast(conversationId) {
  const last = await Message.findOne({ conversationId }).sort({ createdAt: -1 });
  if (!last) {
    await Conversation.updateOne({ _id: conversationId }, { $unset: { lastMessage: 1 } });
    return;
  }
  const text = last.viewOnce ? '🔒' : last.type === 'image' ? '📷 Photo' : last.type === 'audio' ? '🎤 Message vocal' : last.type === 'file' ? `📎 ${last.fileName || 'Fichier'}` : last.type === 'location' ? '📍 Position' : last.text || '';
  await Conversation.updateOne({ _id: conversationId }, { $set: { lastMessage: { text, type: last.type, durationMs: last.durationMs || 0, senderId: last.senderId, messageId: last._id, createdAt: last.createdAt } } });
}

async function hardDeleteMessage(message, conversation) {
  const url = message.mediaUrl;
  await Message.deleteOne({ _id: message._id });
  await purgeMediaIfUnused(url);
  await refreshConversationLast(conversation._id);
}

// Nettoyage périodique : fichiers qui ne sont plus référencés par rien
async function sweepOrphanMedia() {
  try {
    const refs = new Set();
    const lists = await Promise.all([
      Message.distinct('mediaUrl'), Status.distinct('mediaUrl'), User.distinct('photoUrl'),
      User.distinct('statusMediaUrl'), Conversation.distinct('photoUrl'),
    ]);
    for (const l of lists) for (const u of l) { const id = mediaIdFromUrl(u); if (id) refs.add(id); }
    const old = await Media.find({ createdAt: { $lt: new Date(Date.now() - 60 * 60 * 1000) } }).select('_id');
    const dead = old.map((m) => m._id.toString()).filter((id) => !refs.has(id));
    for (let i = 0; i < dead.length; i += 200) await Media.deleteMany({ _id: { $in: dead.slice(i, i + 200) } });
    if (dead.length) console.log(`Nettoyage : ${dead.length} fichier(s) orphelin(s) supprimé(s).`);
  } catch (err) {
    console.error('sweepOrphanMedia:', err.message);
  }
}

// ─────────────────────────────────────────────
// COCHES : REÇU / LU
// ─────────────────────────────────────────────
async function markDelivered(userId, onlyChatIds) {
  const filter = onlyChatIds && onlyChatIds.length
    ? { _id: { $in: onlyChatIds }, participants: userId }
    : { participants: userId };
  const convs = await Conversation.find(filter).select('_id participants').limit(500);
  if (!convs.length) return;
  const ids = convs.map((c) => c._id);
  const pending = await Message.distinct('conversationId', { conversationId: { $in: ids }, senderId: { $ne: userId }, deliveredTo: { $ne: userId } });
  if (!pending.length) return;
  await Message.updateMany(
    { conversationId: { $in: pending }, senderId: { $ne: userId }, deliveredTo: { $ne: userId } },
    { $addToSet: { deliveredTo: userId } },
  );
  const pendingSet = new Set(pending.map((p) => p.toString()));
  for (const c of convs) {
    if (!pendingSet.has(c._id.toString())) continue;
    for (const pid of c.participants) io.to(`user:${pid}`).emit('chat:delivered', { chatId: c._id.toString(), userId: userId.toString() });
  }
}

app.post('/api/chats/:chatId/read', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.chatId)) throw httpError(400, 'Identifiant invalide.');
    const conversation = await Conversation.findOne({ _id: req.params.chatId, participants: req.user._id });
    if (!conversation) throw httpError(404, 'Conversation introuvable.');
    const r = await Message.updateMany(
      { conversationId: conversation._id, senderId: { $ne: req.user._id }, readBy: { $ne: req.user._id } },
      { $addToSet: { readBy: req.user._id, deliveredTo: req.user._id } },
    );
    if (r.modifiedCount) {
      for (const pid of conversation.participants) {
        io.to(`user:${pid}`).emit('chat:read', { chatId: conversation._id.toString(), userId: req.user._id.toString() });
      }
    }
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// APPAREILS (notifications push)
// ─────────────────────────────────────────────
app.put('/api/devices', authenticate, async (req, res, next) => {
  try {
    const token = String((req.body && req.body.token) || '').trim();
    const lang = LANGS.includes(req.body && req.body.lang) ? req.body.lang : 'fr';
    if (token.length < 20 || token.length > 4096) throw httpError(400, 'Jeton invalide.');
    // un appareil = un seul compte
    await User.updateMany({ 'fcmTokens.token': token, _id: { $ne: req.user._id } }, { $pull: { fcmTokens: { token } } });
    const updated = await User.updateOne({ _id: req.user._id, 'fcmTokens.token': token }, { $set: { 'fcmTokens.$.lang': lang, 'fcmTokens.$.updatedAt': new Date() } });
    if (!updated.matchedCount) {
      await User.updateOne({ _id: req.user._id }, { $push: { fcmTokens: { $each: [{ token, lang, updatedAt: new Date() }], $slice: -10 } } });
    }
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/devices', authenticate, async (req, res, next) => {
  try {
    const token = String(req.query.token || '').trim();
    if (token) await User.updateOne({ _id: req.user._id }, { $pull: { fcmTokens: { token } } });
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// Ouverture d'un média à vue unique : une seule fois par destinataire
app.post('/api/messages/:id/open-once', authenticate, async (req, res, next) => {
  try {
    const { message, conversation } = await loadMessageForUser(req.params.id, req.user._id);
    if (!message.viewOnce || message.deleted) throw httpError(400, 'Ce message n’est pas à vue unique.');
    if (String(message.senderId) === req.user._id.toString()) throw httpError(403, 'Tu ne peux pas rouvrir ton propre média.');
    const claimed = await Message.findOneAndUpdate(
      { _id: message._id, viewedBy: { $ne: req.user._id } },
      { $addToSet: { viewedBy: req.user._id } },
      { new: true },
    );
    if (!claimed) throw httpError(410, 'Déjà ouvert.');
    const mid = /\/api\/media\/([a-f0-9]{24})/i.exec(message.mediaUrl || '');
    if (!mid) throw httpError(404, 'Média introuvable.');
    const t = jwt.sign({ m: mid[1], u: req.user._id.toString() }, process.env.JWT_SECRET, { expiresIn: '3m' });
    await broadcastMessageUpdate(claimed, conversation);
    const others = conversation.participants.filter((pid) => pid.toString() !== String(message.senderId));
    if (others.every((pid) => claimed.viewedBy.some((v) => v.toString() === pid.toString()))) {
      // tout le monde l'a vu : le fichier est supprimé de la base (après le délai du jeton)
      setTimeout(async () => {
        await Message.updateOne({ _id: claimed._id }, { $set: { mediaUrl: '', fileName: '' } });
        await Media.deleteOne({ _id: mid[1] });
      }, 4 * 60 * 1000).unref();
    }
    res.json({ success: true, data: { url: `/api/media/${mid[1]}?t=${t}`, type: message.type, mimeType: message.mimeType } });
  } catch (error) {
    next(error);
  }
});

// Photo du groupe
app.patch('/api/chats/:chatId', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.chatId)) throw httpError(400, 'Identifiant invalide.');
    const conversation = await Conversation.findOne({ _id: req.params.chatId, participants: req.user._id });
    if (!conversation) throw httpError(404, 'Conversation introuvable.');
    if (conversation.type !== 'group') throw httpError(400, 'Réservé aux groupes.');
    if (conversation.slug) throw httpError(403, 'La photo d’une communauté ne peut pas être modifiée.');
    if (req.body && req.body.photoUrl !== undefined) conversation.photoUrl = String(req.body.photoUrl).trim().slice(0, 500);
    await conversation.save();
    for (const pid of conversation.participants) {
      io.to(`user:${pid}`).emit('chat:updated', { chatId: conversation._id.toString(), photoUrl: conversation.photoUrl });
    }
    res.json({ success: true, data: { photoUrl: conversation.photoUrl } });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ROUTES — ACTIONS SUR LES MESSAGES / GROUPES
// ─────────────────────────────────────────────
async function loadMessageForUser(messageId, userId) {
  if (!mongoose.isValidObjectId(messageId)) throw httpError(400, 'Identifiant invalide.');
  const message = await Message.findById(messageId);
  if (!message) throw httpError(404, 'Message introuvable.');
  const conversation = await Conversation.findOne({ _id: message.conversationId, participants: userId });
  if (!conversation) throw httpError(403, 'Accès refusé.');
  return { message, conversation };
}

async function broadcastMessageUpdate(message, conversation) {
  const populated = await message.populate('senderId', 'displayName photoUrl');
  const payload = msgJson(populated);
  for (const pid of conversation.participants) io.to(`user:${pid}`).emit('message:update', payload);
  return payload;
}

// Réaction (un seul emoji par personne ; renvoyer le même emoji l'enlève)
app.put('/api/messages/:id/react', authenticate, async (req, res, next) => {
  try {
    const { message, conversation } = await loadMessageForUser(req.params.id, req.user._id);
    if (message.deleted) throw httpError(400, 'Message supprimé.');
    const emoji = String((req.body && req.body.emoji) || '').trim().slice(0, 16);
    const me = req.user._id.toString();
    const existing = message.reactions.find((r) => String(r.userId) === me);
    message.reactions = message.reactions.filter((r) => String(r.userId) !== me);
    if (emoji && !(existing && existing.emoji === emoji)) {
      message.reactions.push({ userId: req.user._id, emoji });
    }
    await message.save();
    const payload = await broadcastMessageUpdate(message, conversation);
    res.json({ success: true, data: { message: payload } });
  } catch (error) {
    next(error);
  }
});

// Suppression : ?forAll=1 (auteur uniquement) ou pour moi seulement
app.delete('/api/messages/:id', authenticate, async (req, res, next) => {
  try {
    const { message, conversation } = await loadMessageForUser(req.params.id, req.user._id);
    const forAll = req.query.forAll === '1' || req.query.forAll === 'true';
    if (forAll) {
      if (String(message.senderId) !== req.user._id.toString()) throw httpError(403, 'Tu ne peux supprimer pour tous que tes propres messages.');
      // 1) on prévient les écrans ouverts, 2) on efface réellement le message et son fichier
      const mediaUrl = message.mediaUrl;
      message.deleted = true;
      message.text = '';
      message.mediaUrl = '';
      message.fileName = '';
      message.reactions = [];
      message.reply = undefined;
      await broadcastMessageUpdate(message, conversation);
      await Message.deleteOne({ _id: message._id });
      await purgeMediaIfUnused(mediaUrl);
      await refreshConversationLast(conversation._id);
    } else {
      const m2 = await Message.findOneAndUpdate({ _id: message._id }, { $addToSet: { deletedFor: req.user._id } }, { new: true });
      // si tous les participants l'ont supprimé, plus personne n'en a besoin : suppression réelle
      if (m2 && conversation.participants.every((pid) => m2.deletedFor.some((d) => d.toString() === pid.toString()))) {
        await hardDeleteMessage(m2, conversation);
      }
    }
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// Quitter un groupe ou une communauté
app.post('/api/chats/:chatId/leave', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.chatId)) throw httpError(400, 'Identifiant invalide.');
    const conversation = await Conversation.findOne({ _id: req.params.chatId, participants: req.user._id });
    if (!conversation) throw httpError(404, 'Conversation introuvable.');
    if (conversation.type !== 'group') throw httpError(400, 'Tu ne peux quitter qu’un groupe.');
    await Conversation.updateOne({ _id: conversation._id }, { $pull: { participants: req.user._id } });
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ROUTES — STATUTS (24 h)
// ─────────────────────────────────────────────
// Audience = moi + toutes les personnes avec qui je partage une discussion.
async function statusAudience(userId) {
  const convs = await Conversation.find({ participants: userId }).select('participants').limit(500);
  const ids = new Set([userId.toString()]);
  for (const c of convs) for (const p of c.participants) ids.add(p.toString());
  return [...ids];
}

function statusJson(st, me) {
  const owner = st.userId && st.userId._id ? st.userId : null;
  const ownerId = owner ? owner._id.toString() : String(st.userId);
  const mine = ownerId === me.toString();
  return {
    id: st._id,
    userId: ownerId,
    displayName: owner ? owner.displayName : '',
    photoUrl: owner ? owner.photoUrl || '' : '',
    type: st.type,
    text: st.text,
    mediaUrl: st.mediaUrl,
    bg: st.bg,
    createdAt: st.createdAt,
    expiresAt: st.expiresAt,
    viewed: mine ? true : st.viewers.some((v) => v.toString() === me.toString()),
    viewCount: mine ? st.viewers.length : 0,
  };
}

app.get('/api/statuses', authenticate, async (req, res, next) => {
  try {
    const audience = await statusAudience(req.user._id);
    const list = await Status.find({ userId: { $in: audience }, expiresAt: { $gt: new Date() } })
      .populate('userId', 'displayName photoUrl')
      .sort({ createdAt: 1 })
      .limit(400);
    res.json({ success: true, data: { statuses: list.map((st) => statusJson(st, req.user._id)) } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/statuses', authenticate, async (req, res, next) => {
  try {
    const { type, text = '', mediaUrl = '', bg = '0' } = req.body || {};
    if (!['text', 'image', 'video'].includes(type)) throw httpError(400, 'Type de statut invalide.');
    const cleanText = String(text).trim().slice(0, 200);
    if (type === 'text' && !cleanText) throw httpError(400, 'Écris quelque chose pour ton statut.');
    if (type !== 'text' && !mediaUrl) throw httpError(400, 'Média manquant.');
    const st = await Status.create({
      userId: req.user._id,
      type,
      text: cleanText,
      mediaUrl: type === 'text' ? '' : String(mediaUrl).slice(0, 500),
      bg: String(bg).slice(0, 12),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
    statusAudience(req.user._id)
      .then((ids) => ids.forEach((id) => io.to(`user:${id}`).emit('status:changed', { userId: req.user._id.toString() })))
      .catch(() => {});
    res.status(201).json({ success: true, data: { status: { id: st._id } } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/statuses/:id/view', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) throw httpError(400, 'Identifiant invalide.');
    await Status.updateOne(
      { _id: req.params.id, userId: { $ne: req.user._id } },
      { $addToSet: { viewers: req.user._id } },
    );
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/statuses/:id', authenticate, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) throw httpError(400, 'Identifiant invalide.');
    const st = await Status.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    if (!st) throw httpError(404, 'Statut introuvable.');
    await purgeMediaIfUnused(st.mediaUrl);
    statusAudience(req.user._id)
      .then((ids) => ids.forEach((id) => io.to(`user:${id}`).emit('status:changed', { userId: req.user._id.toString() })))
      .catch(() => {});
    res.json({ success: true });
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
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ success: false, message: 'Fichier trop volumineux (12 Mo max).' });
  }
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
  // tout ce qui m'attendait est maintenant « reçu »
  markDelivered(socket.user._id).catch(() => {});

  socket.on('message:send', async (data = {}, callback = () => {}) => {
    try {
      const { chatId, text, type, mediaUrl, fileName, mimeType, durationMs, lat, lng, forwarded, replyTo, viewOnce } = data;
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
        lat,
        lng,
        forwarded,
        replyTo,
        viewOnce,
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
    setTimeout(sweepOrphanMedia, 60 * 1000).unref();
    setInterval(sweepOrphanMedia, 6 * 60 * 60 * 1000).unref();
  })
  .catch((error) => {
    console.error('Impossible de démarrer :', error.message);
    process.exit(1);
  });
