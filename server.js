require('dotenv').config();

const http = require('http');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Server } = require('socket.io');

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
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['private', 'group'], default: 'private' },
  title: { type: String, trim: true, default: '' },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastMessage: {
    text: { type: String, default: '' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date },
  },
}, { timestamps: true });
conversationSchema.index({ participants: 1, updatedAt: -1 });

const messageSchema = new mongoose.Schema({
  conversationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation',
    required: true,
    index: true,
  },
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: { type: String, enum: ['text'], default: 'text' },
  text: { type: String, required: true, trim: true, maxlength: 5000 },
  createdAt: { type: Date, default: Date.now, index: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
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
    photoUrl: user.photoUrl,
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
    const user = await User.findById(payload.sub).select('_id displayName email country program photoUrl');
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
// DATABASE
// ─────────────────────────────────────────────
async function connectDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('La variable MONGODB_URI est absente du fichier .env.');
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 15000 });
  console.log(`MongoDB connected: ${mongoose.connection.name}`);
}

// ─────────────────────────────────────────────
// APP + SOCKET.IO
// ─────────────────────────────────────────────
const app = express();
const server = http.createServer(app);

const allowedOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((origin) => origin.trim());

app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origine non autorisée par CORS.'));
  },
}));
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const io = new Server(server, {
  cors: {
    origin: allowedOrigins.includes('*') ? '*' : allowedOrigins,
    methods: ['GET', 'POST'],
  },
});
app.set('io', io);

// ─────────────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────────────
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { displayName, email, password, country = '', program = '' } = req.body;
    if (!displayName || !email || !password) {
      return res.status(400).json({ success: false, message: 'Nom, e-mail et mot de passe obligatoires.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ success: false, message: 'Le mot de passe doit contenir au moins 8 caractères.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Cette adresse e-mail est déjà utilisée.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({
      displayName, email: normalizedEmail, passwordHash, country, program,
    });

    return res.status(201).json({
      success: true,
      message: 'Compte créé.',
      data: { user: publicUser(user), token: createToken(user._id) },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ success: false, message: 'Cette adresse e-mail est déjà utilisée.' });
    }
    next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'E-mail et mot de passe obligatoires.' });
    }

    const user = await User.findOne({ email: String(email).trim().toLowerCase() })
      .select('+passwordHash');
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, message: 'Identifiants incorrects.' });
    }

    return res.json({
      success: true,
      message: 'Connexion réussie.',
      data: { user: publicUser(user), token: createToken(user._id) },
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({ success: true, data: { user: publicUser(req.user) } });
});

// ─────────────────────────────────────────────
// ROUTES — CHATS
// ─────────────────────────────────────────────
app.get('/api/chats', authenticate, async (req, res, next) => {
  try {
    const conversations = await Conversation.find({ participants: req.user._id })
      .populate('participants', 'displayName email photoUrl country')
      .sort({ updatedAt: -1 })
      .limit(100);
    res.json({ success: true, data: { conversations } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/chats/group', authenticate, async (req, res, next) => {
  try {
    const { title, participantIds = [] } = req.body;
    if (!title || !Array.isArray(participantIds)) {
      return res.status(400).json({ success: false, message: 'Nom du groupe et liste des membres requis.' });
    }

    const ids = [...new Set([req.user._id.toString(), ...participantIds.map(String)])];
    if (ids.some((id) => !mongoose.isValidObjectId(id))) {
      return res.status(400).json({ success: false, message: 'Identifiant de membre invalide.' });
    }

    const count = await User.countDocuments({ _id: { $in: ids } });
    if (count !== ids.length) {
      return res.status(400).json({ success: false, message: 'Un ou plusieurs membres sont introuvables.' });
    }

    const conversation = await Conversation.create({
      type: 'group',
      title: String(title).trim(),
      participants: ids,
      createdBy: req.user._id,
    });

    const populated = await conversation.populate('participants', 'displayName email photoUrl');
    res.status(201).json({ success: true, data: { conversation: populated } });
  } catch (error) {
    next(error);
  }
});

app.get('/api/chats/:chatId/messages', authenticate, async (req, res, next) => {
  try {
    const conversation = await Conversation.findOne({
      _id: req.params.chatId,
      participants: req.user._id,
    });
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

app.post('/api/chats/:chatId/messages', authenticate, async (req, res, next) => {
  try {
    const { text } = req.body;
    if (!text || !String(text).trim()) {
      return res.status(400).json({ success: false, message: 'Le message ne peut pas être vide.' });
    }

    const conversation = await Conversation.findOne({
      _id: req.params.chatId,
      participants: req.user._id,
    });
    if (!conversation) {
      return res.status(404).json({ success: false, message: 'Conversation introuvable.' });
    }

    const message = await Message.create({
      conversationId: conversation._id,
      senderId: req.user._id,
      text: String(text).trim(),
      type: 'text',
    });

    conversation.lastMessage = {
      text: message.text,
      senderId: req.user._id,
      createdAt: message.createdAt,
    };
    await conversation.save();

    const populated = await message.populate('senderId', 'displayName photoUrl');
    req.app.get('io').to(conversation._id.toString()).emit('message:new', populated);

    res.status(201).json({ success: true, data: { message: populated } });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// HEALTH + ERRORS
// ─────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.json({ success: true, name: 'Fesh API', health: '/health' });
});

app.get('/health', (_req, res) => {
  res.json({ success: true, status: 'ok', service: 'fesh-backend' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route introuvable: ${req.method} ${req.originalUrl}` });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Erreur interne du serveur.',
  });
});

// ─────────────────────────────────────────────
// SOCKET.IO HANDLERS
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
  socket.on('join_chat', async ({ chatId } = {}, callback = () => {}) => {
    try {
      const conversation = await Conversation.findOne({
        _id: chatId,
        participants: socket.user._id,
      }).select('_id');
      if (!conversation) return callback({ success: false, message: 'Accès refusé.' });
      socket.join(conversation._id.toString());
      callback({ success: true });
    } catch (_error) {
      callback({ success: false, message: 'Identifiant de conversation invalide.' });
    }
  });

  socket.on('message:send', async ({ chatId, text } = {}, callback = () => {}) => {
    try {
      if (!text || !String(text).trim()) {
        return callback({ success: false, message: 'Message vide.' });
      }
      const conversation = await Conversation.findOne({
        _id: chatId,
        participants: socket.user._id,
      });
      if (!conversation) return callback({ success: false, message: 'Accès refusé.' });

      const message = await Message.create({
        conversationId: conversation._id,
        senderId: socket.user._id,
        type: 'text',
        text: String(text).trim(),
      });

      conversation.lastMessage = {
        text: message.text,
        senderId: socket.user._id,
        createdAt: message.createdAt,
      };
      await conversation.save();

      const populated = await message.populate('senderId', 'displayName photoUrl');
      io.to(conversation._id.toString()).emit('message:new', populated);
      callback({ success: true, data: populated });
    } catch (_error) {
      callback({ success: false, message: 'Impossible d’envoyer le message.' });
    }
  });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 5000;

connectDatabase()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`Fesh API running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Impossible de démarrer sans MongoDB :', error.message);
    process.exit(1);
  });
