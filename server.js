/**
 * ============================================================
 * OPENPHONE-CLONE SERVER — V3.0 ENTERPRISE EDITION
 * Firebase Firestore | Virtual Extensions | Conference Calls
 * Voicemail | Auth | Typing Indicators | Advanced Analytics
 * ============================================================
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

// ── FIREBASE SDK ──
const { initializeApp } = require('firebase/app');
const { 
  getFirestore, doc, setDoc, getDoc, updateDoc, deleteDoc,
  collection, addDoc, query, where, getDocs, orderBy, limit 
} = require('firebase/firestore');

// ── INITIALIZE EXPRESS & SOCKET.IO ──
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 60000,
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve the HTML from root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'phone_dailer.html'));
});

// ── FIREBASE CONFIGURATION ──
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY || "AIzaSyAn_k3_o500O-tvMxHKsBXTfKuTDd0igzI",
  authDomain: process.env.FIREBASE_AUTH_DOMAIN || "openphone-2a844.firebaseapp.com",
  projectId: process.env.FIREBASE_PROJECT_ID || "openphone-2a844",
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "openphone-2a844.firebasestorage.app",
  messagingSenderId: process.env.FIREBASE_MSG_SENDER_ID || "274916994647",
  appId: process.env.FIREBASE_APP_ID || "1:274916994647:web:c7abf7feeac67ad2c9bd12",
  measurementId: process.env.FIREBASE_MEASUREMENT_ID || "G-4V12VQGPZC"
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// ── IN-MEMORY CACHE (For fast real-time routing) ──
const activeCalls = new Map();       // callId -> call data
const activeConferences = new Map(); // roomId -> participants
const socketUserMap = new Map();     // socketId -> userId
const userSocketMap = new Map();     // userId -> socketId
const userStatusMap = new Map();     // userId -> status

// ── HELPER FUNCTIONS ──
function generateId(prefix) {
  return `${prefix}${crypto.randomBytes(6).toString('hex')}`;
}

function generateVirtualNumber() {
  return `EXT${Math.floor(1000 + Math.random() * 9000)}`;
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function saveToFirestore(collectionName, docId, data) {
  try {
    await setDoc(doc(db, collectionName, docId), { ...data, updatedAt: new Date().toISOString() }, { merge: true });
    return { success: true };
  } catch (err) {
    console.error(`❌ Firestore write error (${collectionName}):`, err.message);
    return { success: false, error: err.message };
  }
}

async function getFromFirestore(collectionName, docId) {
  try {
    const docRef = doc(db, collectionName, docId);
    const docSnap = await getDoc(docRef);
    return docSnap.exists() ? docSnap.data() : null;
  } catch (err) {
    console.error(`❌ Firestore read error (${collectionName}):`, err.message);
    return null;
  }
}

async function queryFirestore(collectionName, field, operator, value) {
  try {
    const q = query(collection(db, collectionName), where(field, operator, value));
    const querySnapshot = await getDocs(q);
    const results = [];
    querySnapshot.forEach((doc) => results.push({ id: doc.id, ...doc.data() }));
    return results;
  } catch (err) {
    console.error(`❌ Firestore query error (${collectionName}):`, err.message);
    return [];
  }
}

async function fireWebhooks(eventType, payload) {
  try {
    const hooks = await queryFirestore('webhooks', 'status', '==', 'enabled');
    for (const hook of hooks) {
      if (hook.events.includes(eventType) || hook.events.includes('*')) {
        await axios.post(hook.url, {
          id: generateId('EV'), object: 'event', apiVersion: 'v4',
          createdAt: new Date().toISOString(), type: eventType, data: payload,
        }, { timeout: 5000 }).catch(e => console.error(`Webhook failed: ${hook.url}`));
      }
    }
  } catch (err) {
    console.error('Webhook processing error:', err.message);
  }
}

// ============================================================
// REST API ROUTES
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), version: '3.0.0', database: 'Firebase Connected' });
});

// ── 1. USER MANAGEMENT & AUTH ──
app.post('/api/users/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  const existing = await queryFirestore('users', 'email', '==', email);
  if (existing.length > 0) return res.status(400).json({ error: 'Email already in use' });

  const userId = generateId('USR');
  const virtualNumber = generateVirtualNumber();
  const hashedPassword = hashPassword(password);
  
  const user = {
    userId, username, email, password: hashedPassword, virtualNumber,
    role: 'member', status: 'active',
    createdAt: new Date().toISOString()
  };

  const result = await saveToFirestore('users', userId, user);
  if (result.success) {
    delete user.password;
    res.status(201).json({ data: user });
  } else {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await queryFirestore('users', 'email', '==', email);
  if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  
  const user = users[0];
  if (user.password !== hashPassword(password)) return res.status(401).json({ error: 'Invalid credentials' });
  
  delete user.password;
  res.json({ data: user, token: generateId('TOKEN') });
});

app.get('/api/users/:userId', async (req, res) => {
  const user = await getFromFirestore('users', req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  delete user.password;
  res.json({ data: user });
});

app.get('/api/users', async (req, res) => {
  const users = await queryFirestore('users', 'status', '==', 'active');
  users.forEach(u => delete u.password);
  res.json({ data: users });
});

// ── 2. VIRTUAL NUMBER MANAGEMENT ──
app.post('/api/virtual-numbers/generate', async (req, res) => {
  const { userId } = req.body;
  const virtualNumber = generateVirtualNumber();
  const numberData = {
    numberId: generateId('VN'), virtualNumber, userId, status: 'active',
    createdAt: new Date().toISOString()
  };
  await saveToFirestore('virtual_numbers', numberData.numberId, numberData);
  res.status(201).json({ data: numberData });
});

app.get('/api/virtual-numbers/:userId', async (req, res) => {
  const numbers = await queryFirestore('virtual_numbers', 'userId', '==', req.params.userId);
  res.json({ data: numbers });
});

// ── 3. CONTACTS & ADDRESS BOOK ──
app.post('/api/contacts', async (req, res) => {
  const contactId = generateId('CT');
  const contact = { contactId, ...req.body, createdAt: new Date().toISOString() };
  await saveToFirestore('contacts', contactId, contact);
  res.status(201).json({ data: contact });
});

app.get('/api/contacts/:userId', async (req, res) => {
  const contacts = await queryFirestore('contacts', 'userId', '==', req.params.userId);
  res.json({ data: contacts });
});

// ── 4. SMS / MESSAGING ──
app.post('/api/messages/send', async (req, res) => {
  const { from, to, content, userId, conversationId } = req.body;
  const messageId = generateId('MSG');
  
  const message = {
    messageId, conversationId: conversationId || generateId('CONV'),
    from, to, content, userId,
    direction: 'outgoing', status: 'sent', read: false,
    createdAt: new Date().toISOString()
  };
  
  await saveToFirestore('messages', messageId, message);
  
  const targetSocket = userSocketMap.get(to);
  if (targetSocket) {
    io.to(targetSocket).emit('message-received', message);
  }
  
  await fireWebhooks('message.sent', { object: message });
  res.status(201).json({ data: message });
});

app.get('/api/messages/:userId', async (req, res) => {
  const messages = await queryFirestore('messages', 'userId', '==', req.params.userId);
  res.json({ data: messages });
});

// ── 5. VOICEMAIL & CALL RECORDING ──
app.post('/api/voicemails', async (req, res) => {
  const { callId, recordingUrl, transcript, duration } = req.body;
  const voicemailId = generateId('VM');
  const voicemail = {
    voicemailId, callId, recordingUrl, transcript, duration,
    listened: false, createdAt: new Date().toISOString()
  };
  await saveToFirestore('voicemails', voicemailId, voicemail);
  res.status(201).json({ data: voicemail });
});

app.get('/api/voicemails/:userId', async (req, res) => {
  const voicemails = await queryFirestore('voicemails', 'userId', '==', req.params.userId);
  res.json({ data: voicemails });
});

// ── 6. CALL LOGS & ANALYTICS ──
app.post('/api/calls/log', async (req, res) => {
  const callId = generateId('CALL');
  const callLog = { callId, ...req.body, createdAt: new Date().toISOString() };
  await saveToFirestore('call_logs', callId, callLog);
  res.status(201).json({ data: callLog });
});

app.get('/api/calls/logs/:userId', async (req, res) => {
  const logs = await queryFirestore('call_logs', 'userId', '==', req.params.userId);
  res.json({ data: logs });
});

app.get('/api/analytics/:userId', async (req, res) => {
  const callLogs = await queryFirestore('call_logs', 'userId', '==', req.params.userId);
  const messages = await queryFirestore('messages', 'userId', '==', req.params.userId);
  
  const inbound = callLogs.filter(c => c.direction === 'incoming').length;
  const outbound = callLogs.filter(c => c.direction === 'outgoing').length;
  const missed = callLogs.filter(c => c.status === 'missed').length;
  
  res.json({
    data: {
      totalCalls: callLogs.length,
      inboundCalls: inbound,
      outboundCalls: outbound,
      missedCalls: missed,
      totalMessages: messages.length,
      activeCalls: activeCalls.size,
      activeConferences: activeConferences.size,
      timestamp: new Date().toISOString()
    }
  });
});

// ── 7. RING GROUPS & IVR ──
app.post('/api/ring-groups', async (req, res) => {
  const groupId = generateId('RG');
  const group = { groupId, ...req.body, createdAt: new Date().toISOString() };
  await saveToFirestore('ring_groups', groupId, group);
  res.status(201).json({ data: group });
});

app.get('/api/ring-groups/:userId', async (req, res) => {
  const groups = await queryFirestore('ring_groups', 'userId', '==', req.params.userId);
  res.json({ data: groups });
});

// ── 8. WEBHOOKS ──
app.post('/api/webhooks', async (req, res) => {
  const webhookId = generateId('WH');
  const hook = { webhookId, ...req.body, status: 'enabled', createdAt: new Date().toISOString() };
  await saveToFirestore('webhooks', webhookId, hook);
  res.status(201).json({ data: hook });
});

// ============================================================
// SOCKET.IO — REAL-TIME NETWORK ENGINE (V3.0)
// ============================================================
io.on('connection', (socket) => {
  console.log(`🔌 Client connected: ${socket.id}`);

  // ── User Registration & Presence ──
  socket.on('register', async (userData) => {
    const { userId, username } = userData;
    socketUserMap.set(socket.id, userId);
    userSocketMap.set(userId, socket.id);
    userStatusMap.set(userId, 'online');
    
    await saveToFirestore('users', userId, { userId, username, status: 'online', lastSeen: new Date().toISOString() });
    
    io.emit('user-list', Array.from(userSocketMap.keys()).map(id => ({
      userId: id, username: id, status: userStatusMap.get(id) || 'offline'
    })));
    console.log(`👤 Registered: ${username} (${userId})`);
  });

  // ── Direct Call Signaling ──
  socket.on('call-initiate', async ({ from, to }) => {
    const callId = generateId('CALL');
    const call = {
      callId, from, to, status: 'ringing',
      direction: 'outgoing', startedAt: new Date().toISOString(),
      participants: [from, to]
    };
    activeCalls.set(callId, call);
    
    await fireWebhooks('call.ringing', { object: call });
    
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) {
      io.to(targetSocket).emit('call-incoming', { callId, from });
    } else {
      socket.emit('call-voicemail', { callId, message: 'User offline. Leave a voicemail.' });
    }
  });

  socket.on('call-answer', ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    call.status = 'active';
    activeCalls.set(callId, call);
    
    const callerSocket = userSocketMap.get(call.from);
    if (callerSocket) io.to(callerSocket).emit('call-answered', { callId });
  });

  socket.on('call-end', async ({ callId, reason }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    
    call.status = reason || 'completed';
    call.completedAt = new Date().toISOString();
    call.duration = Math.floor((new Date(call.completedAt) - new Date(call.startedAt)) / 1000);
    
    await saveToFirestore('call_logs', callId, call);
    activeCalls.delete(callId);
    
    if (userSocketMap.has(call.from)) io.to(userSocketMap.get(call.from)).emit('call-ended', { callId });
    if (userSocketMap.has(call.to)) io.to(userSocketMap.get(call.to)).emit('call-ended', { callId });
    
    await fireWebhooks('call.completed', { object: call });
  });

  // ── Conference Calling (Multi-Party) ──
  socket.on('conference-join', ({ roomId, userId }) => {
    socket.join(roomId);
    if (!activeConferences.has(roomId)) activeConferences.set(roomId, []);
    activeConferences.get(roomId).push(userId);
    
    io.to(roomId).emit('conference-participants', { roomId, participants: activeConferences.get(roomId) });
    console.log(`📞 ${userId} joined conference ${roomId}`);
  });

  socket.on('conference-leave', ({ roomId, userId }) => {
    socket.leave(roomId);
    if (activeConferences.has(roomId)) {
      const participants = activeConferences.get(roomId).filter(id => id !== userId);
      activeConferences.set(roomId, participants);
      io.to(roomId).emit('conference-participants', { roomId, participants });
      if (participants.length === 0) activeConferences.delete(roomId);
    }
  });

  // ── WebRTC Signaling ──
  socket.on('ice-candidate', ({ to, candidate }) => {
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('ice-candidate', { from: socketUserMap.get(socket.id), candidate });
  });

  socket.on('offer', ({ to, offer }) => {
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('offer', { from: socketUserMap.get(socket.id), offer });
  });

  socket.on('answer', ({ to, answer }) => {
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('answer', { from: socketUserMap.get(socket.id), answer });
  });

  // ── Messaging Enhancements (Typing & Read Receipts) ──
  socket.on('typing', ({ to, from }) => {
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('user-typing', { from });
  });

  socket.on('stop-typing', ({ to, from }) => {
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('user-stop-typing', { from });
  });

  socket.on('message-read', async ({ messageId, to }) => {
    await saveToFirestore('messages', messageId, { read: true, readAt: new Date().toISOString() });
    const targetSocket = userSocketMap.get(to);
    if (targetSocket) io.to(targetSocket).emit('message-read-receipt', { messageId });
  });

  // ── Disconnect & Cleanup ──
  socket.on('disconnect', async () => {
    const userId = socketUserMap.get(socket.id);
    if (userId) {
      userStatusMap.set(userId, 'offline');
      await saveToFirestore('users', userId, { status: 'offline', lastSeen: new Date().toISOString() });
      socketUserMap.delete(socket.id);
      userSocketMap.delete(userId);
      io.emit('user-list', Array.from(userSocketMap.keys()).map(id => ({ userId: id, username: id, status: userStatusMap.get(id) || 'offline' })));
      console.log(`👋 Disconnected: ${userId}`);
    }
  });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 OpenPhone Enterprise Server v3.0 running on port ${PORT}`);
  console.log(`🔥 Firebase Firestore Connected`);
  console.log(`🔗 REST API available at /api`);
});
