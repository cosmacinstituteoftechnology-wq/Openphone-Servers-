require('dotenv').config();
const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const multer     = require('multer');
const crypto     = require('crypto');
const path       = require('path');
const admin      = require('firebase-admin');

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 3000;
const VIEWER_TOKEN = process.env.VIEWER_TOKEN || 'super_secret_viewer_token_123';
const TOKEN_PEPPER = process.env.TOKEN_PEPPER || 'my_secret_pepper_string_12345';
const DEFAULT_RETENTION = Number(process.env.RETENTION_DAYS || 30);

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_B64 || 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=', 'base64');
if (MASTER_KEY.length !== 32) {
  console.error('MASTER_KEY_B64 must decode to exactly 32 bytes.');
  process.exit(1);
}

/* ---------------- FIREBASE INITIALIZATION ---------------- */
const PROJECT_ID = "openphone-2a844";
const DATABASE_URL = "https://openphone-2a844-default-rtdb.firebaseio.com";
const STORAGE_BUCKET = "openphone-2a844.firebasestorage.app";

try {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId:   PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
    }),
    storageBucket: STORAGE_BUCKET,
    databaseURL: DATABASE_URL
  });
  console.log("✅ Connected to Firebase Project: " + PROJECT_ID);
} catch (error) {
  console.error("❌ Firebase Admin initialization error. Did you set the .env file?");
  process.exit(1);
}

const db     = admin.firestore();
const rtdb   = admin.database(); 
const bucket = admin.storage().bucket();

/* ---------------- HELPERS ---------------- */
const safeEqual = (a, b) => {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
};
const hashToken = (t) => crypto.createHash('sha256').update(t + TOKEN_PEPPER).digest('hex');
const hashNumber = (n) => crypto.createHash('sha256').update(String(n || '') + TOKEN_PEPPER).digest('hex');

function encryptBuffer(buf) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const enc    = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}
function decryptBuffer(buf) {
  const iv     = buf.subarray(0, 12);
  const tag    = buf.subarray(12, 28);
  const data   = buf.subarray(28);
  const d      = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}

/* ---------------- APP SETUP ---------------- */
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({ windowMs: 60_000, max: 60 });
app.use('/api/', apiLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

/* ---------------- MIDDLEWARE ---------------- */
async function requireConsent(req, res, next) {
  try {
    const id    = req.get('x-consent-id');
    const token = req.get('x-consent-token');
    if (!id || !token) return res.status(401).json({ error: 'missing consent headers' });

    const snap = await db.collection('consents').doc(id).get();
    if (!snap.exists) return res.status(403).json({ error: 'consent not found' });

    const d = snap.data();
    if (d.status !== 'active') return res.status(403).json({ error: 'consent is not active' });
    if (!safeEqual(hashToken(token), d.tokenHash)) return res.status(403).json({ error: 'invalid consent token' });

    req.consent = { id, ...d };
    next();
  } catch (e) {
    res.status(500).json({ error: 'consent check failed' });
  }
}

function requireViewer(req, res, next) {
  const t = req.get('x-viewer-token');
  if (!t || !safeEqual(t, VIEWER_TOKEN)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

/* ---------------- CONSENT ENDPOINTS ---------------- */
app.post('/api/consent', async (req, res) => {
  const { personA, personB, deviceLabel, retentionDays,
          agreedToCallerNotice, agreedToRevocation, agreedToLegalResponsibility } = req.body || {};

  if (!personA || !personB || !deviceLabel) return res.status(400).json({ error: 'names and device required' });
  if (!agreedToCallerNotice || !agreedToRevocation || !agreedToLegalResponsibility)
    return res.status(400).json({ error: 'all consent boxes must be accepted' });

  const days = Math.min(Math.max(Number(retentionDays) || DEFAULT_RETENTION, 1), 365);
  const consentId    = crypto.randomUUID();
  const consentToken = crypto.randomBytes(32).toString('hex');

  const record = {
    personA, personB, deviceLabel,
    retentionDays: days,
    status: 'active',
    tokenHash: hashToken(consentToken),
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    ipHash: hashNumber(req.ip || '')
  };

  await db.collection('consents').doc(consentId).set(record);
  res.json({ consentId, consentToken, retentionDays: days });
});

app.get('/api/consent/:id/status', requireConsent, (req, res) => {
  res.json({ active: true, consentId: req.consent.id, retentionDays: req.consent.retentionDays });
});

/* ---------------- RECORDING ENDPOINTS ---------------- */
app.post('/api/recordings', requireConsent, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'audio file required' });

    const recordingId = crypto.randomUUID();
    const startedAt   = new Date(req.body.startedAt || Date.now());
    const durationSec = Number(req.body.durationSec || 0);
    const direction   = req.body.direction === 'outgoing' ? 'outgoing' : 'incoming';
    const expiresAt   = new Date(Date.now() + req.consent.retentionDays * 86400_000);

    const encrypted = encryptBuffer(req.file.buffer);
    const storagePath = `recordings/${req.consent.id}/${recordingId}.enc`;

    await bucket.file(storagePath).save(encrypted, {
      resumable: false,
      metadata: { contentType: 'application/octet-stream' }
    });

    const metaData = {
      consentId: req.consent.id,
      storagePath,
      direction,
      startedAt,
      durationSec,
      sizeBytes: encrypted.length,
      status: 'stored',
      expiresAt
    };

    await db.collection('recordings').doc(recordingId).set(metaData);

    // Write to your public RTDB node (openphone)
    await rtdb.ref(`openphone/recordings/${req.consent.id}/${recordingId}`).set({
      recordingId,
      storagePath,
      direction,
      startedAt: startedAt.toISOString(),
      durationSec,
      status: 'stored',
      expiresAt: expiresAt.toISOString()
    });

    res.json({ ok: true, recordingId, expiresAt });
  } catch (e) {
    console.error("Upload error:", e);
    res.status(500).json({ error: 'upload failed' });
  }
});

app.get('/api/recordings', requireViewer, async (req, res) => {
  const consentId = String(req.query.consentId || '');
  if (!consentId) return res.status(400).json({ error: 'consentId required' });

  const snap = await db.collection('recordings')
    .where('consentId', '==', consentId)
    .where('status', '==', 'stored')
    .orderBy('startedAt', 'desc')
    .limit(200)
    .get();

  res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
});

app.get('/api/recordings/:id/audio', requireViewer, async (req, res) => {
  const snap = await db.collection('recordings').doc(req.params.id).get();
  if (!snap.exists) return res.status(404).json({ error: 'not found' });

  const d = snap.data();
  if (d.status !== 'stored') return res.status(410).json({ error: 'recording no longer available' });

  try {
    const [buf] = await bucket.file(d.storagePath).download();
    const plain = decryptBuffer(buf);

    res.setHeader('Content-Type', 'audio/mp4');
    res.setHeader('Cache-Control', 'no-store');
    res.send(plain);
  } catch (error) {
    res.status(500).json({ error: "Failed to decrypt file" });
  }
});

app.post('/api/recordings/:id/delete', requireViewer, async (req, res) => {
  const ref  = db.collection('recordings').doc(req.params.id);
  const snap = await ref.get();
  if (!snap.exists) return res.status(404).json({ error: 'not found' });

  const d = snap.data();
  try { await bucket.file(d.storagePath).delete({ ignoreNotFound: true }); } catch (e) {}
  
  await ref.delete();
  await rtdb.ref(`openphone/recordings/${d.consentId}/${req.params.id}`).remove();

  res.json({ ok: true });
});

/* ---------------- RETENTION SWEEPER ---------------- */
async function sweepExpired() {
  const now = new Date();
  const snap = await db.collection('recordings').where('expiresAt', '<', now).limit(200).get();
  if (snap.empty) return;

  for (const doc of snap.docs) {
    const d = doc.data();
    try { 
      await bucket.file(d.storagePath).delete({ ignoreNotFound: true }); 
      await rtdb.ref(`openphone/recordings/${d.consentId}/${doc.id}`).remove();
    } catch (e) {}
    await doc.ref.delete();
  }
}
setInterval(() => sweepExpired().catch(console.error), 60 * 60 * 1000);

app.get('/health', (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`🚀 Server running securely on port ${PORT}`));
