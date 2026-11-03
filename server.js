// 1. Load environment variables (for local testing)
try { require('dotenv').config(); } catch (e) { console.log("No .env file found, relying on system variables."); }

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

// Ensure MASTER_KEY is exactly 32 bytes
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_B64 || 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=', 'base64');
if (MASTER_KEY.length !== 32) {
  console.error('❌ MASTER_KEY_B64 must decode to exactly 32 bytes.');
}

/* ---------------- FIREBASE INITIALIZATION ---------------- */
// Hardcoded credentials so we don't need the .json file anymore
const serviceAccount = {
  "type": "service_account",
  "project_id": "openphone-2a844",
  "private_key_id": "e666e75b44d8a36ec7b0554de860b2562f14aa3b",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAo2hAylKBpYcB\nNU2pqjfQjRKDBheUtkRtDox0hK+G5wW4NMO7W9h2y1ccChA+qHCiks1mQ2hMoQRf\nfd2g+zKiHUcxYXsmABZPlcaF//4umN2BVz2WP6UwUMxbtdaE96ermXjCyoLh8TJW\nQY8iDKpE7jIgc3LjS8SLiR4joktFS+yZ1YIyTJvyLws5OcDoEl4JZcVdlauh+Ukr\nitKA5y8WHHdWB3/Hw9l4VlhKoa0jMXs0BoNYBH/f6vwzZFLeNBEUyFcgFYsCYnPR\n02g6SRAVH7941oqUW/VN+r1aXAA2dMpExBjJBaZeu6eQsYvnimKO1J0DiHbbkM9A\nBeJGeMd9AgMBAAECggEAHNpcyxeCtBhu2Cd7smXkZkA6/ZT0AzoplYwQTYNyJuqD\nWMvOZUmkamaabYC0Xi4scK08RoziGlgjp4naoDn/o3hvKV5Ia7CnptPwIDHviFst\nEipW9yIhQ9NWSIY70z6kxnb+N27Nm7ncqD65iYgMGLb0mxevpYu7rIqlEQFF9OLf\nq6oQszdwvK0m/3/Tk9A69CfUKyshHJa+yy2cbaOJQavAl6HVfejbb6WCzIIJJjJn\nMJIG4/5mFgRQFJcHe0saUA1dVmlXXAEgF3HcF6QgqjwVVzDc3203UOiZAgGEOfHw\nOx2k/1mOJvXwZVedj5xLibvXEGdOuIWSXUCM7IF/oQKBgQDs5aKEXw7EAQ/sWklK\nhnq9mmfmVsi/6KAuJR/RgdaiF9r6ifcsEC0v1N/nVt1d24rHNfU5zosp/V3+opUn\nMU0UsfzTpyolwKeiAja5BkF8StujSXC96HzZjo+cG9B5CPXVb2DFXU2LC2iz8Z0Y\n4Q/AvvrOYDSxqfDR0HGECNhttwKBgQDQLB8OllC5/8gFtn53Hu/pwpVVqfl1OXTE\nLlyeObFwsO3DpWb8uKy+R9hwEKQ9ih1HNskcuzNjH2kneoITnxCRRZgMPbNUbR0w\nuhJDtwyTn8nb1sXgRqCMq5mbOu6teh1BsIOpdVqznlPNkEQm5GwnZGr/xCBCYbVn\njzd3kBR0awKBgDdn/fq3wNxW40KEW1/y1AJEesiEw68e2Vfxlt+JXonKyoyOeCD2\nJ5toTnXs+xlYn7y4AgLjK+lGORW1MO1Zuo18k4VtM45g4NQjcGkV7XsEhxpJsvS3\ny3uWvD/mwXuNfPHOevOuPtSmdnafq/6FpQmPoVljZu+mr4xjFCmtZ/FBAoGABRq/\n3DS1YAo0lmdGLJeWnG3ICaS0WDqDcXgNj1es0S2VdvGsV9ATdEsAtKbD0Dp9w0xF\nnC2+8dRIWM55OA/zcQx60PoGVrCiQZqebgikB06ovXpDud8herGOf67vQVO4Oe8h\nG1ukULk2Jtk9wpJhUIn20bS2ccpBj3uEiar/xWcCgYEApEx9wDFEaCeU44XW8j40\nO1q1sLDSIDZa51IR3f1GEf9XFrGeZ6VcTQx0mfDqnCwpoJ5epBCEcmZOeWISwc5a\nSsNMSzMZzMgzz5DJRdFKvhV1uHojRtqJt6ykKQ+RQ4/D8pJp/2oYDab8YSMIQYD0\nLAyU2aoCePiPZrimqOk5e5g=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@openphone-2a844.iam.gserviceaccount.com",
  "client_id": "114251940539515101423",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40openphone-2a844.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://openphone-2a844-default-rtdb.firebaseio.com",
    storageBucket: "openphone-2a844.firebasestorage.app"
  });
  console.log("✅ Connected to Firebase Project successfully!");
} catch (error) {
  console.error("❌ Firebase Admin initialization error:", error.message);
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

app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'agreement.html'));
});

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
    res.status(500).json({ error: 'consent check failed: ' + e.message });
  }
}

function requireViewer(req, res, next) {
  const t = req.get('x-viewer-token');
  if (!t || !safeEqual(t, VIEWER_TOKEN)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

/* ---------------- CONSENT ENDPOINTS ---------------- */
app.post('/api/consent', async (req, res) => {
  try {
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
  } catch (error) {
    console.error("❌ Consent Error:", error);
    res.status(500).json({ error: 'Database error: ' + error.message });
  }
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
    res.status(500).json({ error: 'upload failed: ' + e.message });
  }
});

app.get('/api/recordings', requireViewer, async (req, res) => {
  try {
    const consentId = String(req.query.consentId || '');
    if (!consentId) return res.status(400).json({ error: 'consentId required' });

    const snap = await db.collection('recordings')
      .where('consentId', '==', consentId)
      .where('status', '==', 'stored')
      .orderBy('startedAt', 'desc')
      .limit(200)
      .get();

    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch recordings: ' + e.message });
  }
});

app.get('/api/recordings/:id/audio', requireViewer, async (req, res) => {
  try {
    const snap = await db.collection('recordings').doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ error: 'not found' });

    const d = snap.data();
    if (d.status !== 'stored') return res.status(410).json({ error: 'recording no longer available' });

    const [buf] = await bucket.file(d.storagePath).download();
    const plain = decryptBuffer(buf);

    res.setHeader('Content-Type', 'audio/mp4');
    res.setHeader('Cache-Control', 'no-store');
    res.send(plain);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to decrypt file: " + error.message });
  }
});

app.post('/api/recordings/:id/delete', requireViewer, async (req, res) => {
  try {
    const ref  = db.collection('recordings').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'not found' });

    const d = snap.data();
    try { await bucket.file(d.storagePath).delete({ ignoreNotFound: true }); } catch (e) {}
    
    await ref.delete();
    await rtdb.ref(`openphone/recordings/${d.consentId}/${req.params.id}`).remove();

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete: ' + e.message });
  }
});

/* ---------------- RETENTION SWEEPER ---------------- */
async function sweepExpired() {
  try {
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
    console.log(`Swept ${snap.size} expired recordings`);
  } catch (err) {
    console.error("Sweeper error:", err);
  }
}
setInterval(sweepExpired, 60 * 60 * 1000);

app.get('/health', (_req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error("Global Error:", err);
  res.status(500).json({ error: 'Internal Server Error: ' + err.message });
});

app.listen(PORT, () => console.log(`🚀 Server running securely on port ${PORT}`));
