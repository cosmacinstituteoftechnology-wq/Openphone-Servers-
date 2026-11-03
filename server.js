// 1. Load environment variables (for local testing)
try { require('dotenv').config(); } catch (e) { console.log("No .env file found, relying on system variables."); }

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const multer     = require('multer');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const admin      = require('firebase-admin');

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 3000;
const VIEWER_TOKEN = process.env.VIEWER_TOKEN || 'super_secret_viewer_token_123';
const TOKEN_PEPPER = process.env.TOKEN_PEPPER || 'my_secret_pepper_string_12345';
const DEFAULT_RETENTION = Number(process.env.RETENTION_DAYS || 30);

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_B64 || 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=', 'base64');

/* ---------------- FIREBASE INITIALIZATION ---------------- */
try {
  let serviceAccount;
  
  // 1. Try Render Secret File (This is the most reliable method)
  if (fs.existsSync('/etc/secrets/serviceAccountKey.json')) {
    serviceAccount = JSON.parse(fs.readFileSync('/etc/secrets/serviceAccountKey.json', 'utf8'));
    console.log("✅ Loaded Firebase credentials from Render Secret File");
  } 
  // 2. Try Local File
  else if (fs.existsSync(path.join(__dirname, 'serviceAccountKey.json'))) {
    serviceAccount = require(path.join(__dirname, 'serviceAccountKey.json'));
    console.log("✅ Loaded Firebase credentials from local file");
  } 
  else {
    throw new Error("Missing serviceAccountKey.json. Please add it to Render Secret Files.");
  }

  // Fix newlines in private key just in case
  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://openphone-2a844-default-rtdb.firebaseio.com",
    storageBucket: "openphone-2a844.firebasestorage.app"
  });
  console.log("✅ Connected to Firebase Realtime Database & Storage!");
} catch (error) {
  console.error("❌ Firebase Admin initialization error:", error.message);
  process.exit(1); 
}

// ⭐ WE ARE NOW USING RTDB INSTEAD OF FIRESTORE ⭐
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

    // Query RTDB
    const snap = await rtdb.ref(`consents/${id}`).once('value');
    if (!snap.exists()) return res.status(403).json({ error: 'consent not found' });

    const d = snap.val();
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
      createdAt: Date.now(), // RTDB uses simple timestamps
      ipHash: hashNumber(req.ip || '')
    };

    // Save to RTDB
    await rtdb.ref(`consents/${consentId}`).set(record);
    
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
    const startedAt   = req.body.startedAt ? new Date(req.body.startedAt).toISOString() : new Date().toISOString();
    const durationSec = Number(req.body.durationSec || 0);
    const direction   = req.body.direction === 'outgoing' ? 'outgoing' : 'incoming';
    const expiresAt   = new Date(Date.now() + req.consent.retentionDays * 86400_000).toISOString();

    const encrypted = encryptBuffer(req.file.buffer);
    const storagePath = `recordings/${req.consent.id}/${recordingId}.enc`;

    // 1. Save to Storage
    await bucket.file(storagePath).save(encrypted, {
      resumable: false,
      metadata: { contentType: 'application/octet-stream' }
    });

    // 2. Save to RTDB
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

    await rtdb.ref(`recordings/${recordingId}`).set(metaData);

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

    // Fetch all recordings from RTDB
    const snap = await rtdb.ref('recordings').once('value');
    if (!snap.exists()) return res.json([]);

    const all = snap.val();
    const items = Object.values(all)
      .filter(r => r.consentId === consentId && r.status === 'stored')
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
      .slice(0, 200);

    res.json(items);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch recordings: ' + e.message });
  }
});

app.get('/api/recordings/:id/audio', requireViewer, async (req, res) => {
  try {
    const snap = await rtdb.ref(`recordings/${req.params.id}`).once('value');
    if (!snap.exists()) return res.status(404).json({ error: 'not found' });

    const d = snap.val();
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
    const ref = rtdb.ref(`recordings/${req.params.id}`);
    const snap = await ref.once('value');
    if (!snap.exists()) return res.status(404).json({ error: 'not found' });

    const d = snap.val();
    try { await bucket.file(d.storagePath).delete({ ignoreNotFound: true }); } catch (e) {}
    
    await ref.remove();

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete: ' + e.message });
  }
});

/* ---------------- RETENTION SWEEPER ---------------- */
async function sweepExpired() {
  try {
    const now = new Date().toISOString();
    const snap = await rtdb.ref('recordings').once('value');
    if (!snap.exists()) return;

    const all = snap.val();
    for (const [id, d] of Object.entries(all)) {
      if (d.expiresAt < now) {
        try { 
          await bucket.file(d.storagePath).delete({ ignoreNotFound: true }); 
        } catch (e) {}
        await rtdb.ref(`recordings/${id}`).remove();
      }
    }
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
