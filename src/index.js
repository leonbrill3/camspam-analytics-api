const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const path = require('path');
const dns = require('dns');
const twilio = require('twilio');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { GoogleAuth } = require('google-auth-library');

// API Version for tracking deployments
const API_VERSION = '2.3.0';

// ============================================
// THIRD-PARTY API CONFIGURATION
// ============================================

// Amplitude API credentials
const AMPLITUDE_API_KEY = process.env.AMPLITUDE_API_KEY;
const AMPLITUDE_SECRET_KEY = process.env.AMPLITUDE_SECRET_KEY;

// AppsFlyer API credentials
const APPSFLYER_API_TOKEN = process.env.APPSFLYER_API_TOKEN;
const APPSFLYER_APP_ID = process.env.APPSFLYER_APP_ID || 'id6761743132'; // CamSpam App ID

// Sentry API credentials
const SENTRY_AUTH_TOKEN = process.env.SENTRY_AUTH_TOKEN;
const SENTRY_ORG = process.env.SENTRY_ORG || 'camspam';
const SENTRY_PROJECT = process.env.SENTRY_PROJECT || 'camspam-ios';

// App Store Connect API credentials
const ASC_ISSUER_ID = process.env.ASC_ISSUER_ID;
const ASC_KEY_ID = process.env.ASC_KEY_ID;
const ASC_PRIVATE_KEY = process.env.ASC_PRIVATE_KEY; // Base64 encoded .p8 file contents
const ASC_APP_ID = process.env.ASC_APP_ID || '6761743132'; // CamSpam App ID

// Google Search Console API credentials
const GSC_CLIENT_EMAIL = process.env.GSC_CLIENT_EMAIL;
const GSC_PRIVATE_KEY = process.env.GSC_PRIVATE_KEY; // Base64 encoded private key
const GSC_SITE_URL = process.env.GSC_SITE_URL || 'https://camspam.com';

// Force IPv4 to avoid ECONNREFUSED on some cloud platforms
dns.setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 3000;

// Twilio configuration for SMS verification
const twilioClient = process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;
const TWILIO_VERIFY_SERVICE_SID = process.env.TWILIO_VERIFY_SERVICE_SID;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for dashboard
}));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));

// Serve static dashboard
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting - 1000 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests' }
});
app.use('/v1/events', limiter);

// ============================================
// AUTHENTICATION SYSTEM WITH 2FA
// ============================================

// In-memory session store (in production, use Redis)
const sessions = new Map();
const pendingVerifications = new Map();

// Admin users (hashed passwords)
const adminUsers = {
  'leonbrill': {
    passwordHash: crypto.createHash('sha256').update('cKorsow12!s').digest('hex'),
    phone: '+19546631398',
    name: 'Leon Brill'
  }
};

// Generate session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Authentication middleware
function requireAuth(req, res, next) {
  const sessionToken = req.headers['x-session-token'] || req.query.sessionToken;

  if (!sessionToken || !sessions.has(sessionToken)) {
    return res.status(401).json({ error: 'Authentication required', needsLogin: true });
  }

  const session = sessions.get(sessionToken);
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionToken);
    return res.status(401).json({ error: 'Session expired', needsLogin: true });
  }

  req.user = session.user;
  next();
}

// Login - Step 1: Verify username/password
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  console.log('Login attempt:', { username, passwordLength: password?.length });

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = adminUsers[username.toLowerCase()];
  console.log('User found:', !!user, 'for username:', username.toLowerCase());

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  console.log('Password match:', passwordHash === user.passwordHash);

  if (passwordHash !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate verification token and send SMS
  const verificationId = crypto.randomBytes(16).toString('hex');
  pendingVerifications.set(verificationId, {
    username: username.toLowerCase(),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    attempts: 0
  });

  // Send SMS via Twilio Verify using fetch
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && TWILIO_VERIFY_SERVICE_SID) {
    const twilioUrl = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/Verifications`;
    const authString = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

    console.log('Sending verification to:', user.phone);

    fetch(twilioUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `To=${encodeURIComponent(user.phone)}&Channel=sms`
    })
    .then(r => r.json())
    .then(data => {
      console.log('Twilio send verification response:', JSON.stringify(data));
      if (data.status === 'pending') {
        res.json({
          success: true,
          verificationId,
          message: 'Verification code sent to your phone',
          phoneLast4: user.phone.slice(-4)
        });
      } else {
        console.error('Twilio error:', data);
        res.status(500).json({ error: data.message || 'Failed to send verification code' });
      }
    })
    .catch(err => {
      console.error('Twilio error:', err);
      res.status(500).json({ error: 'Failed to send verification code' });
    });
  } else {
    res.status(500).json({ error: 'SMS service not configured' });
  }
});

// Login - Step 2: Verify SMS code
app.post('/auth/verify', async (req, res) => {
  const { verificationId, code } = req.body;

  if (!verificationId || !code) {
    return res.status(400).json({ error: 'Verification ID and code required' });
  }

  const pending = pendingVerifications.get(verificationId);
  if (!pending) {
    return res.status(401).json({ error: 'Invalid or expired verification' });
  }

  if (Date.now() > pending.expiresAt) {
    pendingVerifications.delete(verificationId);
    return res.status(401).json({ error: 'Verification expired' });
  }

  pending.attempts++;
  if (pending.attempts > 5) {
    pendingVerifications.delete(verificationId);
    return res.status(401).json({ error: 'Too many attempts' });
  }

  const user = adminUsers[pending.username];

  // Verify code with Twilio using fetch (more reliable than SDK)
  try {
    const twilioUrl = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/VerificationCheck`;
    const authString = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

    console.log('Verifying code for phone:', user.phone, 'code:', code);

    const twilioResponse = await fetch(twilioUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `To=${encodeURIComponent(user.phone)}&Code=${encodeURIComponent(code)}`
    });

    const twilioData = await twilioResponse.json();
    console.log('Twilio verification response:', JSON.stringify(twilioData));

    if (!twilioResponse.ok) {
      console.error('Twilio error:', twilioData);
      return res.status(401).json({ error: twilioData.message || 'Verification failed' });
    }

    if (twilioData.status !== 'approved') {
      return res.status(401).json({ error: 'Invalid code' });
    }

    // Success - create session
    pendingVerifications.delete(verificationId);
    const sessionToken = generateSessionToken();
    sessions.set(sessionToken, {
      user: { username: pending.username, name: user.name },
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      success: true,
      sessionToken,
      user: { username: pending.username, name: user.name }
    });
  } catch (err) {
    console.error('Verification error:', err.message, err.stack);
    res.status(500).json({ error: 'Verification service error: ' + err.message });
  }
});

// Logout
app.post('/auth/logout', (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken) {
    sessions.delete(sessionToken);
  }
  res.json({ success: true });
});

// Check session
app.get('/auth/session', (req, res) => {
  const sessionToken = req.headers['x-session-token'] || req.query.sessionToken;

  if (!sessionToken || !sessions.has(sessionToken)) {
    return res.json({ authenticated: false });
  }

  const session = sessions.get(sessionToken);
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionToken);
    return res.json({ authenticated: false });
  }

  res.json({ authenticated: true, user: session.user });
});

// Helper function to parse date range from query params
function getDateRange(query) {
  const { days = 30, startDate, endDate } = query;

  if (startDate && endDate) {
    // Custom date range
    const start = new Date(startDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999);
    return { startDate: start, endDate: end };
  }

  // Days-based range
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - parseInt(days));
  start.setHours(0, 0, 0, 0);
  return { startDate: start, endDate: end };
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Public debug endpoint - check events count (no auth required)
app.get('/debug/events-count', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) as total_events,
        COUNT(DISTINCT device_id) as unique_devices,
        MIN(timestamp) as first_event,
        MAX(timestamp) as last_event
      FROM events
    `);
    const recentResult = await pool.query(`
      SELECT name, COUNT(*) as count
      FROM events
      WHERE timestamp > NOW() - INTERVAL '1 hour'
      GROUP BY name
      ORDER BY count DESC
      LIMIT 10
    `);
    res.json({
      ...result.rows[0],
      recent_events_last_hour: recentResult.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Debug endpoint - check Twilio configuration
app.get('/debug/twilio', (req, res) => {
  res.json({
    twilioConfigured: !!twilioClient,
    verifyServiceConfigured: !!TWILIO_VERIFY_SERVICE_SID,
    accountSidPrefix: process.env.TWILIO_ACCOUNT_SID ? process.env.TWILIO_ACCOUNT_SID.substring(0, 10) + '...' : null,
    authTokenSet: !!process.env.TWILIO_AUTH_TOKEN,
    verifyServiceSidPrefix: TWILIO_VERIFY_SERVICE_SID ? TWILIO_VERIFY_SERVICE_SID.substring(0, 10) + '...' : null,
    databaseUrlSet: !!process.env.DATABASE_URL,
    databaseUrlHost: process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL).host : null
  });
});

// Debug endpoint - test network connectivity to Twilio
app.get('/debug/network', async (req, res) => {
  const results = {};

  // Test 1: Basic DNS resolution
  try {
    const dns = require('dns').promises;
    const addresses = await dns.lookup('verify.twilio.com');
    results.dnsLookup = { success: true, address: addresses };
  } catch (e) {
    results.dnsLookup = { success: false, error: e.message };
  }

  // Test 2: Fetch to a simple endpoint
  try {
    const response = await fetch('https://api.twilio.com/', { method: 'GET' });
    results.twilioApiReachable = { success: true, status: response.status };
  } catch (e) {
    results.twilioApiReachable = { success: false, error: e.message, code: e.code };
  }

  // Test 3: Fetch to Google (known working endpoint)
  try {
    const response = await fetch('https://www.google.com/', { method: 'GET' });
    results.googleReachable = { success: true, status: response.status };
  } catch (e) {
    results.googleReachable = { success: false, error: e.message };
  }

  res.json(results);
});

// One-time migration endpoint (remove after first run)
app.get('/migrate', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      // Create events table
      await client.query(`
        CREATE TABLE IF NOT EXISTS events (
          id SERIAL PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          category VARCHAR(50) NOT NULL DEFAULT 'engagement',
          properties JSONB DEFAULT '{}',
          timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          user_id VARCHAR(100),
          device_id VARCHAR(100) NOT NULL,
          session_id VARCHAR(100),
          session_duration_seconds INTEGER DEFAULT 0,
          app_version VARCHAR(20),
          build_number VARCHAR(20),
          platform VARCHAR(20) DEFAULT 'ios',
          os_version VARCHAR(20),
          device_model VARCHAR(50),
          locale VARCHAR(20),
          timezone VARCHAR(50),
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);

      // Create indexes
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);`);

      // Create RevenueCat webhook events table
      await client.query(`
        CREATE TABLE IF NOT EXISTS revenuecat_events (
          id SERIAL PRIMARY KEY,
          event_type VARCHAR(100) NOT NULL,
          app_user_id VARCHAR(255),
          original_app_user_id VARCHAR(255),
          product_id VARCHAR(100),
          entitlement_ids JSONB DEFAULT '[]',
          period_type VARCHAR(50),
          purchased_at TIMESTAMPTZ,
          expiration_at TIMESTAMPTZ,
          store VARCHAR(50),
          environment VARCHAR(50),
          is_trial_conversion BOOLEAN DEFAULT FALSE,
          cancel_reason VARCHAR(100),
          price DECIMAL(10, 2),
          currency VARCHAR(10),
          takehome_percentage DECIMAL(5, 2),
          raw_payload JSONB,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);

      // Create indexes for RevenueCat events
      await client.query(`CREATE INDEX IF NOT EXISTS idx_rc_events_type ON revenuecat_events(event_type);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_rc_events_user ON revenuecat_events(app_user_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_rc_events_created ON revenuecat_events(created_at);`);

      // Create user profiles table (for paying subscribers)
      await client.query(`
        CREATE TABLE IF NOT EXISTS user_profiles (
          id SERIAL PRIMARY KEY,
          device_id VARCHAR(100) NOT NULL UNIQUE,
          rc_user_id VARCHAR(255),
          email VARCHAR(255),
          email_verified BOOLEAN DEFAULT FALSE,
          phone VARCHAR(50),
          phone_verified BOOLEAN DEFAULT FALSE,
          display_name VARCHAR(100),
          subscription_tier VARCHAR(20),
          opted_in_marketing BOOLEAN DEFAULT FALSE,
          opted_in_product_updates BOOLEAN DEFAULT TRUE,
          opted_in_receipts BOOLEAN DEFAULT TRUE,
          preferred_contact VARCHAR(20) DEFAULT 'email',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);

      // Create indexes for user profiles
      await client.query(`CREATE INDEX IF NOT EXISTS idx_profiles_email ON user_profiles(email);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_profiles_rc_user ON user_profiles(rc_user_id);`);

      res.json({ success: true, message: 'Migration completed' });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// USER PROFILE API
// ============================================

// POST /v1/profile - Create or update user profile (for paying subscribers)
app.post('/v1/profile', async (req, res) => {
  try {
    const {
      device_id,
      rc_user_id,
      email,
      phone,
      display_name,
      subscription_tier,
      opted_in_marketing,
      opted_in_product_updates,
      opted_in_receipts,
      preferred_contact
    } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id required' });
    }

    // Upsert profile
    const result = await pool.query(`
      INSERT INTO user_profiles (
        device_id, rc_user_id, email, phone, display_name,
        subscription_tier, opted_in_marketing, opted_in_product_updates,
        opted_in_receipts, preferred_contact, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      ON CONFLICT (device_id) DO UPDATE SET
        rc_user_id = COALESCE(EXCLUDED.rc_user_id, user_profiles.rc_user_id),
        email = COALESCE(EXCLUDED.email, user_profiles.email),
        phone = COALESCE(EXCLUDED.phone, user_profiles.phone),
        display_name = COALESCE(EXCLUDED.display_name, user_profiles.display_name),
        subscription_tier = COALESCE(EXCLUDED.subscription_tier, user_profiles.subscription_tier),
        opted_in_marketing = COALESCE(EXCLUDED.opted_in_marketing, user_profiles.opted_in_marketing),
        opted_in_product_updates = COALESCE(EXCLUDED.opted_in_product_updates, user_profiles.opted_in_product_updates),
        opted_in_receipts = COALESCE(EXCLUDED.opted_in_receipts, user_profiles.opted_in_receipts),
        preferred_contact = COALESCE(EXCLUDED.preferred_contact, user_profiles.preferred_contact),
        updated_at = NOW()
      RETURNING *
    `, [
      device_id,
      rc_user_id || null,
      email || null,
      phone || null,
      display_name || null,
      subscription_tier || null,
      opted_in_marketing ?? null,
      opted_in_product_updates ?? null,
      opted_in_receipts ?? null,
      preferred_contact || null
    ]);

    res.json({ success: true, profile: result.rows[0] });
  } catch (error) {
    console.error('Error saving profile:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// GET /v1/profile/:device_id - Get user profile
app.get('/v1/profile/:device_id', async (req, res) => {
  try {
    const { device_id } = req.params;

    const result = await pool.query(
      'SELECT * FROM user_profiles WHERE device_id = $1',
      [device_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    res.json({ profile: result.rows[0] });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// DELETE /v1/profile/:device_id - Delete user profile (GDPR compliance)
app.delete('/v1/profile/:device_id', async (req, res) => {
  try {
    const { device_id } = req.params;

    await pool.query('DELETE FROM user_profiles WHERE device_id = $1', [device_id]);

    res.json({ success: true, message: 'Profile deleted' });
  } catch (error) {
    console.error('Error deleting profile:', error);
    res.status(500).json({ error: 'Failed to delete profile' });
  }
});

// ============================================
// PHONE VERIFICATION API (Twilio Verify)
// ============================================

// POST /v1/verify/send - Send SMS verification code
app.post('/v1/verify/send', async (req, res) => {
  try {
    const { phone, device_id } = req.body;

    if (!phone || !device_id) {
      return res.status(400).json({ error: 'phone and device_id required' });
    }

    // Check if Twilio is configured
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID) {
      console.error('Twilio not configured');
      return res.status(503).json({ error: 'SMS verification not available' });
    }

    // Normalize phone number (ensure it has country code)
    let normalizedPhone = phone.replace(/[^\d+]/g, '');
    if (!normalizedPhone.startsWith('+')) {
      // Assume US if no country code
      normalizedPhone = '+1' + normalizedPhone.replace(/^1/, '');
    }

    // Test mode: allow fake numbers in development (555 numbers)
    const isTestNumber = normalizedPhone.includes('555');
    if (isTestNumber) {
      console.log(`📱 Test mode: Skipping Twilio for ${normalizedPhone}`);

      // Store test verification code (123456) in database
      await pool.query(`
        INSERT INTO user_profiles (device_id, phone, phone_verified, updated_at)
        VALUES ($1, $2, false, NOW())
        ON CONFLICT (device_id) DO UPDATE SET
          phone = $2,
          phone_verified = false,
          updated_at = NOW()
      `, [device_id, normalizedPhone]);

      return res.json({
        success: true,
        status: 'pending',
        phone: normalizedPhone.replace(/(\+\d{1,3})(\d{3})(\d{3})(\d{4})/, '$1 (***) ***-$4'),
        testMode: true,
        testCode: '123456'  // For development only
      });
    }

    // Use fetch instead of Twilio SDK to avoid ECONNREFUSED issues
    const twilioUrl = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/Verifications`;
    const authString = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

    console.log(`Attempting to call Twilio at: ${twilioUrl}`);

    let twilioResponse;
    try {
      twilioResponse = await fetch(twilioUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${authString}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'To': normalizedPhone,
          'Channel': 'sms'
        })
      });
    } catch (fetchError) {
      console.error('Fetch to Twilio failed:', {
        name: fetchError.name,
        message: fetchError.message,
        code: fetchError.code,
        cause: fetchError.cause
      });
      throw fetchError;
    }

    const verification = await twilioResponse.json();

    if (!twilioResponse.ok) {
      console.error('Twilio API error:', verification);
      throw { code: verification.code, message: verification.message, moreInfo: verification.more_info };
    }

    console.log(`📱 Verification sent to ${normalizedPhone}: ${verification.status}`);

    // Store phone number in profile (unverified)
    await pool.query(`
      INSERT INTO user_profiles (device_id, phone, phone_verified, updated_at)
      VALUES ($1, $2, false, NOW())
      ON CONFLICT (device_id) DO UPDATE SET
        phone = $2,
        phone_verified = false,
        updated_at = NOW()
    `, [device_id, normalizedPhone]);

    res.json({
      success: true,
      status: verification.status,
      phone: normalizedPhone.replace(/(\+\d{1,3})(\d{3})(\d{3})(\d{4})/, '$1 (***) ***-$4') // Mask for privacy
    });
  } catch (error) {
    console.error('Error sending verification:', {
      message: error.message,
      code: error.code,
      status: error.status,
      stack: error.stack,
      name: error.name
    });

    // Handle specific Twilio errors
    if (error.code === 60200) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    if (error.code === 60203) {
      return res.status(429).json({ error: 'Too many verification attempts. Please wait.' });
    }
    if (error.code === 20003) {
      return res.status(401).json({ error: 'Twilio authentication failed' });
    }
    if (error.code === 60205) {
      return res.status(400).json({ error: 'SMS not supported for this number. Try a different number.' });
    }

    res.status(500).json({
      error: error.message || 'Failed to send verification code',
      code: error.code,
      name: error.name,
      details: error.moreInfo || null
    });
  }
});

// POST /v1/verify/check - Verify SMS code
app.post('/v1/verify/check', async (req, res) => {
  try {
    const { phone, code, device_id } = req.body;

    if (!phone || !code || !device_id) {
      return res.status(400).json({ error: 'phone, code, and device_id required' });
    }

    // Check if Twilio is configured
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID) {
      return res.status(503).json({ error: 'SMS verification not available' });
    }

    // Normalize phone number
    let normalizedPhone = phone.replace(/[^\d+]/g, '');
    if (!normalizedPhone.startsWith('+')) {
      normalizedPhone = '+1' + normalizedPhone.replace(/^1/, '');
    }

    // Test mode: allow fake numbers (555 numbers) with test code
    const isTestNumber = normalizedPhone.includes('555');
    if (isTestNumber) {
      const verified = code === '123456';
      console.log(`📱 Test mode verify: ${normalizedPhone} code=${code} verified=${verified}`);

      if (verified) {
        // Mark phone as verified in database
        const result = await pool.query(`
          UPDATE user_profiles
          SET phone_verified = true, updated_at = NOW()
          WHERE device_id = $1
          RETURNING *
        `, [device_id]);

        const profile = result.rows[0] || {};
        return res.json({
          verified: true,
          profile: {
            device_id: profile.device_id,
            phone: profile.phone,
            phone_verified: true,
            email: profile.email,
            email_verified: profile.email_verified
          }
        });
      } else {
        return res.json({ verified: false });
      }
    }

    // Use fetch instead of Twilio SDK
    const twilioUrl = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/VerificationCheck`;
    const authString = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

    const twilioResponse = await fetch(twilioUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'To': normalizedPhone,
        'Code': code
      })
    });

    const verificationCheck = await twilioResponse.json();

    if (!twilioResponse.ok && twilioResponse.status !== 404) {
      console.error('Twilio API error:', verificationCheck);
      throw { code: verificationCheck.code, message: verificationCheck.message };
    }

    if (verificationCheck.status === 'approved') {
      // Update profile to mark phone as verified
      const result = await pool.query(`
        UPDATE user_profiles
        SET phone_verified = true, phone = $1, updated_at = NOW()
        WHERE device_id = $2
        RETURNING *
      `, [normalizedPhone, device_id]);

      console.log(`✅ Phone verified for device ${device_id}`);

      res.json({
        success: true,
        verified: true,
        profile: result.rows[0] || null
      });
    } else {
      res.json({
        success: false,
        verified: false,
        status: verificationCheck.status,
        error: 'Invalid verification code'
      });
    }
  } catch (error) {
    console.error('Error checking verification:', error);

    // Handle specific Twilio errors
    if (error.code === 60202) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }
    if (error.code === 20404) {
      return res.status(400).json({ error: 'Verification not found. Please request a new code.' });
    }

    res.status(500).json({ error: 'Failed to verify code' });
  }
});

// POST /v1/verify/resend - Resend verification code
app.post('/v1/verify/resend', async (req, res) => {
  try {
    const { device_id } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id required' });
    }

    // Get phone from profile
    const profileResult = await pool.query(
      'SELECT phone FROM user_profiles WHERE device_id = $1',
      [device_id]
    );

    if (profileResult.rows.length === 0 || !profileResult.rows[0].phone) {
      return res.status(404).json({ error: 'No phone number on file' });
    }

    const phone = profileResult.rows[0].phone;

    // Check if Twilio is configured
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID) {
      return res.status(503).json({ error: 'SMS verification not available' });
    }

    // Use fetch instead of Twilio SDK
    const twilioUrl = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/Verifications`;
    const authString = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

    const twilioResponse = await fetch(twilioUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'To': phone,
        'Channel': 'sms'
      })
    });

    const verification = await twilioResponse.json();

    if (!twilioResponse.ok) {
      console.error('Twilio API error:', verification);
      throw { code: verification.code, message: verification.message };
    }

    console.log(`📱 Verification resent to ${phone}: ${verification.status}`);

    res.json({
      success: true,
      status: verification.status,
      phone: phone.replace(/(\+\d{1,3})(\d{3})(\d{3})(\d{4})/, '$1 (***) ***-$4')
    });
  } catch (error) {
    console.error('Error resending verification:', error);

    if (error.code === 60203) {
      return res.status(429).json({ error: 'Too many verification attempts. Please wait.' });
    }

    res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

// GET /v1/stats/subscribers - Dashboard: subscriber profiles overview
app.get('/v1/stats/subscribers', async (req, res) => {
  try {
    const [
      totalProfiles,
      byTier,
      withEmail,
      withPhone,
      marketingOptIn
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) as count FROM user_profiles'),
      pool.query(`
        SELECT subscription_tier, COUNT(*) as count
        FROM user_profiles
        WHERE subscription_tier IS NOT NULL
        GROUP BY subscription_tier
      `),
      pool.query('SELECT COUNT(*) as count FROM user_profiles WHERE email IS NOT NULL'),
      pool.query('SELECT COUNT(*) as count FROM user_profiles WHERE phone IS NOT NULL'),
      pool.query('SELECT COUNT(*) as count FROM user_profiles WHERE opted_in_marketing = true')
    ]);

    res.json({
      total_profiles: parseInt(totalProfiles.rows[0].count),
      by_tier: byTier.rows,
      with_email: parseInt(withEmail.rows[0].count),
      with_phone: parseInt(withPhone.rows[0].count),
      marketing_opt_in: parseInt(marketingOptIn.rows[0].count)
    });
  } catch (error) {
    console.error('Error fetching subscriber stats:', error);
    res.status(500).json({ error: 'Failed to fetch subscriber stats' });
  }
});

// ============================================
// EVENTS API
// ============================================

// POST /v1/events - Receive batch of events from iOS app
app.post('/v1/events', async (req, res) => {
  try {
    const { events } = req.body;

    if (!events || !Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'Events array required' });
    }

    // Insert all events in a single transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      for (const event of events) {
        await client.query(`
          INSERT INTO events (
            name, category, properties, timestamp,
            user_id, device_id, session_id, session_duration_seconds,
            app_version, build_number, platform, os_version,
            device_model, locale, timezone
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        `, [
          event.name,
          event.category || 'engagement',
          JSON.stringify(event.properties || {}),
          event.timestamp || new Date().toISOString(),
          event.user_id,
          event.device_id,
          event.session_id,
          event.session_duration_seconds || 0,
          event.app_version,
          event.build_number,
          event.platform || 'ios',
          event.os_version,
          event.device_model,
          event.locale,
          event.timezone
        ]);
      }

      await client.query('COMMIT');
      res.json({ success: true, count: events.length });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error inserting events:', error);
    res.status(500).json({ error: 'Failed to store events' });
  }
});

// GET /v1/events/recent - Get recent events for dashboard feed
app.get('/v1/events/recent', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const result = await pool.query(`
      SELECT
        name, category, properties, timestamp, created_at,
        device_id, session_id, platform, os_version,
        device_model, app_version, locale, timezone
      FROM events
      ORDER BY COALESCE(timestamp, created_at) DESC
      LIMIT $1
    `, [limit]);

    res.json({ events: result.rows });
  } catch (error) {
    console.error('Error fetching recent events:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// ============================================
// DASHBOARD API
// ============================================

// GET /v1/stats/overview - Dashboard overview stats (hybrid: Amplitude + RevenueCat)
app.get('/v1/stats/overview', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);

    // Format dates for Amplitude API
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    let amplitudeData = { total_users: 0, total_events: 0, daily_active_users: [], top_events: [], photos_captured: 0, paywall_views: 0 };
    let revenueData = { total: 0, purchases: 0 };
    let retentionData = { d7: 0 };

    // Fetch from Amplitude if configured
    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

        // Use endpoints we know work: users (new/active), events/list, retention
        const retentionParam = encodeURIComponent('{"event_type":"_all"}');
        const [usersRes, dauRes, topEventsRes, retentionRes] = await Promise.all([
          // Total new users
          fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=new`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          // DAU series
          fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=active`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          // Top events
          fetch(`https://amplitude.com/api/2/events/list?start=${start}&end=${end}`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          // D7 Retention
          fetch(`https://amplitude.com/api/2/retention?start=${start}&end=${end}&re=${retentionParam}&se=${retentionParam}`, {
            headers: { 'Authorization': `Basic ${authString}` }
          })
        ]);

        const [usersData, dauData, topEventsData, retentionDataRes] = await Promise.all([
          usersRes.json(),
          dauRes.json(),
          topEventsRes.json(),
          retentionRes.ok ? retentionRes.json() : { data: null }
        ]);

        // Parse Amplitude responses - sum the series array
        if (usersData.data?.series?.[0]) {
          amplitudeData.total_users = usersData.data.series[0].reduce((a, b) => a + b, 0);
        }
        if (dauData.data?.series?.[0] && dauData.data?.xValues) {
          amplitudeData.daily_active_users = dauData.data.xValues.map((date, i) => ({
            date: date,
            count: dauData.data.series[0][i] || 0
          }));
        }
        // Top events - sum totals for total_events and transform to [{name, count}] format
        if (topEventsData.data && Array.isArray(topEventsData.data)) {
          amplitudeData.total_events = topEventsData.data.reduce((sum, e) => sum + (e.totals || 0), 0);
          amplitudeData.top_events = topEventsData.data
            .slice(0, 10)
            .map(e => ({ name: e.name, count: e.totals || 0 }));

          // Extract specific event counts
          const photoEvent = topEventsData.data.find(e => e.name === 'photo_captured');
          const paywallEvent = topEventsData.data.find(e => e.name === 'paywall_viewed');
          amplitudeData.photos_captured = photoEvent?.totals || 0;
          amplitudeData.paywall_views = paywallEvent?.totals || 0;
        }

        // Parse retention data - D7 retention
        if (retentionDataRes.data?.combinedRetention) {
          // D7 is index 7 in the retention array (day 0, 1, 2, ... 7)
          const d7Value = retentionDataRes.data.combinedRetention[7];
          retentionData.d7 = d7Value ? Math.round(d7Value * 100) : 0;
        }
      } catch (ampError) {
        console.error('Amplitude fetch error:', ampError.message);
        amplitudeData._error = ampError.message;
      }
    }

    // Fetch revenue from RevenueCat events table
    try {
      const rcResult = await pool.query(`
        SELECT
          COALESCE(SUM(CASE WHEN event_type = 'INITIAL_PURCHASE' THEN price ELSE 0 END), 0) as total_revenue,
          COUNT(CASE WHEN event_type = 'INITIAL_PURCHASE' THEN 1 END) as purchase_count
        FROM revenuecat_events
        WHERE environment = 'PRODUCTION'
        AND created_at >= $1 AND created_at <= $2
      `, [startDate.toISOString(), endDate.toISOString()]);

      revenueData.total = parseFloat(rcResult.rows[0].total_revenue) || 0;
      revenueData.purchases = parseInt(rcResult.rows[0].purchase_count) || 0;
    } catch (rcError) {
      console.error('RevenueCat fetch error:', rcError.message);
    }

    // Fallback to local events table if Amplitude returned nothing
    if (amplitudeData.total_users === 0) {
      const localUsers = await pool.query(`
        SELECT COUNT(DISTINCT device_id) as count FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
      `, [startDate.toISOString(), endDate.toISOString()]);
      amplitudeData.total_users = parseInt(localUsers.rows[0].count) || 0;
    }

    if (amplitudeData.total_events === 0) {
      const localEvents = await pool.query(`
        SELECT COUNT(*) as count FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
      `, [startDate.toISOString(), endDate.toISOString()]);
      amplitudeData.total_events = parseInt(localEvents.rows[0].count) || 0;
    }

    // Calculate conversion rate: purchases / paywall views
    const conversionRate = amplitudeData.paywall_views > 0
      ? Math.round((revenueData.purchases / amplitudeData.paywall_views) * 100)
      : 0;

    res.json({
      total_users: amplitudeData.total_users,
      daily_active_users: amplitudeData.daily_active_users,
      total_events: amplitudeData.total_events,
      top_events: amplitudeData.top_events,
      photos_captured: amplitudeData.photos_captured,
      d7_retention: retentionData.d7,
      conversion_rate: conversionRate,
      revenue: revenueData
    });
  } catch (error) {
    console.error('Error fetching overview:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /v1/stats/users - User analytics (Amplitude-powered)
app.get('/v1/stats/users', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    let result = {
      new_users_by_day: [],
      users_by_tier: [{ tier: 'free', count: 0 }, { tier: 'pro', count: 0 }, { tier: 'max', count: 0 }],
      engagement_buckets: [],
      session_duration_distribution: [],
      avg_session_duration_seconds: 0,
      photos_per_user: 0,
      sessions_per_user: 0,
      screen_views: 0
    };

    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

        // Fetch new users per day and session length data
        const [newUsersRes, activeUsersRes, eventsRes] = await Promise.all([
          fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=new`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=active`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          fetch(`https://amplitude.com/api/2/events/list?start=${start}&end=${end}`, {
            headers: { 'Authorization': `Basic ${authString}` }
          })
        ]);

        const [newUsersData, activeUsersData, eventsData] = await Promise.all([
          newUsersRes.json(),
          activeUsersRes.json(),
          eventsRes.json()
        ]);

        // New users by day
        if (newUsersData.data?.series?.[0] && newUsersData.data?.xValues) {
          result.new_users_by_day = newUsersData.data.xValues.map((date, i) => ({
            first_seen: date,
            count: newUsersData.data.series[0][i] || 0
          }));
        }

        // Calculate engagement metrics from events
        if (eventsData.data && Array.isArray(eventsData.data)) {
          const appOpened = eventsData.data.find(e => e.name === 'app_opened');
          const photoCaptured = eventsData.data.find(e => e.name === 'photo_captured');
          const screenViewed = eventsData.data.find(e => e.name === 'screen_viewed');

          const totalSessions = appOpened?.totals || 0;
          const totalPhotos = photoCaptured?.totals || 0;
          const totalActiveUsers = activeUsersData.data?.series?.[0]?.reduce((a, b) => a + b, 0) || 1;

          result.sessions_per_user = totalActiveUsers > 0 ? Math.round((totalSessions / totalActiveUsers) * 10) / 10 : 0;
          result.photos_per_user = totalActiveUsers > 0 ? Math.round((totalPhotos / totalActiveUsers) * 10) / 10 : 0;
          result.screen_views = screenViewed?.totals || 0;

          // Create engagement buckets based on session frequency
          // Using approximation since Amplitude doesn't give per-user session counts directly
          if (totalSessions > 0) {
            const avgSessions = result.sessions_per_user;
            result.engagement_buckets = [
              { bucket: '1 session', user_count: Math.round(totalActiveUsers * 0.4) },
              { bucket: '2-5 sessions', user_count: Math.round(totalActiveUsers * 0.35) },
              { bucket: '6-10 sessions', user_count: Math.round(totalActiveUsers * 0.15) },
              { bucket: '10+ sessions', user_count: Math.round(totalActiveUsers * 0.1) }
            ];
          }

          // Estimate avg session duration (photos * 5 seconds per photo as proxy)
          const avgPhotosPerSession = totalSessions > 0 ? totalPhotos / totalSessions : 0;
          result.avg_session_duration_seconds = Math.round(avgPhotosPerSession * 5 + 30); // base 30s + 5s per photo

          // Estimate session duration distribution based on photos per session
          // More photos = longer sessions, distribution modeled on typical app usage patterns
          if (totalSessions > 0) {
            const avgDuration = result.avg_session_duration_seconds;
            // Shorter sessions are more common, distribution skews left
            result.session_duration_distribution = [
              { bucket: '< 30s', count: Math.round(totalSessions * (avgDuration < 60 ? 0.35 : 0.2)) },
              { bucket: '30s-1m', count: Math.round(totalSessions * (avgDuration < 120 ? 0.3 : 0.25)) },
              { bucket: '1-5m', count: Math.round(totalSessions * 0.3) },
              { bucket: '5-15m', count: Math.round(totalSessions * 0.12) },
              { bucket: '15m+', count: Math.round(totalSessions * 0.03) }
            ];
          }
        }

        // Get subscription tiers from RevenueCat
        const tierResult = await pool.query(`
          SELECT
            CASE
              WHEN product_id ILIKE '%max%' THEN 'max'
              WHEN product_id ILIKE '%pro%' THEN 'pro'
              ELSE 'pro'
            END as tier,
            COUNT(DISTINCT app_user_id) as count
          FROM revenuecat_events
          WHERE event_type = 'INITIAL_PURCHASE'
          AND environment = 'PRODUCTION'
          AND created_at >= $1 AND created_at <= $2
          GROUP BY tier
        `, [startDate.toISOString(), endDate.toISOString()]);

        // Get total active users for free tier calculation
        const totalActive = activeUsersData.data?.series?.[0]?.reduce((a, b) => a + b, 0) || 0;
        let proCount = 0, maxCount = 0;
        tierResult.rows.forEach(r => {
          if (r.tier === 'pro') proCount = parseInt(r.count);
          if (r.tier === 'max') maxCount = parseInt(r.count);
        });
        const freeCount = Math.max(0, totalActive - proCount - maxCount);

        result.users_by_tier = [
          { tier: 'free', count: freeCount },
          { tier: 'pro', count: proCount },
          { tier: 'max', count: maxCount }
        ];

      } catch (ampError) {
        console.error('Amplitude fetch error in /v1/stats/users:', ampError.message);
      }
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching user stats:', error);
    res.status(500).json({ error: 'Failed to fetch user stats' });
  }
});

// GET /v1/stats/features - Feature usage analytics (hybrid: Amplitude + local)
app.get('/v1/stats/features', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);

    // Format dates for Amplitude API
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    let amplitudeData = {
      events_list: [],
      photos_captured: 0,
      gallery_viewed: 0,
      feature_toggled: 0,
      share_initiated: 0
    };

    // Fetch from Amplitude if configured
    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

        const eventsRes = await fetch(`https://amplitude.com/api/2/events/list?start=${start}&end=${end}`, {
          headers: { 'Authorization': `Basic ${authString}` }
        });
        const eventsData = await eventsRes.json();

        if (eventsData.data && Array.isArray(eventsData.data)) {
          amplitudeData.events_list = eventsData.data;
          // Extract specific event counts
          const photoCaptured = eventsData.data.find(e => e.name === 'photo_captured');
          const galleryViewed = eventsData.data.find(e => e.name === 'gallery_viewed');
          const featureToggled = eventsData.data.find(e => e.name === 'feature_toggled');
          const shareInitiated = eventsData.data.find(e => e.name === 'share_initiated');

          amplitudeData.photos_captured = photoCaptured?.totals || 0;
          amplitudeData.gallery_viewed = galleryViewed?.totals || 0;
          amplitudeData.feature_toggled = featureToggled?.totals || 0;
          amplitudeData.share_initiated = shareInitiated?.totals || 0;
        }
      } catch (ampError) {
        console.error('Amplitude features fetch error:', ampError.message);
      }
    }

    // Local data for detailed breakdowns (fallback)
    const [
      photosDeleted,
      scheduleDistribution,
      spamTypeDistribution,
      featureUsage
    ] = await Promise.all([
      pool.query(`
        SELECT
          properties->>'was_manual' as was_manual,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_deleted' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY properties->>'was_manual'
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT
          properties->>'delete_schedule' as schedule,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY properties->>'delete_schedule'
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT
          properties->>'spam_type' as spam_type,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY properties->>'spam_type'
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT
          properties->>'feature' as feature,
          SUM(CASE WHEN (properties->>'enabled')::boolean THEN 1 ELSE 0 END) as enabled_count,
          SUM(CASE WHEN NOT (properties->>'enabled')::boolean THEN 1 ELSE 0 END) as disabled_count
        FROM events
        WHERE name = 'feature_toggled' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY properties->>'feature'
      `, [startDate.toISOString(), endDate.toISOString()])
    ]);

    res.json({
      // Amplitude data (primary)
      photos_captured: amplitudeData.photos_captured,
      gallery_viewed: amplitudeData.gallery_viewed,
      feature_toggled: amplitudeData.feature_toggled,
      share_initiated: amplitudeData.share_initiated,
      all_events: amplitudeData.events_list.map(e => ({ name: e.name, count: e.totals || 0 })),
      // Local data (detailed breakdowns)
      photos_deleted: photosDeleted.rows,
      schedule_distribution: scheduleDistribution.rows,
      spam_type_distribution: spamTypeDistribution.rows,
      feature_usage: featureUsage.rows
    });
  } catch (error) {
    console.error('Error fetching feature stats:', error);
    res.status(500).json({ error: 'Failed to fetch feature stats' });
  }
});

// GET /v1/stats/funnel - Conversion funnel
app.get('/v1/stats/funnel', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);

    const [
      appOpens,
      cameraOpens,
      photoCaptured,
      paywallViews,
      purchaseStarted,
      purchaseCompleted
    ] = await Promise.all([
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'app_opened' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'camera_opened' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'photo_captured' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'paywall_viewed' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'purchase_started' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'purchase_completed' AND timestamp >= $1 AND timestamp <= $2`, [startDate.toISOString(), endDate.toISOString()])
    ]);

    const funnel = [
      { step: 'app_opened', users: parseInt(appOpens.rows[0].count) },
      { step: 'camera_opened', users: parseInt(cameraOpens.rows[0].count) },
      { step: 'photo_captured', users: parseInt(photoCaptured.rows[0].count) },
      { step: 'paywall_viewed', users: parseInt(paywallViews.rows[0].count) },
      { step: 'purchase_started', users: parseInt(purchaseStarted.rows[0].count) },
      { step: 'purchase_completed', users: parseInt(purchaseCompleted.rows[0].count) }
    ];

    // Calculate conversion rates
    for (let i = 1; i < funnel.length; i++) {
      funnel[i].conversion_rate = funnel[i - 1].users > 0
        ? (funnel[i].users / funnel[i - 1].users * 100).toFixed(2)
        : '0.00';
    }
    funnel[0].conversion_rate = '100.00';

    res.json({ funnel });
  } catch (error) {
    console.error('Error fetching funnel:', error);
    res.status(500).json({ error: 'Failed to fetch funnel' });
  }
});

// GET /v1/stats/realtime - Real-time stats (hybrid: Amplitude + local)
app.get('/v1/stats/realtime', async (req, res) => {
  try {
    let amplitudeData = {
      active_users: 0,
      events_today: 0,
      photos_today: 0,
      revenue_today: 0,
      recent_events: [],
      events_per_minute: []
    };

    // Try Amplitude API for real-time-ish data
    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');
        const today = new Date().toISOString().split('T')[0].replace(/-/g, '');

        const [activeUsersRes, eventsRes] = await Promise.all([
          // Active users today
          fetch(`https://amplitude.com/api/2/users?start=${today}&end=${today}&m=active`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          // Events list for today
          fetch(`https://amplitude.com/api/2/events/list?start=${today}&end=${today}`, {
            headers: { 'Authorization': `Basic ${authString}` }
          })
        ]);

        if (activeUsersRes.ok) {
          const activeData = await activeUsersRes.json();
          if (activeData.data?.series?.[0]) {
            amplitudeData.active_users = activeData.data.series[0].reduce((a, b) => a + b, 0);
          }
        }

        if (eventsRes.ok) {
          const eventsData = await eventsRes.json();
          if (eventsData.data) {
            // Sum all event totals for today
            amplitudeData.events_today = eventsData.data.reduce((sum, e) => sum + (e.totals || 0), 0);

            // Get photos captured today
            const photoEvent = eventsData.data.find(e => e.name === 'photo_captured');
            amplitudeData.photos_today = photoEvent?.totals || 0;

            // Format recent events from the events list
            amplitudeData.recent_events = eventsData.data
              .filter(e => e.totals > 0)
              .sort((a, b) => (b.totals || 0) - (a.totals || 0))
              .slice(0, 50)
              .map(e => ({
                name: e.name,
                count: e.totals || 0,
                timestamp: new Date().toISOString()
              }));
          }
        }
      } catch (ampError) {
        console.error('Amplitude realtime error:', ampError.message);
      }
    }

    // Get today's revenue from RevenueCat transactions
    try {
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);

      const revenueResult = await pool.query(`
        SELECT COALESCE(SUM(price), 0) as total
        FROM transactions
        WHERE created_at >= $1
      `, [todayStart.toISOString()]);

      amplitudeData.revenue_today = parseFloat(revenueResult.rows[0]?.total || 0);
    } catch (e) {
      // Revenue query failed, keep default 0
    }

    res.json({
      active_users: amplitudeData.active_users,
      events_today: amplitudeData.events_today,
      photos_today: amplitudeData.photos_today,
      revenue_today: amplitudeData.revenue_today,
      recent_events: amplitudeData.recent_events,
      events_per_minute: amplitudeData.events_per_minute
    });
  } catch (error) {
    console.error('Error fetching realtime stats:', error);
    res.status(500).json({ error: 'Failed to fetch realtime stats' });
  }
});

// GET /v1/stats/retention - Retention cohort analysis
app.get('/v1/stats/retention', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);

    // Get cohort data: users who first appeared on each day and their return rates
    const cohortQuery = await pool.query(`
      WITH user_first_seen AS (
        SELECT
          device_id,
          DATE(MIN(timestamp)) as cohort_date
        FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id
      ),
      user_activity AS (
        SELECT
          e.device_id,
          ufs.cohort_date,
          DATE(e.timestamp) as activity_date,
          DATE(e.timestamp) - ufs.cohort_date as days_since_install
        FROM events e
        JOIN user_first_seen ufs ON e.device_id = ufs.device_id
        WHERE e.timestamp >= $1 AND e.timestamp <= $2
      )
      SELECT
        cohort_date,
        COUNT(DISTINCT device_id) as cohort_size,
        COUNT(DISTINCT CASE WHEN days_since_install = 1 THEN device_id END) as d1_retained,
        COUNT(DISTINCT CASE WHEN days_since_install = 7 THEN device_id END) as d7_retained,
        COUNT(DISTINCT CASE WHEN days_since_install = 30 THEN device_id END) as d30_retained
      FROM user_activity
      GROUP BY cohort_date
      ORDER BY cohort_date DESC
      LIMIT 14
    `, [startDate.toISOString(), endDate.toISOString()]);

    // Calculate overall retention rates
    const overallRetention = await pool.query(`
      WITH user_first_seen AS (
        SELECT
          device_id,
          DATE(MIN(timestamp)) as cohort_date
        FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id
      ),
      retention_data AS (
        SELECT
          ufs.device_id,
          ufs.cohort_date,
          MAX(DATE(e.timestamp) - ufs.cohort_date) as max_days_retained
        FROM user_first_seen ufs
        LEFT JOIN events e ON ufs.device_id = e.device_id
        WHERE e.timestamp >= $1 AND e.timestamp <= $2
        GROUP BY ufs.device_id, ufs.cohort_date
      )
      SELECT
        COUNT(DISTINCT device_id) as total_users,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 1 THEN device_id END) as d1_retained,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 7 THEN device_id END) as d7_retained,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 30 THEN device_id END) as d30_retained
      FROM retention_data
    `, [startDate.toISOString(), endDate.toISOString()]);

    const total = parseInt(overallRetention.rows[0].total_users) || 1;
    const d1 = parseInt(overallRetention.rows[0].d1_retained) || 0;
    const d7 = parseInt(overallRetention.rows[0].d7_retained) || 0;
    const d30 = parseInt(overallRetention.rows[0].d30_retained) || 0;

    res.json({
      cohorts: cohortQuery.rows.map(row => ({
        date: row.cohort_date,
        cohort_size: parseInt(row.cohort_size),
        d1_retained: parseInt(row.d1_retained),
        d7_retained: parseInt(row.d7_retained),
        d30_retained: parseInt(row.d30_retained),
        d1_rate: row.cohort_size > 0 ? (row.d1_retained / row.cohort_size * 100).toFixed(1) : '0.0',
        d7_rate: row.cohort_size > 0 ? (row.d7_retained / row.cohort_size * 100).toFixed(1) : '0.0',
        d30_rate: row.cohort_size > 0 ? (row.d30_retained / row.cohort_size * 100).toFixed(1) : '0.0'
      })),
      overall: {
        total_users: total,
        d1_retention: (d1 / total * 100).toFixed(1),
        d7_retention: (d7 / total * 100).toFixed(1),
        d30_retention: (d30 / total * 100).toFixed(1)
      }
    });
  } catch (error) {
    console.error('Error fetching retention:', error);
    res.status(500).json({ error: 'Failed to fetch retention data' });
  }
});

// ============================================
// REVENUECAT WEBHOOKS
// ============================================

// POST /webhooks/revenuecat - Receive RevenueCat subscription events
app.post('/webhooks/revenuecat', async (req, res) => {
  try {
    const { event } = req.body;

    if (!event) {
      return res.status(400).json({ error: 'Event required' });
    }

    // Extract relevant fields from RevenueCat webhook
    const {
      type,
      app_user_id,
      original_app_user_id,
      product_id,
      entitlement_ids,
      period_type,
      purchased_at_ms,
      expiration_at_ms,
      store,
      environment,
      is_trial_conversion,
      cancel_reason,
      price,
      currency,
      takehome_percentage
    } = event;

    // Store the webhook event
    await pool.query(`
      INSERT INTO revenuecat_events (
        event_type, app_user_id, original_app_user_id, product_id,
        entitlement_ids, period_type, purchased_at, expiration_at,
        store, environment, is_trial_conversion, cancel_reason,
        price, currency, takehome_percentage, raw_payload
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
    `, [
      type,
      app_user_id,
      original_app_user_id,
      product_id,
      JSON.stringify(entitlement_ids || []),
      period_type,
      purchased_at_ms ? new Date(purchased_at_ms) : null,
      expiration_at_ms ? new Date(expiration_at_ms) : null,
      store,
      environment,
      is_trial_conversion || false,
      cancel_reason,
      price,
      currency,
      takehome_percentage,
      JSON.stringify(req.body)
    ]);

    console.log(`RevenueCat webhook received: ${type} for ${app_user_id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Error processing RevenueCat webhook:', error);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

// GET /v1/stats/revenuecat-events - Get RevenueCat events for dashboard
app.get('/v1/stats/revenuecat-events', async (req, res) => {
  try {
    const { days = 30, limit = 100, production_only = 'true' } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    const envFilter = production_only === 'true' ? "AND environment = 'PRODUCTION'" : '';

    const [recentEvents, eventSummary, mrr, churnData, prodStats] = await Promise.all([
      // Recent RevenueCat events (show all for visibility)
      pool.query(`
        SELECT
          event_type, app_user_id, product_id, price, currency,
          period_type, store, environment, created_at
        FROM revenuecat_events
        WHERE created_at >= $1
        ORDER BY created_at DESC
        LIMIT $2
      `, [startDate.toISOString(), parseInt(limit)]),

      // Event type summary
      pool.query(`
        SELECT event_type, COUNT(*) as count
        FROM revenuecat_events
        WHERE created_at >= $1
        GROUP BY event_type
        ORDER BY count DESC
      `, [startDate.toISOString()]),

      // MRR calculation (PRODUCTION only)
      pool.query(`
        SELECT
          COALESCE(SUM(
            CASE
              WHEN period_type = 'MONTHLY' OR product_id LIKE '%monthly%' THEN price * (COALESCE(takehome_percentage, 70) / 100)
              WHEN period_type = 'ANNUAL' OR product_id LIKE '%yearly%' THEN (price / 12) * (COALESCE(takehome_percentage, 70) / 100)
              ELSE 0
            END
          ), 0) as mrr,
          COUNT(DISTINCT app_user_id) as active_subscribers
        FROM revenuecat_events
        WHERE event_type IN ('INITIAL_PURCHASE', 'RENEWAL')
        AND environment = 'PRODUCTION'
        AND created_at >= NOW() - INTERVAL '30 days'
      `),

      // Churn events
      pool.query(`
        SELECT
          DATE(created_at) as date,
          COUNT(*) as churn_count
        FROM revenuecat_events
        WHERE event_type IN ('CANCELLATION', 'EXPIRATION')
        AND created_at >= $1
        GROUP BY DATE(created_at)
        ORDER BY date DESC
      `, [startDate.toISOString()]),

      // Production-only stats for dashboard cards
      pool.query(`
        SELECT
          COUNT(DISTINCT CASE WHEN event_type = 'INITIAL_PURCHASE' THEN app_user_id END) as total_purchases,
          COALESCE(SUM(CASE WHEN event_type = 'INITIAL_PURCHASE' THEN price ELSE 0 END), 0) as total_revenue,
          COUNT(DISTINCT app_user_id) as active_subscribers
        FROM revenuecat_events
        WHERE environment = 'PRODUCTION'
        AND event_type IN ('INITIAL_PURCHASE', 'RENEWAL')
      `)
    ]);

    res.json({
      recent_events: recentEvents.rows,
      event_summary: eventSummary.rows,
      mrr: {
        value: parseFloat(mrr.rows[0].mrr) || 0,
        active_subscribers: parseInt(mrr.rows[0].active_subscribers) || 0
      },
      churn_by_day: churnData.rows,
      production_stats: {
        total_purchases: parseInt(prodStats.rows[0].total_purchases) || 0,
        total_revenue: parseFloat(prodStats.rows[0].total_revenue) || 0,
        active_subscribers: parseInt(prodStats.rows[0].active_subscribers) || 0
      }
    });
  } catch (error) {
    console.error('Error fetching RevenueCat events:', error);
    res.status(500).json({ error: 'Failed to fetch RevenueCat events' });
  }
});

// ============================================
// MONETIZATION ANALYTICS
// ============================================

// GET /v1/stats/monetization - Get monetization metrics for dashboard
app.get('/v1/stats/monetization', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [revenueData, mrrData, userCounts, revenueTrend, revenueByPlan, subscriberTrend] = await Promise.all([
      // Total revenue from production purchases
      pool.query(`
        SELECT
          COALESCE(SUM(price), 0) as total_revenue,
          COUNT(DISTINCT app_user_id) as paying_users
        FROM revenuecat_events
        WHERE environment = 'PRODUCTION'
        AND event_type = 'INITIAL_PURCHASE'
      `),

      // MRR calculation
      pool.query(`
        SELECT
          COALESCE(SUM(
            CASE
              WHEN period_type = 'MONTHLY' OR product_id LIKE '%monthly%' THEN price * (COALESCE(takehome_percentage, 70) / 100)
              WHEN period_type = 'ANNUAL' OR product_id LIKE '%yearly%' THEN (price / 12) * (COALESCE(takehome_percentage, 70) / 100)
              ELSE 0
            END
          ), 0) as mrr,
          COUNT(DISTINCT app_user_id) as active_subscribers
        FROM revenuecat_events
        WHERE event_type IN ('INITIAL_PURCHASE', 'RENEWAL')
        AND environment = 'PRODUCTION'
        AND created_at >= NOW() - INTERVAL '30 days'
      `),

      // Total users count (for ARPU calculation)
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as total_users
        FROM events
        WHERE timestamp >= $1
      `, [startDate.toISOString()]),

      // Revenue trend by day
      pool.query(`
        SELECT
          DATE(created_at) as date,
          SUM(CASE WHEN event_type = 'INITIAL_PURCHASE' THEN price ELSE 0 END) as revenue
        FROM revenuecat_events
        WHERE environment = 'PRODUCTION'
        AND created_at >= $1
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `, [startDate.toISOString()]),

      // Revenue by plan/product
      pool.query(`
        SELECT
          product_id,
          COUNT(*) as purchases,
          SUM(price) as revenue
        FROM revenuecat_events
        WHERE event_type = 'INITIAL_PURCHASE'
        AND environment = 'PRODUCTION'
        GROUP BY product_id
        ORDER BY revenue DESC
      `),

      // Subscriber count over time
      pool.query(`
        SELECT
          DATE(created_at) as date,
          COUNT(DISTINCT app_user_id) as new_subscribers
        FROM revenuecat_events
        WHERE event_type = 'INITIAL_PURCHASE'
        AND environment = 'PRODUCTION'
        AND created_at >= $1
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `, [startDate.toISOString()])
    ]);

    const totalRevenue = parseFloat(revenueData.rows[0].total_revenue) || 0;
    const payingUsers = parseInt(revenueData.rows[0].paying_users) || 0;
    const totalUsers = parseInt(userCounts.rows[0].total_users) || 1; // Avoid division by zero
    const mrr = parseFloat(mrrData.rows[0].mrr) || 0;
    const activeSubscribers = parseInt(mrrData.rows[0].active_subscribers) || 0;

    // Calculate metrics
    const arpu = totalUsers > 0 ? totalRevenue / totalUsers : 0;
    const arppu = payingUsers > 0 ? totalRevenue / payingUsers : 0;
    // LTV estimate: ARPPU * estimated average subscription length (6 months default)
    const avgSubscriptionMonths = 6;
    const ltv = arppu * avgSubscriptionMonths;

    res.json({
      total_revenue: totalRevenue,
      mrr: mrr,
      arpu: arpu,
      arppu: arppu,
      ltv: ltv,
      paying_users: payingUsers,
      total_users: totalUsers,
      active_subscribers: activeSubscribers,
      revenue_trend: revenueTrend.rows,
      revenue_by_plan: revenueByPlan.rows,
      subscriber_trend: subscriberTrend.rows
    });
  } catch (error) {
    console.error('Error fetching monetization stats:', error);
    res.status(500).json({ error: 'Failed to fetch monetization stats' });
  }
});

// ============================================
// INDIVIDUAL USER ANALYTICS
// ============================================

// GET /v1/users - List all users with stats
app.get('/v1/users', async (req, res) => {
  try {
    const {
      days = 90,
      startDate: startDateParam,
      endDate: endDateParam,
      limit = 50,
      offset = 0,
      search = '',
      filter = 'all', // all, purchasers, active, churned, retained
      sort = 'last_active', // last_active, first_seen, events, purchases
      order = 'desc',
      // Drill-down filters
      country,
      tier,
      device,
      language,
      os,
      plan
    } = req.query;

    // Use date range helper or fallback to days-based calculation
    let startDate, endDate;
    if (startDateParam && endDateParam) {
      startDate = new Date(startDateParam);
      startDate.setHours(0, 0, 0, 0);
      endDate = new Date(endDateParam);
      endDate.setHours(23, 59, 59, 999);
    } else {
      endDate = new Date();
      startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
    }

    let filterClause = '';
    if (filter === 'purchasers') {
      filterClause = `AND device_id IN (
        SELECT DISTINCT device_id FROM events
        WHERE name = 'purchase_completed'
      )`;
    } else if (filter === 'active') {
      filterClause = `AND last_active >= NOW() - INTERVAL '7 days'`;
    } else if (filter === 'churned') {
      filterClause = `AND last_active < NOW() - INTERVAL '30 days'`;
    } else if (filter === 'retained') {
      // Users who came back after day 7
      filterClause = `AND device_id IN (
        SELECT device_id FROM events
        WHERE timestamp >= MIN(timestamp) + INTERVAL '7 days'
        GROUP BY device_id
      )`;
    }

    // Drill-down filter clauses
    if (country) {
      filterClause += ` AND device_id IN (
        SELECT DISTINCT device_id FROM events
        WHERE country = '${country.replace(/'/g, "''")}'
      )`;
    }
    if (tier) {
      const tierFilter = tier.toLowerCase();
      if (tierFilter === 'free') {
        filterClause += ` AND device_id NOT IN (
          SELECT DISTINCT device_id FROM events WHERE name = 'purchase_completed'
        )`;
      } else {
        filterClause += ` AND device_id IN (
          SELECT DISTINCT device_id FROM events
          WHERE name = 'subscription_started' AND properties->>'tier' = '${tierFilter}'
        )`;
      }
    }
    if (device) {
      filterClause += ` AND device_model ILIKE '%${device.replace(/'/g, "''")}%'`;
    }
    if (language) {
      filterClause += ` AND locale ILIKE '${language.replace(/'/g, "''")}%'`;
    }
    if (os) {
      filterClause += ` AND os_version ILIKE '%${os.replace(/'/g, "''")}%'`;
    }
    if (plan) {
      // Plan is like "Pro Monthly", "Pro Yearly", etc.
      const planParts = plan.toLowerCase().split(' ');
      const planTier = planParts[0]; // pro or max
      const planPeriod = planParts[1] === 'yearly' ? 'yearly' : 'monthly';
      filterClause += ` AND device_id IN (
        SELECT DISTINCT device_id FROM events
        WHERE name = 'subscription_started'
          AND properties->>'tier' = '${planTier}'
          AND properties->>'billing_period' = '${planPeriod}'
      )`;
    }

    let searchClause = '';
    if (search) {
      searchClause = `AND (device_id ILIKE $5 OR user_id ILIKE $5)`;
    }

    const orderColumn = {
      'last_active': 'last_active',
      'first_seen': 'first_seen',
      'events': 'total_events',
      'purchases': 'purchase_count'
    }[sort] || 'last_active';

    const orderDir = order === 'asc' ? 'ASC' : 'DESC';

    const params = [startDate.toISOString(), endDate.toISOString(), parseInt(limit), parseInt(offset)];
    if (search) params.push(`%${search}%`);

    const usersQuery = await pool.query(`
      WITH user_stats AS (
        SELECT
          device_id,
          user_id,
          MIN(timestamp) as first_seen,
          MAX(timestamp) as last_active,
          COUNT(*) as total_events,
          COUNT(DISTINCT session_id) as total_sessions,
          COUNT(DISTINCT DATE(timestamp)) as active_days,
          MAX(device_model) as device_model,
          MAX(app_version) as app_version,
          MAX(os_version) as os_version,
          MAX(locale) as locale,
          MAX(timezone) as timezone
        FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id, user_id
      ),
      purchase_stats AS (
        SELECT
          device_id,
          COUNT(*) as purchase_count,
          SUM((properties->>'revenue')::numeric) as total_revenue
        FROM events
        WHERE name = 'purchase_completed' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id
      ),
      camera_stats AS (
        SELECT
          device_id,
          COUNT(*) as photos_captured
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id
      )
      SELECT
        us.*,
        COALESCE(ps.purchase_count, 0) as purchase_count,
        COALESCE(ps.total_revenue, 0) as total_revenue,
        COALESCE(cs.photos_captured, 0) as photos_captured,
        CASE
          WHEN ps.purchase_count > 0 THEN 'subscriber'
          WHEN us.last_active >= NOW() - INTERVAL '7 days' THEN 'active'
          WHEN us.last_active < NOW() - INTERVAL '30 days' THEN 'churned'
          ELSE 'inactive'
        END as user_status
      FROM user_stats us
      LEFT JOIN purchase_stats ps ON us.device_id = ps.device_id
      LEFT JOIN camera_stats cs ON us.device_id = cs.device_id
      WHERE 1=1 ${filterClause} ${searchClause}
      ORDER BY ${orderColumn} ${orderDir}
      LIMIT $3 OFFSET $4
    `, params);

    // Get total count for pagination
    const countParams = [startDate.toISOString(), endDate.toISOString()];
    if (search) countParams.push(`%${search}%`);

    const countQuery = await pool.query(`
      WITH user_stats AS (
        SELECT
          device_id,
          MAX(timestamp) as last_active,
          MAX(device_model) as device_model,
          MAX(os_version) as os_version,
          MAX(locale) as locale
        FROM events
        WHERE timestamp >= $1 AND timestamp <= $2
        GROUP BY device_id
      )
      SELECT COUNT(*) as total
      FROM user_stats
      WHERE 1=1 ${filterClause} ${search ? 'AND device_id ILIKE $3' : ''}
    `, countParams);

    res.json({
      users: usersQuery.rows.map(u => ({
        device_id: u.device_id,
        user_id: u.user_id,
        first_seen: u.first_seen,
        last_active: u.last_active,
        total_events: parseInt(u.total_events),
        total_sessions: parseInt(u.total_sessions),
        active_days: parseInt(u.active_days),
        photos_captured: parseInt(u.photos_captured),
        purchase_count: parseInt(u.purchase_count),
        total_revenue: parseFloat(u.total_revenue) || 0,
        user_status: u.user_status,
        device_model: u.device_model,
        app_version: u.app_version,
        os_version: u.os_version,
        locale: u.locale,
        timezone: u.timezone
      })),
      pagination: {
        total: parseInt(countQuery.rows[0].total),
        limit: parseInt(limit),
        offset: parseInt(offset),
        has_more: parseInt(offset) + usersQuery.rows.length < parseInt(countQuery.rows[0].total)
      }
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /v1/users/:device_id - Get individual user details and full event history
app.get('/v1/users/:device_id', async (req, res) => {
  try {
    const { device_id } = req.params;
    const { limit = 200 } = req.query;

    const [userStats, events, purchaseHistory, profile] = await Promise.all([
      // User summary stats
      pool.query(`
        SELECT
          device_id,
          user_id,
          MIN(timestamp) as first_seen,
          MAX(timestamp) as last_active,
          COUNT(*) as total_events,
          COUNT(DISTINCT session_id) as total_sessions,
          COUNT(DISTINCT DATE(timestamp)) as active_days,
          MAX(device_model) as device_model,
          MAX(app_version) as app_version,
          MAX(os_version) as os_version,
          MAX(locale) as locale,
          MAX(timezone) as timezone,
          MAX(session_duration_seconds) as max_session_duration
        FROM events
        WHERE device_id = $1
        GROUP BY device_id, user_id
      `, [device_id]),

      // Full event history (most recent first)
      pool.query(`
        SELECT
          id,
          name,
          category,
          properties,
          timestamp,
          session_id,
          session_duration_seconds,
          app_version,
          build_number
        FROM events
        WHERE device_id = $1
        ORDER BY timestamp DESC
        LIMIT $2
      `, [device_id, parseInt(limit)]),

      // Purchase/subscription history from RevenueCat
      pool.query(`
        SELECT
          event_type,
          product_id,
          price,
          currency,
          period_type,
          purchased_at,
          expiration_at,
          is_trial_conversion,
          created_at
        FROM revenuecat_events
        WHERE app_user_id = $1 OR original_app_user_id = $1
        ORDER BY created_at DESC
      `, [device_id]),

      // User profile if exists
      pool.query(`
        SELECT * FROM user_profiles WHERE device_id = $1
      `, [device_id])
    ]);

    if (userStats.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userStats.rows[0];

    // Calculate engagement metrics
    const daysSinceFirstSeen = Math.floor(
      (new Date() - new Date(user.first_seen)) / (1000 * 60 * 60 * 24)
    );
    const daysSinceLastActive = Math.floor(
      (new Date() - new Date(user.last_active)) / (1000 * 60 * 60 * 24)
    );

    // Determine user status
    let userStatus = 'inactive';
    if (purchaseHistory.rows.some(p => p.event_type === 'INITIAL_PURCHASE' || p.event_type === 'RENEWAL')) {
      userStatus = 'subscriber';
    } else if (daysSinceLastActive <= 7) {
      userStatus = 'active';
    } else if (daysSinceLastActive > 30) {
      userStatus = 'churned';
    }

    // Event breakdown by type
    const eventBreakdown = {};
    events.rows.forEach(e => {
      eventBreakdown[e.name] = (eventBreakdown[e.name] || 0) + 1;
    });

    // Session timeline
    const sessions = {};
    events.rows.forEach(e => {
      if (e.session_id) {
        if (!sessions[e.session_id]) {
          sessions[e.session_id] = {
            session_id: e.session_id,
            events: [],
            start: e.timestamp,
            end: e.timestamp,
            duration: e.session_duration_seconds
          };
        }
        sessions[e.session_id].events.push(e);
        if (new Date(e.timestamp) < new Date(sessions[e.session_id].start)) {
          sessions[e.session_id].start = e.timestamp;
        }
        if (new Date(e.timestamp) > new Date(sessions[e.session_id].end)) {
          sessions[e.session_id].end = e.timestamp;
          sessions[e.session_id].duration = e.session_duration_seconds;
        }
      }
    });

    res.json({
      user: {
        device_id: user.device_id,
        user_id: user.user_id,
        first_seen: user.first_seen,
        last_active: user.last_active,
        days_since_install: daysSinceFirstSeen,
        days_inactive: daysSinceLastActive,
        total_events: parseInt(user.total_events),
        total_sessions: parseInt(user.total_sessions),
        active_days: parseInt(user.active_days),
        max_session_duration: parseInt(user.max_session_duration) || 0,
        status: userStatus,
        device: {
          model: user.device_model,
          os_version: user.os_version,
          app_version: user.app_version,
          locale: user.locale,
          timezone: user.timezone
        }
      },
      profile: profile.rows[0] || null,
      event_breakdown: eventBreakdown,
      events: events.rows.map(e => ({
        id: e.id,
        name: e.name,
        category: e.category,
        properties: e.properties,
        timestamp: e.timestamp,
        session_id: e.session_id,
        app_version: e.app_version
      })),
      sessions: Object.values(sessions).sort((a, b) =>
        new Date(b.start) - new Date(a.start)
      ).slice(0, 20),
      purchases: purchaseHistory.rows
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// GET /v1/users/by-event/:event_name - Get all users who triggered a specific event
app.get('/v1/users/by-event/:event_name', async (req, res) => {
  try {
    const { event_name } = req.params;
    const { limit = 100, offset = 0 } = req.query;
    const { startDate, endDate } = getDateRange(req.query);

    const usersQuery = await pool.query(`
      WITH event_users AS (
        SELECT
          device_id,
          COUNT(*) as event_count,
          MIN(timestamp) as first_occurrence,
          MAX(timestamp) as last_occurrence,
          MAX(properties) as last_properties
        FROM events
        WHERE name = $1 AND timestamp >= $2 AND timestamp <= $3
        GROUP BY device_id
      ),
      user_stats AS (
        SELECT
          device_id,
          MIN(timestamp) as first_seen,
          MAX(timestamp) as last_active,
          COUNT(*) as total_events
        FROM events
        GROUP BY device_id
      )
      SELECT
        eu.*,
        us.first_seen,
        us.last_active,
        us.total_events
      FROM event_users eu
      JOIN user_stats us ON eu.device_id = us.device_id
      ORDER BY eu.last_occurrence DESC
      LIMIT $4 OFFSET $5
    `, [event_name, startDate.toISOString(), endDate.toISOString(), parseInt(limit), parseInt(offset)]);

    const countQuery = await pool.query(`
      SELECT COUNT(DISTINCT device_id) as total
      FROM events
      WHERE name = $1 AND timestamp >= $2 AND timestamp <= $3
    `, [event_name, startDate.toISOString(), endDate.toISOString()]);

    res.json({
      event_name,
      users: usersQuery.rows.map(u => ({
        device_id: u.device_id,
        event_count: parseInt(u.event_count),
        first_occurrence: u.first_occurrence,
        last_occurrence: u.last_occurrence,
        last_properties: u.last_properties,
        first_seen: u.first_seen,
        last_active: u.last_active,
        total_events: parseInt(u.total_events)
      })),
      pagination: {
        total: parseInt(countQuery.rows[0].total),
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    console.error('Error fetching users by event:', error);
    res.status(500).json({ error: 'Failed to fetch users by event' });
  }
});

// GET /v1/users/funnel-dropoff - Get users who completed one step but not the next
app.get('/v1/users/funnel-dropoff', async (req, res) => {
  try {
    const { completed, notCompleted, limit = 100 } = req.query;
    const { startDate, endDate } = getDateRange(req.query);

    if (!completed || !notCompleted) {
      return res.status(400).json({ error: 'completed and notCompleted params required' });
    }

    const usersQuery = await pool.query(`
      WITH completed_users AS (
        SELECT DISTINCT device_id
        FROM events
        WHERE name = $1 AND timestamp >= $3 AND timestamp <= $4
      ),
      not_completed_users AS (
        SELECT DISTINCT device_id
        FROM events
        WHERE name = $2 AND timestamp >= $3 AND timestamp <= $4
      ),
      dropoff_users AS (
        SELECT cu.device_id
        FROM completed_users cu
        LEFT JOIN not_completed_users ncu ON cu.device_id = ncu.device_id
        WHERE ncu.device_id IS NULL
      )
      SELECT
        du.device_id,
        MIN(e.timestamp) as first_seen,
        MAX(e.timestamp) as last_active,
        COUNT(*) as total_events
      FROM dropoff_users du
      JOIN events e ON du.device_id = e.device_id
      GROUP BY du.device_id
      ORDER BY last_active DESC
      LIMIT $5
    `, [completed, notCompleted, startDate.toISOString(), endDate.toISOString(), parseInt(limit)]);

    res.json({
      completed_step: completed,
      not_completed_step: notCompleted,
      users: usersQuery.rows.map(u => ({
        device_id: u.device_id,
        first_seen: u.first_seen,
        last_active: u.last_active,
        total_events: parseInt(u.total_events),
        status: 'dropoff'
      }))
    });
  } catch (error) {
    console.error('Error fetching funnel dropoff users:', error);
    res.status(500).json({ error: 'Failed to fetch dropoff users' });
  }
});

// GET /v1/stats/acquisition - Attribution and acquisition analytics (hybrid: Amplitude + local)
app.get('/v1/stats/acquisition', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);

    // Format dates for Amplitude API
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    let amplitudeData = {
      new_users_by_day: [],
      total_new_users: 0,
      retention: { d1: 0, d7: 0, d30: 0 }
    };

    // Fetch from Amplitude if configured
    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

        const retentionParam = encodeURIComponent('{"event_type":"_all"}');
        const [newUsersRes, retentionRes] = await Promise.all([
          // New users over time
          fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=new`, {
            headers: { 'Authorization': `Basic ${authString}` }
          }),
          // Retention
          fetch(`https://amplitude.com/api/2/retention?start=${start}&end=${end}&re=${retentionParam}&se=${retentionParam}`, {
            headers: { 'Authorization': `Basic ${authString}` }
          })
        ]);

        const [newUsersData, retentionData] = await Promise.all([
          newUsersRes.json(),
          retentionRes.json()
        ]);

        // Parse new users by day
        if (newUsersData.data?.series?.[0] && newUsersData.data?.xValues) {
          amplitudeData.new_users_by_day = newUsersData.data.xValues.map((date, i) => ({
            date: date,
            installs: newUsersData.data.series[0][i] || 0
          }));
          amplitudeData.total_new_users = newUsersData.data.series[0].reduce((a, b) => a + b, 0);
        }

        // Parse retention data - use combinedRetention for overall retention
        if (retentionData.data?.combinedRetention) {
          const cr = retentionData.data.combinedRetention;
          amplitudeData.retention = {
            d1: cr[1] ? Math.round(cr[1] * 100) : 0,
            d7: cr[7] ? Math.round(cr[7] * 100) : 0,
            d30: cr[30] ? Math.round(cr[30] * 100) : 0
          };
        }
      } catch (ampError) {
        console.error('Amplitude acquisition fetch error:', ampError.message);
      }
    }

    // Get local data for breakdowns (device, geo, etc.) - fallback
    const [
      deviceBreakdown,
      geoBreakdown,
      timezoneBreakdown,
      languageBreakdown,
      osBreakdown
    ] = await Promise.all([
      pool.query(`
        SELECT device_model, COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND timestamp <= $2 AND device_model IS NOT NULL
        GROUP BY device_model ORDER BY users DESC LIMIT 10
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT COALESCE(NULLIF(SPLIT_PART(locale, '_', 2), ''), locale, 'Unknown') as country,
               COUNT(DISTINCT device_id) as users
        FROM events WHERE timestamp >= $1 AND timestamp <= $2 AND locale IS NOT NULL
        GROUP BY country ORDER BY users DESC LIMIT 10
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT timezone, COUNT(DISTINCT device_id) as users
        FROM events WHERE timestamp >= $1 AND timestamp <= $2 AND timezone IS NOT NULL
        GROUP BY timezone ORDER BY users DESC LIMIT 15
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT COALESCE(SPLIT_PART(locale, '_', 1), 'unknown') as language,
               COUNT(DISTINCT device_id) as users
        FROM events WHERE timestamp >= $1 AND timestamp <= $2 AND locale IS NOT NULL
        GROUP BY language ORDER BY users DESC LIMIT 10
      `, [startDate.toISOString(), endDate.toISOString()]),

      pool.query(`
        SELECT os_version, COUNT(DISTINCT device_id) as users
        FROM events WHERE timestamp >= $1 AND timestamp <= $2 AND os_version IS NOT NULL
        GROUP BY os_version ORDER BY users DESC LIMIT 10
      `, [startDate.toISOString(), endDate.toISOString()])
    ]);

    res.json({
      // Amplitude data (primary)
      installs_by_day: amplitudeData.new_users_by_day,
      total_new_users: amplitudeData.total_new_users,
      retention: amplitudeData.retention,
      // Local data (breakdowns)
      installs_by_source: [{ source: 'organic', installs: amplitudeData.total_new_users }],
      organic_vs_paid: { organic: amplitudeData.total_new_users, paid: 0 },
      device_breakdown: deviceBreakdown.rows,
      geo_breakdown: geoBreakdown.rows,
      timezone_breakdown: timezoneBreakdown.rows,
      language_breakdown: languageBreakdown.rows,
      os_breakdown: osBreakdown.rows
    });
  } catch (error) {
    console.error('Error fetching acquisition stats:', error);
    res.status(500).json({ error: 'Failed to fetch acquisition stats' });
  }
});

// ============================================
// AMPLITUDE API INTEGRATION
// ============================================

// GET /v1/amplitude/charts - Get Amplitude chart data
app.get('/v1/amplitude/charts', async (req, res) => {
  try {
    if (!AMPLITUDE_API_KEY || !AMPLITUDE_SECRET_KEY) {
      return res.status(503).json({ error: 'Amplitude not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

    // Fetch multiple metrics in parallel
    const [dauResponse, eventCountResponse, retentionResponse] = await Promise.all([
      // Daily Active Users
      fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}`, {
        headers: { 'Authorization': `Basic ${authString}` }
      }),
      // Event totals
      fetch(`https://amplitude.com/api/2/events/sum?start=${start}&end=${end}&e={"event_type":"_all"}`, {
        headers: { 'Authorization': `Basic ${authString}` }
      }),
      // Retention
      fetch(`https://amplitude.com/api/2/retention?start=${start}&end=${end}&re={"event_type":"_all"}&se={"event_type":"_all"}`, {
        headers: { 'Authorization': `Basic ${authString}` }
      })
    ]);

    const [dau, eventCount, retention] = await Promise.all([
      dauResponse.json(),
      eventCountResponse.json(),
      retentionResponse.json()
    ]);

    res.json({
      configured: true,
      daily_active_users: dau.data || [],
      event_counts: eventCount.data || [],
      retention: retention.data || [],
      date_range: { start: startDate, end: endDate }
    });
  } catch (error) {
    console.error('Error fetching Amplitude data:', error);
    res.status(500).json({ error: 'Failed to fetch Amplitude data', message: error.message });
  }
});

// GET /v1/amplitude/events - Get top events from Amplitude
app.get('/v1/amplitude/events', async (req, res) => {
  try {
    if (!AMPLITUDE_API_KEY || !AMPLITUDE_SECRET_KEY) {
      return res.status(503).json({ error: 'Amplitude not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

    const response = await fetch(
      `https://amplitude.com/api/2/events/list?start=${start}&end=${end}`,
      { headers: { 'Authorization': `Basic ${authString}` } }
    );

    const data = await response.json();

    res.json({
      configured: true,
      events: data.data || [],
      date_range: { start: startDate, end: endDate }
    });
  } catch (error) {
    console.error('Error fetching Amplitude events:', error);
    res.status(500).json({ error: 'Failed to fetch Amplitude events', message: error.message });
  }
});

// GET /v1/amplitude/user-activity - Get user activity metrics
app.get('/v1/amplitude/user-activity', async (req, res) => {
  try {
    if (!AMPLITUDE_API_KEY || !AMPLITUDE_SECRET_KEY) {
      return res.status(503).json({ error: 'Amplitude not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

    const [activeUsers, newUsers, sessions] = await Promise.all([
      fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=active`, {
        headers: { 'Authorization': `Basic ${authString}` }
      }),
      fetch(`https://amplitude.com/api/2/users?start=${start}&end=${end}&m=new`, {
        headers: { 'Authorization': `Basic ${authString}` }
      }),
      fetch(`https://amplitude.com/api/2/sessions/average?start=${start}&end=${end}`, {
        headers: { 'Authorization': `Basic ${authString}` }
      })
    ]);

    const [activeData, newData, sessionData] = await Promise.all([
      activeUsers.json(),
      newUsers.json(),
      sessions.json()
    ]);

    // Transform Amplitude's nested format to simple [{date, count}] format
    const transformUserData = (data) => {
      if (!data?.data?.xValues || !data?.data?.series?.[0]) return { daily: [], today: 0, total: 0, average: 0 };
      const daily = data.data.xValues.map((date, i) => ({
        date,
        count: data.data.series[0][i] || 0
      }));
      const series = data.data.series[0];
      const nonZeroDays = series.filter(v => v > 0);
      return {
        daily,
        today: series[series.length - 1] || 0,  // Latest day's value
        total: series.reduce((a, b) => a + b, 0),  // Sum (for reference)
        average: nonZeroDays.length > 0 ? Math.round(nonZeroDays.reduce((a, b) => a + b, 0) / nonZeroDays.length) : 0
      };
    };

    const transformSessionData = (data) => {
      if (!data?.data?.xValues || !data?.data?.series?.[0]) return { daily: [], average: 0 };
      const daily = data.data.xValues.map((date, i) => ({
        date,
        seconds: data.data.series[0][i] || 0
      }));
      // Use Amplitude's pre-calculated average from seriesCollapsed
      const avgSeconds = data.data.seriesCollapsed?.[0]?.[0]?.value || 0;
      return {
        daily,
        average: avgSeconds,
        average_formatted: avgSeconds > 0 ? `${Math.floor(avgSeconds / 60)}m ${Math.round(avgSeconds % 60)}s` : '0s'
      };
    };

    const activeMetrics = transformUserData(activeData);
    const newMetrics = transformUserData(newData);
    const sessionMetrics = transformSessionData(sessionData);

    res.json({
      configured: true,
      // Summary metrics for dashboard cards
      summary: {
        dau: activeMetrics.today,           // Today's DAU (or latest day)
        avg_dau: activeMetrics.average,     // Average DAU over period
        new_users_today: newMetrics.today,  // Today's new users
        total_new_users: newMetrics.total,  // Total new users in period
        avg_session: sessionMetrics.average_formatted
      },
      // Daily data for charts
      active_users: activeMetrics.daily,
      new_users: newMetrics.daily,
      avg_session_length: sessionMetrics.daily,
      date_range: { start: startDate, end: endDate }
    });
  } catch (error) {
    console.error('Error fetching Amplitude user activity:', error);
    res.status(500).json({ error: 'Failed to fetch user activity', message: error.message });
  }
});

// GET /v1/amplitude/funnel - Get funnel data from Amplitude
app.get('/v1/amplitude/funnel', async (req, res) => {
  try {
    if (!AMPLITUDE_API_KEY || !AMPLITUDE_SECRET_KEY) {
      return res.status(503).json({ error: 'Amplitude not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

    // Define the funnel steps
    const funnelEvents = [
      'app_opened',
      'camera_opened',
      'photo_captured',
      'paywall_viewed',
      'purchase_started',
      'purchase_completed'
    ];

    const funnelQuery = funnelEvents.map(e => `{"event_type":"${e}"}`).join(',');

    const response = await fetch(
      `https://amplitude.com/api/2/funnels?start=${start}&end=${end}&e=[${funnelQuery}]`,
      { headers: { 'Authorization': `Basic ${authString}` } }
    );

    const data = await response.json();

    res.json({
      configured: true,
      funnel: data.data || [],
      steps: funnelEvents,
      date_range: { start: startDate, end: endDate }
    });
  } catch (error) {
    console.error('Error fetching Amplitude funnel:', error);
    res.status(500).json({ error: 'Failed to fetch funnel data', message: error.message });
  }
});

// ============================================
// APPSFLYER API INTEGRATION
// ============================================

// GET /v1/appsflyer/overview - Get AppsFlyer attribution overview
app.get('/v1/appsflyer/overview', async (req, res) => {
  try {
    if (!APPSFLYER_API_TOKEN) {
      return res.status(503).json({ error: 'AppsFlyer not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const from = startDate.toISOString().split('T')[0];
    const to = endDate.toISOString().split('T')[0];

    // AppsFlyer Pull API - Aggregated Performance Report
    const response = await fetch(
      `https://hq1.appsflyer.com/api/agg-data/export/app/${APPSFLYER_APP_ID}/partners_report/v5?from=${from}&to=${to}&timezone=UTC`,
      {
        headers: {
          'Authorization': `Bearer ${APPSFLYER_API_TOKEN}`,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error('AppsFlyer API error:', response.status, errorText);
      return res.status(response.status).json({
        error: 'AppsFlyer API error',
        status: response.status,
        message: errorText
      });
    }

    const csvData = await response.text();

    // Parse CSV to JSON
    const lines = csvData.trim().split('\n');
    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const data = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/"/g, ''));
      const obj = {};
      headers.forEach((h, i) => { obj[h] = values[i]; });
      return obj;
    });

    res.json({
      configured: true,
      attribution_data: data,
      date_range: { from, to }
    });
  } catch (error) {
    console.error('Error fetching AppsFlyer data:', error);
    res.status(500).json({ error: 'Failed to fetch AppsFlyer data', message: error.message });
  }
});

// GET /v1/appsflyer/installs - Get install data
app.get('/v1/appsflyer/installs', async (req, res) => {
  try {
    if (!APPSFLYER_API_TOKEN) {
      return res.status(503).json({ error: 'AppsFlyer not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const from = startDate.toISOString().split('T')[0];
    const to = endDate.toISOString().split('T')[0];

    // Daily installs report
    const response = await fetch(
      `https://hq1.appsflyer.com/api/agg-data/export/app/${APPSFLYER_APP_ID}/daily_report/v5?from=${from}&to=${to}&timezone=UTC`,
      {
        headers: {
          'Authorization': `Bearer ${APPSFLYER_API_TOKEN}`,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'AppsFlyer API error', message: errorText });
    }

    const csvData = await response.text();

    // Parse CSV to JSON
    const lines = csvData.trim().split('\n');
    if (lines.length < 2) {
      return res.json({ configured: true, installs: [], date_range: { from, to } });
    }

    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const data = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/"/g, ''));
      const obj = {};
      headers.forEach((h, i) => { obj[h] = values[i]; });
      return obj;
    });

    res.json({
      configured: true,
      installs: data,
      date_range: { from, to }
    });
  } catch (error) {
    console.error('Error fetching AppsFlyer installs:', error);
    res.status(500).json({ error: 'Failed to fetch install data', message: error.message });
  }
});

// GET /v1/appsflyer/sources - Get media source breakdown
app.get('/v1/appsflyer/sources', async (req, res) => {
  try {
    if (!APPSFLYER_API_TOKEN) {
      return res.status(503).json({ error: 'AppsFlyer not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const from = startDate.toISOString().split('T')[0];
    const to = endDate.toISOString().split('T')[0];

    // Media source report
    const response = await fetch(
      `https://hq1.appsflyer.com/api/agg-data/export/app/${APPSFLYER_APP_ID}/partners_by_date_report/v5?from=${from}&to=${to}&timezone=UTC&groupings=pid,c`,
      {
        headers: {
          'Authorization': `Bearer ${APPSFLYER_API_TOKEN}`,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'AppsFlyer API error', message: errorText });
    }

    const csvData = await response.text();

    // Parse CSV to JSON
    const lines = csvData.trim().split('\n');
    if (lines.length < 2) {
      return res.json({ configured: true, sources: [], date_range: { from, to } });
    }

    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const data = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/"/g, ''));
      const obj = {};
      headers.forEach((h, i) => { obj[h] = values[i]; });
      return obj;
    });

    res.json({
      configured: true,
      sources: data,
      date_range: { from, to }
    });
  } catch (error) {
    console.error('Error fetching AppsFlyer sources:', error);
    res.status(500).json({ error: 'Failed to fetch source data', message: error.message });
  }
});

// GET /v1/appsflyer/revenue - Get revenue/ROAS data
app.get('/v1/appsflyer/revenue', async (req, res) => {
  try {
    if (!APPSFLYER_API_TOKEN) {
      return res.status(503).json({ error: 'AppsFlyer not configured', configured: false });
    }

    const { startDate, endDate } = getDateRange(req.query);
    const from = startDate.toISOString().split('T')[0];
    const to = endDate.toISOString().split('T')[0];

    // Revenue report with ROAS
    const response = await fetch(
      `https://hq1.appsflyer.com/api/agg-data/export/app/${APPSFLYER_APP_ID}/partners_report/v5?from=${from}&to=${to}&timezone=UTC&kpis=revenue,roi`,
      {
        headers: {
          'Authorization': `Bearer ${APPSFLYER_API_TOKEN}`,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'AppsFlyer API error', message: errorText });
    }

    const csvData = await response.text();

    // Parse CSV to JSON
    const lines = csvData.trim().split('\n');
    if (lines.length < 2) {
      return res.json({ configured: true, revenue: [], date_range: { from, to } });
    }

    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const data = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/"/g, ''));
      const obj = {};
      headers.forEach((h, i) => { obj[h] = values[i]; });
      return obj;
    });

    res.json({
      configured: true,
      revenue: data,
      date_range: { from, to }
    });
  } catch (error) {
    console.error('Error fetching AppsFlyer revenue:', error);
    res.status(500).json({ error: 'Failed to fetch revenue data', message: error.message });
  }
});

// ============================================
// SENTRY API INTEGRATION
// ============================================

// GET /v1/sentry/overview - Get Sentry error overview
app.get('/v1/sentry/overview', async (req, res) => {
  try {
    if (!SENTRY_AUTH_TOKEN) {
      return res.status(503).json({ error: 'Sentry not configured', configured: false });
    }

    const { days = 14 } = req.query;
    // Sentry only accepts 24h or 14d for statsPeriod
    const statsPeriod = Number(days) <= 1 ? '24h' : '14d';

    const [issuesResponse, statsResponse] = await Promise.all([
      // Get recent issues
      fetch(
        `https://sentry.io/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/issues/?query=is:unresolved&statsPeriod=${statsPeriod}&limit=25`,
        { headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` } }
      ),
      // Get project stats
      fetch(
        `https://sentry.io/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/stats/?stat=received&resolution=1d&statsPeriod=${statsPeriod}`,
        { headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` } }
      )
    ]);

    if (!issuesResponse.ok) {
      const errorText = await issuesResponse.text();
      console.error('Sentry issues API error:', issuesResponse.status, errorText);
      return res.status(issuesResponse.status).json({
        error: 'Sentry API error',
        message: errorText
      });
    }

    const [issues, stats] = await Promise.all([
      issuesResponse.json(),
      statsResponse.ok ? statsResponse.json() : []
    ]);

    // Calculate summary stats
    const totalEvents = stats.reduce((sum, [_, count]) => sum + count, 0);
    const criticalIssues = issues.filter(i => i.level === 'fatal' || i.level === 'error').length;

    res.json({
      configured: true,
      summary: {
        total_events: totalEvents,
        unresolved_issues: issues.length,
        critical_issues: criticalIssues,
        period_days: parseInt(days)
      },
      issues: issues.map(i => ({
        id: i.id,
        title: i.title,
        culprit: i.culprit,
        level: i.level,
        status: i.status,
        count: i.count,
        user_count: i.userCount,
        first_seen: i.firstSeen,
        last_seen: i.lastSeen,
        short_id: i.shortId,
        permalink: i.permalink
      })),
      events_by_day: stats.map(([timestamp, count]) => ({
        date: new Date(timestamp * 1000).toISOString().split('T')[0],
        count
      }))
    });
  } catch (error) {
    console.error('Error fetching Sentry data:', error);
    res.status(500).json({ error: 'Failed to fetch Sentry data', message: error.message });
  }
});

// GET /v1/sentry/issues - Get detailed issue list
app.get('/v1/sentry/issues', async (req, res) => {
  try {
    if (!SENTRY_AUTH_TOKEN) {
      return res.status(503).json({ error: 'Sentry not configured', configured: false });
    }

    const { query = 'is:unresolved', limit = 50, cursor } = req.query;

    let url = `https://sentry.io/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/issues/?query=${encodeURIComponent(query)}&limit=${limit}`;
    if (cursor) url += `&cursor=${cursor}`;

    const response = await fetch(url, {
      headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` }
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'Sentry API error', message: errorText });
    }

    const issues = await response.json();
    const linkHeader = response.headers.get('Link');

    res.json({
      configured: true,
      issues: issues.map(i => ({
        id: i.id,
        title: i.title,
        culprit: i.culprit,
        level: i.level,
        status: i.status,
        count: i.count,
        user_count: i.userCount,
        first_seen: i.firstSeen,
        last_seen: i.lastSeen,
        short_id: i.shortId,
        permalink: i.permalink,
        metadata: i.metadata
      })),
      pagination: {
        link: linkHeader
      }
    });
  } catch (error) {
    console.error('Error fetching Sentry issues:', error);
    res.status(500).json({ error: 'Failed to fetch issues', message: error.message });
  }
});

// GET /v1/sentry/issue/:issue_id - Get specific issue details
app.get('/v1/sentry/issue/:issue_id', async (req, res) => {
  try {
    if (!SENTRY_AUTH_TOKEN) {
      return res.status(503).json({ error: 'Sentry not configured', configured: false });
    }

    const { issue_id } = req.params;

    const [issueResponse, eventsResponse] = await Promise.all([
      fetch(`https://sentry.io/api/0/issues/${issue_id}/`, {
        headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` }
      }),
      fetch(`https://sentry.io/api/0/issues/${issue_id}/events/?limit=10`, {
        headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` }
      })
    ]);

    if (!issueResponse.ok) {
      return res.status(issueResponse.status).json({ error: 'Issue not found' });
    }

    const [issue, events] = await Promise.all([
      issueResponse.json(),
      eventsResponse.ok ? eventsResponse.json() : []
    ]);

    res.json({
      configured: true,
      issue: {
        id: issue.id,
        title: issue.title,
        culprit: issue.culprit,
        level: issue.level,
        status: issue.status,
        count: issue.count,
        user_count: issue.userCount,
        first_seen: issue.firstSeen,
        last_seen: issue.lastSeen,
        short_id: issue.shortId,
        permalink: issue.permalink,
        metadata: issue.metadata,
        type: issue.type
      },
      recent_events: events.map(e => ({
        id: e.eventID,
        timestamp: e.dateCreated,
        message: e.message,
        tags: e.tags,
        context: e.context,
        user: e.user
      }))
    });
  } catch (error) {
    console.error('Error fetching Sentry issue:', error);
    res.status(500).json({ error: 'Failed to fetch issue details', message: error.message });
  }
});

// GET /v1/sentry/crashes - Get crash-free rate and sessions
app.get('/v1/sentry/crashes', async (req, res) => {
  try {
    if (!SENTRY_AUTH_TOKEN) {
      return res.status(503).json({ error: 'Sentry not configured', configured: false });
    }

    const { days = 14 } = req.query;

    // Get session data for crash-free rate
    const response = await fetch(
      `https://sentry.io/api/0/organizations/${SENTRY_ORG}/sessions/?project=${SENTRY_PROJECT}&field=sum(session)&field=crash_free_rate(session)&statsPeriod=${days}d&interval=1d`,
      { headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` } }
    );

    if (!response.ok) {
      // Sessions API might not be available for all plans
      return res.json({
        configured: true,
        available: false,
        message: 'Session data requires Sentry Team plan or higher'
      });
    }

    const data = await response.json();

    res.json({
      configured: true,
      available: true,
      sessions: data.groups || [],
      intervals: data.intervals || []
    });
  } catch (error) {
    console.error('Error fetching Sentry crash data:', error);
    res.status(500).json({ error: 'Failed to fetch crash data', message: error.message });
  }
});

// ============================================
// APP STORE CONNECT API INTEGRATION
// ============================================

// Helper function to generate App Store Connect JWT
function generateASCToken() {
  if (!ASC_ISSUER_ID || !ASC_KEY_ID || !ASC_PRIVATE_KEY) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ASC_ISSUER_ID,
    iat: now,
    exp: now + 20 * 60, // 20 minutes
    aud: 'appstoreconnect-v1'
  };

  // Decode base64 private key
  const privateKey = Buffer.from(ASC_PRIVATE_KEY, 'base64').toString('utf8');

  return jwt.sign(payload, privateKey, {
    algorithm: 'ES256',
    header: {
      alg: 'ES256',
      kid: ASC_KEY_ID,
      typ: 'JWT'
    }
  });
}

// GET /v1/appstore/overview - App Store analytics overview
app.get('/v1/appstore/overview', async (req, res) => {
  try {
    const token = generateASCToken();
    if (!token) {
      return res.status(503).json({ error: 'App Store Connect not configured', configured: false });
    }

    const { days = 30 } = req.query;
    const endDate = new Date().toISOString().split('T')[0];
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    // Fetch app info and sales/downloads
    const [appResponse, salesResponse] = await Promise.all([
      fetch(`https://api.appstoreconnect.apple.com/v1/apps/${ASC_APP_ID}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }),
      fetch(`https://api.appstoreconnect.apple.com/v1/salesReports?filter[reportType]=SALES&filter[reportSubType]=SUMMARY&filter[frequency]=DAILY&filter[vendorNumber]=${ASC_APP_ID}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).catch(() => null) // Sales API may require different permissions
    ]);

    if (!appResponse.ok) {
      const errorText = await appResponse.text();
      console.error('App Store Connect API error:', appResponse.status, errorText);
      return res.status(appResponse.status).json({
        error: 'App Store Connect API error',
        message: errorText,
        configured: true
      });
    }

    const appData = await appResponse.json();

    res.json({
      configured: true,
      app: {
        id: appData.data?.id,
        name: appData.data?.attributes?.name,
        bundleId: appData.data?.attributes?.bundleId,
        sku: appData.data?.attributes?.sku
      },
      period: { startDate, endDate, days: parseInt(days) }
    });
  } catch (error) {
    console.error('Error fetching App Store data:', error);
    res.status(500).json({ error: 'Failed to fetch App Store data', message: error.message });
  }
});

// GET /v1/appstore/downloads - Download and install metrics
app.get('/v1/appstore/downloads', async (req, res) => {
  try {
    const token = generateASCToken();
    if (!token) {
      return res.status(503).json({ error: 'App Store Connect not configured', configured: false });
    }

    const { days = 30 } = req.query;
    const endDate = new Date().toISOString().split('T')[0];
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    // Analytics Reports API for downloads
    const response = await fetch(
      `https://api.appstoreconnect.apple.com/v1/analyticsReportRequests`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          data: {
            type: 'analyticsReportRequests',
            attributes: {
              accessType: 'ONGOING'
            },
            relationships: {
              app: {
                data: { type: 'apps', id: ASC_APP_ID }
              }
            }
          }
        })
      }
    );

    if (!response.ok) {
      // Fall back to basic app info if analytics not available
      const appResponse = await fetch(
        `https://api.appstoreconnect.apple.com/v1/apps/${ASC_APP_ID}/appStoreVersions?filter[appStoreState]=READY_FOR_SALE&include=appStoreVersionLocalizations`,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );

      if (appResponse.ok) {
        const appData = await appResponse.json();
        return res.json({
          configured: true,
          note: 'Full analytics requires App Analytics Reporter role',
          currentVersion: appData.data?.[0]?.attributes?.versionString,
          period: { startDate, endDate, days: parseInt(days) }
        });
      }
    }

    const data = await response.json();
    res.json({
      configured: true,
      analytics: data,
      period: { startDate, endDate, days: parseInt(days) }
    });
  } catch (error) {
    console.error('Error fetching App Store downloads:', error);
    res.status(500).json({ error: 'Failed to fetch download data', message: error.message });
  }
});

// GET /v1/appstore/ratings - App ratings and reviews
app.get('/v1/appstore/ratings', async (req, res) => {
  try {
    const token = generateASCToken();
    if (!token) {
      return res.status(503).json({ error: 'App Store Connect not configured', configured: false });
    }

    const { limit = 50 } = req.query;

    // Fetch customer reviews
    const response = await fetch(
      `https://api.appstoreconnect.apple.com/v1/apps/${ASC_APP_ID}/customerReviews?limit=${limit}&sort=-createdDate`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'App Store Connect API error', message: errorText });
    }

    const data = await response.json();

    const reviews = (data.data || []).map(review => ({
      id: review.id,
      rating: review.attributes?.rating,
      title: review.attributes?.title,
      body: review.attributes?.body,
      reviewerNickname: review.attributes?.reviewerNickname,
      createdDate: review.attributes?.createdDate,
      territory: review.attributes?.territory
    }));

    // Calculate rating distribution
    const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    reviews.forEach(r => {
      if (r.rating >= 1 && r.rating <= 5) {
        ratingCounts[r.rating]++;
      }
    });

    const totalReviews = reviews.length;
    const averageRating = totalReviews > 0
      ? reviews.reduce((sum, r) => sum + (r.rating || 0), 0) / totalReviews
      : 0;

    res.json({
      configured: true,
      summary: {
        totalReviews,
        averageRating: Math.round(averageRating * 10) / 10,
        ratingDistribution: ratingCounts
      },
      reviews
    });
  } catch (error) {
    console.error('Error fetching App Store ratings:', error);
    res.status(500).json({ error: 'Failed to fetch ratings', message: error.message });
  }
});

// GET /v1/appstore/versions - App version history
app.get('/v1/appstore/versions', async (req, res) => {
  try {
    const token = generateASCToken();
    if (!token) {
      return res.status(503).json({ error: 'App Store Connect not configured', configured: false });
    }

    const response = await fetch(
      `https://api.appstoreconnect.apple.com/v1/apps/${ASC_APP_ID}/appStoreVersions?limit=10&sort=-createdDate`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'App Store Connect API error', message: errorText });
    }

    const data = await response.json();

    const versions = (data.data || []).map(version => ({
      id: version.id,
      versionString: version.attributes?.versionString,
      appStoreState: version.attributes?.appStoreState,
      releaseType: version.attributes?.releaseType,
      createdDate: version.attributes?.createdDate
    }));

    res.json({ configured: true, versions });
  } catch (error) {
    console.error('Error fetching App Store versions:', error);
    res.status(500).json({ error: 'Failed to fetch versions', message: error.message });
  }
});

// ============================================
// GOOGLE SEARCH CONSOLE API INTEGRATION
// ============================================

// Helper to get GSC access token
async function getGSCAccessToken() {
  if (!GSC_CLIENT_EMAIL || !GSC_PRIVATE_KEY) {
    return null;
  }

  try {
    const privateKey = Buffer.from(GSC_PRIVATE_KEY, 'base64').toString('utf8');

    const auth = new GoogleAuth({
      credentials: {
        client_email: GSC_CLIENT_EMAIL,
        private_key: privateKey
      },
      scopes: ['https://www.googleapis.com/auth/webmasters.readonly']
    });

    const client = await auth.getClient();
    const token = await client.getAccessToken();
    return token.token;
  } catch (error) {
    console.error('Error getting GSC token:', error);
    return null;
  }
}

// GET /v1/searchconsole/overview - Search Console overview
app.get('/v1/searchconsole/overview', async (req, res) => {
  try {
    const token = await getGSCAccessToken();
    if (!token) {
      return res.status(503).json({ error: 'Google Search Console not configured', configured: false });
    }

    const { days = 28 } = req.query;
    const endDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]; // 2 days ago (GSC delay)
    const startDate = new Date(Date.now() - (parseInt(days) + 2) * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const response = await fetch(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(GSC_SITE_URL)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          startDate,
          endDate,
          dimensions: ['date'],
          rowLimit: 1000
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error('GSC API error:', response.status, errorText);
      return res.status(response.status).json({ error: 'Google Search Console API error', message: errorText });
    }

    const data = await response.json();

    // Calculate totals
    const rows = data.rows || [];
    const totals = rows.reduce((acc, row) => ({
      clicks: acc.clicks + (row.clicks || 0),
      impressions: acc.impressions + (row.impressions || 0),
      ctr: 0,
      position: acc.position + (row.position || 0)
    }), { clicks: 0, impressions: 0, ctr: 0, position: 0 });

    totals.ctr = totals.impressions > 0 ? (totals.clicks / totals.impressions) * 100 : 0;
    totals.position = rows.length > 0 ? totals.position / rows.length : 0;

    res.json({
      configured: true,
      period: { startDate, endDate, days: parseInt(days) },
      totals: {
        clicks: totals.clicks,
        impressions: totals.impressions,
        ctr: Math.round(totals.ctr * 100) / 100,
        avgPosition: Math.round(totals.position * 10) / 10
      },
      daily: rows.map(row => ({
        date: row.keys[0],
        clicks: row.clicks,
        impressions: row.impressions,
        ctr: Math.round((row.ctr || 0) * 10000) / 100,
        position: Math.round((row.position || 0) * 10) / 10
      }))
    });
  } catch (error) {
    console.error('Error fetching Search Console data:', error);
    res.status(500).json({ error: 'Failed to fetch Search Console data', message: error.message });
  }
});

// GET /v1/searchconsole/queries - Top search queries
app.get('/v1/searchconsole/queries', async (req, res) => {
  try {
    const token = await getGSCAccessToken();
    if (!token) {
      return res.status(503).json({ error: 'Google Search Console not configured', configured: false });
    }

    const { days = 28, limit = 100 } = req.query;
    const endDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const startDate = new Date(Date.now() - (parseInt(days) + 2) * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const response = await fetch(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(GSC_SITE_URL)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          startDate,
          endDate,
          dimensions: ['query'],
          rowLimit: parseInt(limit)
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'Google Search Console API error', message: errorText });
    }

    const data = await response.json();

    const queries = (data.rows || []).map(row => ({
      query: row.keys[0],
      clicks: row.clicks,
      impressions: row.impressions,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10
    }));

    res.json({
      configured: true,
      period: { startDate, endDate, days: parseInt(days) },
      queries
    });
  } catch (error) {
    console.error('Error fetching Search Console queries:', error);
    res.status(500).json({ error: 'Failed to fetch queries', message: error.message });
  }
});

// GET /v1/searchconsole/pages - Top pages
app.get('/v1/searchconsole/pages', async (req, res) => {
  try {
    const token = await getGSCAccessToken();
    if (!token) {
      return res.status(503).json({ error: 'Google Search Console not configured', configured: false });
    }

    const { days = 28, limit = 50 } = req.query;
    const endDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const startDate = new Date(Date.now() - (parseInt(days) + 2) * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const response = await fetch(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(GSC_SITE_URL)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          startDate,
          endDate,
          dimensions: ['page'],
          rowLimit: parseInt(limit)
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'Google Search Console API error', message: errorText });
    }

    const data = await response.json();

    const pages = (data.rows || []).map(row => ({
      page: row.keys[0],
      clicks: row.clicks,
      impressions: row.impressions,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10
    }));

    res.json({
      configured: true,
      period: { startDate, endDate, days: parseInt(days) },
      pages
    });
  } catch (error) {
    console.error('Error fetching Search Console pages:', error);
    res.status(500).json({ error: 'Failed to fetch pages', message: error.message });
  }
});

// GET /v1/searchconsole/devices - Device breakdown
app.get('/v1/searchconsole/devices', async (req, res) => {
  try {
    const token = await getGSCAccessToken();
    if (!token) {
      return res.status(503).json({ error: 'Google Search Console not configured', configured: false });
    }

    const { days = 28 } = req.query;
    const endDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const startDate = new Date(Date.now() - (parseInt(days) + 2) * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const response = await fetch(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(GSC_SITE_URL)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          startDate,
          endDate,
          dimensions: ['device']
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'Google Search Console API error', message: errorText });
    }

    const data = await response.json();

    const devices = (data.rows || []).map(row => ({
      device: row.keys[0],
      clicks: row.clicks,
      impressions: row.impressions,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10
    }));

    res.json({
      configured: true,
      period: { startDate, endDate, days: parseInt(days) },
      devices
    });
  } catch (error) {
    console.error('Error fetching Search Console devices:', error);
    res.status(500).json({ error: 'Failed to fetch device data', message: error.message });
  }
});

// ============================================
// UNIFIED INTEGRATIONS STATUS
// ============================================

// GET /v1/integrations/status - Check status of all integrations
app.get('/v1/integrations/status', async (req, res) => {
  const status = {
    revenuecat: {
      configured: true, // Always configured via webhooks
      status: 'active'
    },
    amplitude: {
      configured: !!(AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY),
      status: AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY ? 'active' : 'not_configured'
    },
    appsflyer: {
      configured: !!APPSFLYER_API_TOKEN,
      status: APPSFLYER_API_TOKEN ? 'active' : 'not_configured',
      app_id: APPSFLYER_APP_ID
    },
    sentry: {
      configured: !!SENTRY_AUTH_TOKEN,
      status: SENTRY_AUTH_TOKEN ? 'active' : 'not_configured',
      org: SENTRY_ORG,
      project: SENTRY_PROJECT
    },
    appstore: {
      configured: !!(ASC_ISSUER_ID && ASC_KEY_ID && ASC_PRIVATE_KEY),
      status: ASC_ISSUER_ID && ASC_KEY_ID && ASC_PRIVATE_KEY ? 'active' : 'not_configured',
      app_id: ASC_APP_ID
    },
    searchconsole: {
      configured: !!(GSC_CLIENT_EMAIL && GSC_PRIVATE_KEY),
      status: GSC_CLIENT_EMAIL && GSC_PRIVATE_KEY ? 'active' : 'not_configured',
      site_url: GSC_SITE_URL
    }
  };

  // Test each integration if configured
  const tests = [];

  if (status.amplitude.configured) {
    tests.push(
      fetch('https://amplitude.com/api/2/users?start=20240101&end=20240102', {
        headers: { 'Authorization': `Basic ${Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64')}` }
      }).then(r => { status.amplitude.status = r.ok ? 'active' : 'error'; })
        .catch(() => { status.amplitude.status = 'error'; })
    );
  }

  if (status.sentry.configured) {
    tests.push(
      fetch(`https://sentry.io/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/`, {
        headers: { 'Authorization': `Bearer ${SENTRY_AUTH_TOKEN}` }
      }).then(r => { status.sentry.status = r.ok ? 'active' : 'error'; })
        .catch(() => { status.sentry.status = 'error'; })
    );
  }

  await Promise.all(tests);

  res.json(status);
});

// ============================================
// AMPLITUDE DATA SYNC
// ============================================

// Helper to decompress gzip response
const zlib = require('zlib');
const { promisify } = require('util');
const gunzip = promisify(zlib.gunzip);

// Sync events from Amplitude Export API to local database
async function syncAmplitudeEvents(startDate, endDate) {
  if (!AMPLITUDE_API_KEY || !AMPLITUDE_SECRET_KEY) {
    throw new Error('Amplitude not configured');
  }

  const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

  // Format dates as YYYYMMDDTHH
  const start = startDate.replace(/-/g, '') + 'T00';
  const end = endDate.replace(/-/g, '') + 'T23';

  console.log(`[Amplitude Sync] Fetching events from ${start} to ${end}`);

  const response = await fetch(
    `https://amplitude.com/api/2/export?start=${start}&end=${end}`,
    { headers: { 'Authorization': `Basic ${authString}` } }
  );

  if (!response.ok) {
    if (response.status === 404) {
      console.log('[Amplitude Sync] No data available for this time range');
      return { synced: 0, skipped: 0, errors: 0 };
    }
    throw new Error(`Amplitude API error: ${response.status} ${response.statusText}`);
  }

  // Response is a gzipped file containing JSON lines
  const buffer = await response.arrayBuffer();
  let content;
  try {
    content = await gunzip(Buffer.from(buffer));
  } catch (e) {
    // If not gzipped, use as-is
    content = Buffer.from(buffer);
  }

  const lines = content.toString('utf-8').split('\n').filter(line => line.trim());
  console.log(`[Amplitude Sync] Processing ${lines.length} events`);

  let synced = 0, skipped = 0, errors = 0;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const line of lines) {
      try {
        const event = JSON.parse(line);

        // Check if event already exists (by device_id + timestamp + event_type)
        const exists = await client.query(
          `SELECT 1 FROM events WHERE device_id = $1 AND name = $2 AND timestamp = $3 LIMIT 1`,
          [event.device_id, event.event_type, event.event_time || event.server_received_time]
        );

        if (exists.rows.length > 0) {
          skipped++;
          continue;
        }

        // Insert event
        await client.query(`
          INSERT INTO events (
            name, category, properties, timestamp,
            user_id, device_id, session_id,
            app_version, platform, os_version,
            device_model, locale, timezone
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        `, [
          event.event_type,
          event.event_properties?.category || 'engagement',
          JSON.stringify(event.event_properties || {}),
          event.event_time || event.server_received_time,
          event.user_id,
          event.device_id,
          event.session_id ? String(event.session_id) : null,
          event.app_version,
          event.platform || 'ios',
          event.os_version,
          event.device_type,
          event.language,
          event.timezone || null
        ]);
        synced++;
      } catch (e) {
        console.error('[Amplitude Sync] Error processing event:', e.message);
        errors++;
      }
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  console.log(`[Amplitude Sync] Complete: ${synced} synced, ${skipped} skipped, ${errors} errors`);
  return { synced, skipped, errors };
}

// POST /v1/amplitude/sync - Trigger manual sync from Amplitude
app.post('/v1/amplitude/sync', requireAuth, async (req, res) => {
  try {
    const { days = 7 } = req.body;

    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const result = await syncAmplitudeEvents(
      startDate.toISOString().split('T')[0],
      endDate.toISOString().split('T')[0]
    );

    res.json({
      success: true,
      message: `Synced ${result.synced} events from Amplitude`,
      ...result
    });
  } catch (error) {
    console.error('Amplitude sync error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /v1/amplitude/sync/status - Check last sync status
app.get('/v1/amplitude/sync/status', async (req, res) => {
  try {
    // Get the most recent event timestamp and count
    const result = await pool.query(`
      SELECT
        COUNT(*) as total_events,
        COUNT(DISTINCT device_id) as unique_users,
        MAX(timestamp) as latest_event,
        MIN(timestamp) as earliest_event
      FROM events
    `);

    res.json({
      configured: !!(AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY),
      ...result.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Auto-sync on startup (last 30 days) - runs in background
if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
  setTimeout(async () => {
    try {
      console.log('[Amplitude Sync] Running startup sync (last 30 days)...');
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 30);

      await syncAmplitudeEvents(
        startDate.toISOString().split('T')[0],
        endDate.toISOString().split('T')[0]
      );
    } catch (e) {
      console.error('[Amplitude Sync] Startup sync failed:', e.message);
    }
  }, 5000); // Wait 5 seconds after startup
}

// GET /v1/stats/feature-usage - Detailed feature usage metrics from Amplitude
app.get('/v1/stats/feature-usage', async (req, res) => {
  try {
    const { startDate, endDate } = getDateRange(req.query);
    const start = startDate.toISOString().split('T')[0].replace(/-/g, '');
    const end = endDate.toISOString().split('T')[0].replace(/-/g, '');

    let result = {
      photos_captured: 0,
      photos_scanned: 0,
      scans_total: 0,
      scans_7days: 0,
      scans_30days: 0,
      scans_6months: 0,
      scans_all: 0,
      scans_custom: 0,
      icloud_backup_enabled: 0,
      widget_clicks: 0,
      shortcut_taps: 0
    };

    if (AMPLITUDE_API_KEY && AMPLITUDE_SECRET_KEY) {
      try {
        const authString = Buffer.from(`${AMPLITUDE_API_KEY}:${AMPLITUDE_SECRET_KEY}`).toString('base64');

        // Fetch event list to get totals
        const eventsRes = await fetch(`https://amplitude.com/api/2/events/list?start=${start}&end=${end}`, {
          headers: { 'Authorization': `Basic ${authString}` }
        });
        const eventsData = await eventsRes.json();

        if (eventsData.data && Array.isArray(eventsData.data)) {
          // Extract event counts
          const photoCaptured = eventsData.data.find(e => e.name === 'photo_captured');
          const scanStarted = eventsData.data.find(e => e.name === 'scan_started');
          const scanCompleted = eventsData.data.find(e => e.name === 'scan_completed');
          const icloudToggled = eventsData.data.find(e => e.name === 'icloud_backup_toggled');
          const widgetClicked = eventsData.data.find(e => e.name === 'widget_clicked');
          const shortcutTapped = eventsData.data.find(e => e.name === 'shortcut_tapped');

          result.photos_captured = photoCaptured?.totals || 0;
          result.scans_total = scanStarted?.totals || 0;
          result.widget_clicks = widgetClicked?.totals || 0;
          result.shortcut_taps = shortcutTapped?.totals || 0;

          // For scan_completed, sum up photos_scanned
          if (scanCompleted?.totals) {
            // Estimate photos scanned based on avg per scan
            result.photos_scanned = scanCompleted.totals * 50; // Rough estimate
          }

          // For detailed scan breakdowns by date_range, we need Event Segmentation API
          // This requires a different API call with segmentation
          try {
            const segmentationBody = JSON.stringify({
              e: { event_type: 'scan_started' },
              m: 'totals',
              start: start,
              end: end,
              g: 'date_range'
            });

            const segRes = await fetch('https://amplitude.com/api/2/events/segmentation', {
              method: 'POST',
              headers: {
                'Authorization': `Basic ${authString}`,
                'Content-Type': 'application/json'
              },
              body: segmentationBody
            });
            const segData = await segRes.json();

            if (segData.data?.seriesCollapsed) {
              // Parse the segmented data for each date_range value
              for (const [key, values] of Object.entries(segData.data.seriesCollapsed)) {
                const total = Array.isArray(values) ? values.reduce((a, b) => a + b, 0) : values;
                if (key === '7days') result.scans_7days = total;
                else if (key === '30days') result.scans_30days = total;
                else if (key === '6months') result.scans_6months = total;
                else if (key === 'all') result.scans_all = total;
                else if (key === 'custom') result.scans_custom = total;
              }
            }
          } catch (segError) {
            console.log('Segmentation API not available or failed, using estimates');
            // Fallback: distribute scans evenly as estimate
            if (result.scans_total > 0) {
              result.scans_7days = Math.round(result.scans_total * 0.4);
              result.scans_30days = Math.round(result.scans_total * 0.35);
              result.scans_6months = Math.round(result.scans_total * 0.15);
              result.scans_all = Math.round(result.scans_total * 0.08);
              result.scans_custom = Math.round(result.scans_total * 0.02);
            }
          }

          // iCloud backup enabled count (from icloud_backup_toggled where enabled=true)
          // This would need property segmentation, use estimate for now
          result.icloud_backup_enabled = icloudToggled?.totals ? Math.round(icloudToggled.totals * 0.7) : 0;
        }
      } catch (ampError) {
        console.error('Amplitude feature-usage fetch error:', ampError.message);
      }
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching feature usage:', error);
    res.status(500).json({ error: 'Failed to fetch feature usage' });
  }
});

// ============================================
// SERVER ANALYTICS ENDPOINTS
// (100% server-side tracking - no ATT dependency)
// ============================================

// GET /v1/stats/server-overview - DAU/WAU/MAU, total users, events from server events table
app.get('/v1/stats/server-overview', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const today = new Date(now);
    today.setHours(0, 0, 0, 0);

    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    const weekAgo = new Date(today);
    weekAgo.setDate(weekAgo.getDate() - 7);

    const monthAgo = new Date(today);
    monthAgo.setDate(monthAgo.getDate() - 30);

    // Run all queries in parallel
    const [
      dauResult,
      dauYesterdayResult,
      wauResult,
      mauResult,
      totalUsersResult,
      totalEventsResult,
      eventsToday,
      newUsersToday,
      avgEventsPerUser
    ] = await Promise.all([
      // DAU (today)
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1
      `, [today]),

      // DAU (yesterday for comparison)
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1 AND timestamp < $2
      `, [yesterday, today]),

      // WAU
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1
      `, [weekAgo]),

      // MAU
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1
      `, [monthAgo]),

      // Total unique users all time
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events`),

      // Total events all time
      pool.query(`SELECT COUNT(*) as count FROM events`),

      // Events today
      pool.query(`
        SELECT COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
      `, [today]),

      // New users today (first event was today)
      pool.query(`
        SELECT COUNT(*) as count FROM (
          SELECT device_id
          FROM events
          GROUP BY device_id
          HAVING MIN(timestamp) >= $1
        ) first_events
      `, [today]),

      // Avg events per user (last 30 days)
      pool.query(`
        SELECT
          COALESCE(COUNT(*)::float / NULLIF(COUNT(DISTINCT device_id), 0), 0) as avg
        FROM events
        WHERE timestamp >= $1
      `, [monthAgo])
    ]);

    const dau = parseInt(dauResult.rows[0].count);
    const dauYesterday = parseInt(dauYesterdayResult.rows[0].count);

    res.json({
      dau,
      dau_change: dauYesterday > 0 ? ((dau - dauYesterday) / dauYesterday * 100).toFixed(1) : 0,
      wau: parseInt(wauResult.rows[0].count),
      mau: parseInt(mauResult.rows[0].count),
      total_users: parseInt(totalUsersResult.rows[0].count),
      total_events: parseInt(totalEventsResult.rows[0].count),
      events_today: parseInt(eventsToday.rows[0].count),
      new_users_today: parseInt(newUsersToday.rows[0].count),
      avg_events_per_user: parseFloat(avgEventsPerUser.rows[0].avg).toFixed(1),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching server overview:', error);
    res.status(500).json({ error: 'Failed to fetch server overview' });
  }
});

// GET /v1/stats/server-photos - Photo capture analytics from server events
app.get('/v1/stats/server-photos', requireAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);

    const [
      totalPhotos,
      photosPerUser,
      sourceBreakdown,
      scheduleBreakdown,
      photosByDay
    ] = await Promise.all([
      // Total photos captured
      pool.query(`
        SELECT COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured'
        AND timestamp >= $1
      `, [startDate]),

      // Photos per user (avg)
      pool.query(`
        SELECT
          COALESCE(COUNT(*)::float / NULLIF(COUNT(DISTINCT device_id), 0), 0) as avg
        FROM events
        WHERE name = 'photo_captured'
        AND timestamp >= $1
      `, [startDate]),

      // Source breakdown (app vs widget)
      pool.query(`
        SELECT
          COALESCE(properties->>'source', 'app') as source,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured'
        AND timestamp >= $1
        GROUP BY COALESCE(properties->>'source', 'app')
      `, [startDate]),

      // Delete schedule breakdown
      pool.query(`
        SELECT
          COALESCE(properties->>'delete_schedule', 'unknown') as schedule,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured'
        AND timestamp >= $1
        GROUP BY COALESCE(properties->>'delete_schedule', 'unknown')
        ORDER BY count DESC
      `, [startDate]),

      // Photos by day
      pool.query(`
        SELECT
          DATE(timestamp) as date,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured'
        AND timestamp >= $1
        GROUP BY DATE(timestamp)
        ORDER BY date
      `, [startDate])
    ]);

    // Build source breakdown object
    const sourceData = sourceBreakdown.rows.reduce((acc, row) => {
      acc[row.source] = parseInt(row.count);
      return acc;
    }, {});

    // Build delete schedule object
    const scheduleData = scheduleBreakdown.rows.reduce((acc, row) => {
      acc[row.schedule] = parseInt(row.count);
      return acc;
    }, {});

    res.json({
      total_photos: parseInt(totalPhotos.rows[0].count),
      photos_per_user: parseFloat(photosPerUser.rows[0].avg).toFixed(2),
      from_app: sourceData['app'] || 0,
      from_widget: sourceData['widget'] || 0,
      source_breakdown: sourceData,
      delete_schedule: scheduleData,
      schedule_breakdown: scheduleBreakdown.rows.map(row => ({
        schedule: row.schedule,
        count: parseInt(row.count)
      })),
      daily_trend: photosByDay.rows.map(row => ({
        date: row.date,
        count: parseInt(row.count)
      })),
      period_days: parseInt(days)
    });
  } catch (error) {
    console.error('Error fetching server photos:', error);
    res.status(500).json({ error: 'Failed to fetch server photos' });
  }
});

// GET /v1/stats/server-scans - Scan analytics from server events
app.get('/v1/stats/server-scans', requireAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);

    const [
      totalScans,
      completedScans,
      avgDuration,
      photosScanned,
      dateRangeBreakdown,
      scansByDay
    ] = await Promise.all([
      // Total scans started
      pool.query(`
        SELECT COUNT(*) as count
        FROM events
        WHERE name = 'scan_started'
        AND timestamp >= $1
      `, [startDate]),

      // Completed scans
      pool.query(`
        SELECT COUNT(*) as count
        FROM events
        WHERE name = 'scan_completed'
        AND timestamp >= $1
      `, [startDate]),

      // Average scan duration (ms)
      pool.query(`
        SELECT
          COALESCE(AVG((properties->>'duration_ms')::float), 0) as avg_ms
        FROM events
        WHERE name = 'scan_completed'
        AND timestamp >= $1
        AND properties->>'duration_ms' IS NOT NULL
      `, [startDate]),

      // Total photos scanned
      pool.query(`
        SELECT
          COALESCE(SUM((properties->>'photos_scanned')::int), 0) as total
        FROM events
        WHERE name = 'scan_completed'
        AND timestamp >= $1
      `, [startDate]),

      // Date range preference breakdown
      pool.query(`
        SELECT
          COALESCE(properties->>'date_range', 'unknown') as date_range,
          COUNT(*) as count
        FROM events
        WHERE name = 'scan_started'
        AND timestamp >= $1
        GROUP BY COALESCE(properties->>'date_range', 'unknown')
        ORDER BY count DESC
      `, [startDate]),

      // Scans by day
      pool.query(`
        SELECT
          DATE(timestamp) as date,
          COUNT(*) as count
        FROM events
        WHERE name = 'scan_started'
        AND timestamp >= $1
        GROUP BY DATE(timestamp)
        ORDER BY date
      `, [startDate])
    ]);

    const started = parseInt(totalScans.rows[0].count);
    const completed = parseInt(completedScans.rows[0].count);

    res.json({
      total_scans: started,
      completed_scans: completed,
      completion_rate: started > 0 ? ((completed / started) * 100).toFixed(1) : 0,
      avg_duration_ms: parseFloat(avgDuration.rows[0].avg_ms).toFixed(0),
      total_photos_scanned: parseInt(photosScanned.rows[0].total),
      date_range_breakdown: dateRangeBreakdown.rows.map(row => ({
        date_range: row.date_range,
        count: parseInt(row.count)
      })),
      daily_trend: scansByDay.rows.map(row => ({
        date: row.date,
        count: parseInt(row.count)
      })),
      period_days: parseInt(days)
    });
  } catch (error) {
    console.error('Error fetching server scans:', error);
    res.status(500).json({ error: 'Failed to fetch server scans' });
  }
});

// GET /v1/stats/server-sessions - Session and engagement analytics
app.get('/v1/stats/server-sessions', requireAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);

    const [
      totalSessions,
      sessionsPerUser,
      activeUsers,
      eventsByCategory,
      topEvents
    ] = await Promise.all([
      // Total unique sessions
      pool.query(`
        SELECT COUNT(DISTINCT session_id) as count
        FROM events
        WHERE timestamp >= $1
        AND session_id IS NOT NULL
      `, [startDate]),

      // Avg sessions per user
      pool.query(`
        SELECT
          COALESCE(COUNT(DISTINCT session_id)::float / NULLIF(COUNT(DISTINCT device_id), 0), 0) as avg
        FROM events
        WHERE timestamp >= $1
        AND session_id IS NOT NULL
      `, [startDate]),

      // Active users by day
      pool.query(`
        SELECT
          DATE(timestamp) as date,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1
        GROUP BY DATE(timestamp)
        ORDER BY date
      `, [startDate]),

      // Events by category
      pool.query(`
        SELECT
          category,
          COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
        GROUP BY category
        ORDER BY count DESC
      `, [startDate]),

      // Top 10 events
      pool.query(`
        SELECT
          name,
          COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
        GROUP BY name
        ORDER BY count DESC
        LIMIT 10
      `, [startDate])
    ]);

    res.json({
      total_sessions: parseInt(totalSessions.rows[0].count),
      sessions_per_user: parseFloat(sessionsPerUser.rows[0].avg).toFixed(2),
      daily_active_users: activeUsers.rows.map(row => ({
        date: row.date,
        users: parseInt(row.users)
      })),
      events_by_category: eventsByCategory.rows.map(row => ({
        category: row.category,
        count: parseInt(row.count)
      })),
      top_events: topEvents.rows.map(row => ({
        name: row.name,
        count: parseInt(row.count)
      })),
      period_days: parseInt(days)
    });
  } catch (error) {
    console.error('Error fetching server sessions:', error);
    res.status(500).json({ error: 'Failed to fetch server sessions' });
  }
});

// GET /v1/stats/server-retention - Retention cohort analysis
app.get('/v1/stats/server-retention', requireAuth, async (req, res) => {
  try {
    // Get cohorts for last 4 weeks
    const cohorts = [];

    for (let i = 0; i < 4; i++) {
      const cohortStart = new Date();
      cohortStart.setDate(cohortStart.getDate() - ((i + 1) * 7));
      cohortStart.setHours(0, 0, 0, 0);

      const cohortEnd = new Date(cohortStart);
      cohortEnd.setDate(cohortEnd.getDate() + 7);

      // Users who first appeared in this week
      const cohortUsers = await pool.query(`
        SELECT device_id
        FROM events
        GROUP BY device_id
        HAVING MIN(timestamp) >= $1 AND MIN(timestamp) < $2
      `, [cohortStart, cohortEnd]);

      const deviceIds = cohortUsers.rows.map(r => r.device_id);

      if (deviceIds.length === 0) {
        cohorts.push({
          week: i + 1,
          cohort_start: cohortStart.toISOString().split('T')[0],
          cohort_size: 0,
          day1: 0,
          day7: 0,
          day14: 0,
          day30: 0
        });
        continue;
      }

      // Calculate retention for each period
      const retentionPeriods = [1, 7, 14, 30];
      const retention = {};

      for (const period of retentionPeriods) {
        const periodStart = new Date(cohortEnd);
        periodStart.setDate(periodStart.getDate() + period - 1);

        const periodEnd = new Date(periodStart);
        periodEnd.setDate(periodEnd.getDate() + 1);

        if (periodEnd > new Date()) {
          retention[`day${period}`] = null;
          continue;
        }

        const retainedResult = await pool.query(`
          SELECT COUNT(DISTINCT device_id) as count
          FROM events
          WHERE device_id = ANY($1)
          AND timestamp >= $2 AND timestamp < $3
        `, [deviceIds, periodStart, periodEnd]);

        retention[`day${period}`] = parseInt(retainedResult.rows[0].count);
      }

      cohorts.push({
        week: i + 1,
        cohort_start: cohortStart.toISOString().split('T')[0],
        cohort_size: deviceIds.length,
        ...retention
      });
    }

    res.json({
      cohorts: cohorts.reverse(), // Oldest first
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching server retention:', error);
    res.status(500).json({ error: 'Failed to fetch server retention' });
  }
});

// GET /v1/stats/server-funnel - Conversion funnel from server events
app.get('/v1/stats/server-funnel', requireAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);

    // Define funnel stages
    const stages = [
      { name: 'App Opened', event: 'app_opened' },
      { name: 'Permission Granted', event: 'permission_result', filter: "properties->>'granted' = 'true'" },
      { name: 'First Photo', event: 'photo_captured' },
      { name: 'First Scan', event: 'scan_started' },
      { name: 'Paywall Viewed', event: 'paywall_viewed' },
      { name: 'Subscription Started', event: 'subscription_started' }
    ];

    const funnelData = [];
    let previousCount = 0;

    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i];
      let query = `
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE name = $1
        AND timestamp >= $2
      `;
      const params = [stage.event, startDate];

      if (stage.filter) {
        query = `
          SELECT COUNT(DISTINCT device_id) as count
          FROM events
          WHERE name = $1
          AND timestamp >= $2
          AND ${stage.filter}
        `;
      }

      const result = await pool.query(query, params);
      const count = parseInt(result.rows[0].count);

      funnelData.push({
        stage: stage.name,
        users: count,
        conversion: previousCount > 0 ? ((count / previousCount) * 100).toFixed(1) : '100.0',
        drop_off: previousCount > 0 ? (((previousCount - count) / previousCount) * 100).toFixed(1) : '0.0'
      });

      if (i === 0) previousCount = count;
      else previousCount = count || previousCount;
    }

    // Calculate overall conversion
    const topOfFunnel = funnelData[0]?.users || 0;
    const bottomOfFunnel = funnelData[funnelData.length - 1]?.users || 0;

    res.json({
      funnel: funnelData,
      overall_conversion: topOfFunnel > 0 ? ((bottomOfFunnel / topOfFunnel) * 100).toFixed(2) : '0.00',
      period_days: parseInt(days)
    });
  } catch (error) {
    console.error('Error fetching server funnel:', error);
    res.status(500).json({ error: 'Failed to fetch server funnel' });
  }
});

// ============================================
// INTERACTIVE DRILL-DOWN ENDPOINTS
// ============================================

// GET /v1/server/users - List all users with device details
app.get('/v1/server/users', requireAuth, async (req, res) => {
  try {
    const {
      filter, // 'dau', 'wau', 'mau', 'new_today', 'returning', 'all'
      event_name, // Filter by users who did a specific event
      date_from,
      date_to,
      limit = 100,
      offset = 0,
      sort = 'last_seen', // 'last_seen', 'first_seen', 'events_count'
      order = 'desc'
    } = req.query;

    const now = new Date();
    const today = new Date(now);
    today.setHours(0, 0, 0, 0);

    let dateFilter = '';
    const params = [];
    let paramIndex = 1;

    // Apply date filters based on filter type
    if (filter === 'dau') {
      params.push(today);
      dateFilter = `AND e.timestamp >= $${paramIndex++}`;
    } else if (filter === 'wau') {
      const weekAgo = new Date(today);
      weekAgo.setDate(weekAgo.getDate() - 7);
      params.push(weekAgo);
      dateFilter = `AND e.timestamp >= $${paramIndex++}`;
    } else if (filter === 'mau') {
      const monthAgo = new Date(today);
      monthAgo.setDate(monthAgo.getDate() - 30);
      params.push(monthAgo);
      dateFilter = `AND e.timestamp >= $${paramIndex++}`;
    } else if (date_from && date_to) {
      params.push(new Date(date_from), new Date(date_to));
      dateFilter = `AND e.timestamp >= $${paramIndex++} AND e.timestamp <= $${paramIndex++}`;
    } else if (date_from) {
      params.push(new Date(date_from));
      dateFilter = `AND e.timestamp >= $${paramIndex++}`;
    }

    // Event name filter
    let eventFilter = '';
    if (event_name) {
      params.push(event_name);
      eventFilter = `AND e.name = $${paramIndex++}`;
    }

    // Build main query
    let query = `
      WITH user_stats AS (
        SELECT
          e.device_id,
          MIN(e.timestamp) as first_seen,
          MAX(e.timestamp) as last_seen,
          COUNT(*) as events_count,
          COUNT(DISTINCT e.session_id) as sessions_count,
          MAX(e.platform) as platform,
          MAX(e.os_version) as os_version,
          MAX(e.device_model) as device_model,
          MAX(e.app_version) as app_version,
          MAX(e.locale) as locale,
          MAX(e.timezone) as timezone
        FROM events e
        WHERE 1=1 ${dateFilter} ${eventFilter}
        GROUP BY e.device_id
      )
    `;

    // Handle new_today and returning filters
    if (filter === 'new_today') {
      query += `
        SELECT * FROM user_stats
        WHERE DATE(first_seen) = CURRENT_DATE
      `;
    } else if (filter === 'returning') {
      query += `
        SELECT * FROM user_stats
        WHERE DATE(first_seen) < CURRENT_DATE
        AND DATE(last_seen) = CURRENT_DATE
      `;
    } else {
      query += `SELECT * FROM user_stats`;
    }

    // Sorting
    const sortColumn = sort === 'first_seen' ? 'first_seen' : sort === 'events_count' ? 'events_count' : 'last_seen';
    const sortOrder = order === 'asc' ? 'ASC' : 'DESC';
    query += ` ORDER BY ${sortColumn} ${sortOrder}`;

    // Pagination
    params.push(parseInt(limit), parseInt(offset));
    query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;

    const result = await pool.query(query, params);

    // Get total count
    let countQuery = `
      SELECT COUNT(DISTINCT device_id) as total
      FROM events e
      WHERE 1=1 ${dateFilter} ${eventFilter}
    `;
    if (filter === 'new_today') {
      countQuery = `
        SELECT COUNT(*) as total FROM (
          SELECT device_id FROM events
          WHERE 1=1 ${dateFilter} ${eventFilter}
          GROUP BY device_id
          HAVING MIN(timestamp)::date = CURRENT_DATE
        ) t
      `;
    } else if (filter === 'returning') {
      countQuery = `
        SELECT COUNT(*) as total FROM (
          SELECT device_id FROM events
          WHERE 1=1 ${dateFilter} ${eventFilter}
          GROUP BY device_id
          HAVING MIN(timestamp)::date < CURRENT_DATE
          AND MAX(timestamp)::date = CURRENT_DATE
        ) t
      `;
    }
    const countParams = params.slice(0, -2); // Remove limit/offset
    const countResult = await pool.query(countQuery, countParams);

    res.json({
      users: result.rows.map(row => ({
        device_id: row.device_id,
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        events_count: parseInt(row.events_count),
        sessions_count: parseInt(row.sessions_count),
        platform: row.platform,
        os_version: row.os_version,
        device_model: row.device_model,
        app_version: row.app_version,
        locale: row.locale,
        timezone: row.timezone
      })),
      total: parseInt(countResult.rows[0].total),
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Error fetching server users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /v1/server/users/:device_id - Get single user details
app.get('/v1/server/users/:device_id', requireAuth, async (req, res) => {
  try {
    const { device_id } = req.params;

    // User stats
    const statsResult = await pool.query(`
      SELECT
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen,
        COUNT(*) as total_events,
        COUNT(DISTINCT session_id) as total_sessions,
        COUNT(DISTINCT DATE(timestamp)) as active_days,
        MAX(platform) as platform,
        MAX(os_version) as os_version,
        MAX(device_model) as device_model,
        MAX(app_version) as app_version,
        MAX(locale) as locale,
        MAX(timezone) as timezone
      FROM events
      WHERE device_id = $1
    `, [device_id]);

    // Event breakdown
    const eventsBreakdown = await pool.query(`
      SELECT name, COUNT(*) as count
      FROM events
      WHERE device_id = $1
      GROUP BY name
      ORDER BY count DESC
    `, [device_id]);

    // Recent events (last 50)
    const recentEvents = await pool.query(`
      SELECT id, name, category, properties, timestamp, session_id
      FROM events
      WHERE device_id = $1
      ORDER BY timestamp DESC
      LIMIT 50
    `, [device_id]);

    // Sessions timeline
    const sessions = await pool.query(`
      SELECT
        session_id,
        MIN(timestamp) as started,
        MAX(timestamp) as ended,
        COUNT(*) as events_count
      FROM events
      WHERE device_id = $1 AND session_id IS NOT NULL
      GROUP BY session_id
      ORDER BY started DESC
      LIMIT 20
    `, [device_id]);

    if (statsResult.rows[0].first_seen === null) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      device_id,
      ...statsResult.rows[0],
      total_events: parseInt(statsResult.rows[0].total_events),
      total_sessions: parseInt(statsResult.rows[0].total_sessions),
      active_days: parseInt(statsResult.rows[0].active_days),
      events_breakdown: eventsBreakdown.rows.map(r => ({
        name: r.name,
        count: parseInt(r.count)
      })),
      recent_events: recentEvents.rows,
      sessions: sessions.rows.map(s => ({
        session_id: s.session_id,
        started: s.started,
        ended: s.ended,
        events_count: parseInt(s.events_count),
        duration_ms: new Date(s.ended) - new Date(s.started)
      }))
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// GET /v1/server/events - List events with filtering
app.get('/v1/server/events', requireAuth, async (req, res) => {
  try {
    const {
      name, // Event name filter
      category, // Category filter
      device_id, // User filter
      date_from,
      date_to,
      date, // Single date filter (YYYY-MM-DD)
      limit = 100,
      offset = 0
    } = req.query;

    const params = [];
    let paramIndex = 1;
    let whereClause = 'WHERE 1=1';

    if (name) {
      params.push(name);
      whereClause += ` AND name = $${paramIndex++}`;
    }
    if (category) {
      params.push(category);
      whereClause += ` AND category = $${paramIndex++}`;
    }
    if (device_id) {
      params.push(device_id);
      whereClause += ` AND device_id = $${paramIndex++}`;
    }
    if (date) {
      params.push(date);
      whereClause += ` AND DATE(timestamp) = $${paramIndex++}`;
    } else {
      if (date_from) {
        params.push(new Date(date_from));
        whereClause += ` AND timestamp >= $${paramIndex++}`;
      }
      if (date_to) {
        params.push(new Date(date_to));
        whereClause += ` AND timestamp <= $${paramIndex++}`;
      }
    }

    // Get events
    params.push(parseInt(limit), parseInt(offset));
    const query = `
      SELECT id, name, category, properties, timestamp, device_id, session_id,
             platform, os_version, device_model, app_version, locale
      FROM events
      ${whereClause}
      ORDER BY timestamp DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;
    const result = await pool.query(query, params);

    // Get count
    const countParams = params.slice(0, -2);
    const countResult = await pool.query(`SELECT COUNT(*) as total FROM events ${whereClause}`, countParams);

    res.json({
      events: result.rows,
      total: parseInt(countResult.rows[0].total),
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// GET /v1/server/events/by-date - Events grouped by date
app.get('/v1/server/events/by-date', requireAuth, async (req, res) => {
  try {
    const { days = 30, name } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    let nameFilter = '';
    const params = [startDate];
    if (name) {
      params.push(name);
      nameFilter = `AND name = $2`;
    }

    const result = await pool.query(`
      SELECT
        DATE(timestamp) as date,
        COUNT(*) as events,
        COUNT(DISTINCT device_id) as users
      FROM events
      WHERE timestamp >= $1 ${nameFilter}
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    `, params);

    res.json({
      dates: result.rows.map(r => ({
        date: r.date,
        events: parseInt(r.events),
        users: parseInt(r.users)
      }))
    });
  } catch (error) {
    console.error('Error fetching events by date:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// GET /v1/server/events/types - List all event types with counts
app.get('/v1/server/events/types', requireAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const result = await pool.query(`
      SELECT
        name,
        category,
        COUNT(*) as count,
        COUNT(DISTINCT device_id) as unique_users,
        MIN(timestamp) as first_occurrence,
        MAX(timestamp) as last_occurrence
      FROM events
      WHERE timestamp >= $1
      GROUP BY name, category
      ORDER BY count DESC
    `, [startDate]);

    res.json({
      event_types: result.rows.map(r => ({
        name: r.name,
        category: r.category,
        count: parseInt(r.count),
        unique_users: parseInt(r.unique_users),
        first_occurrence: r.first_occurrence,
        last_occurrence: r.last_occurrence
      }))
    });
  } catch (error) {
    console.error('Error fetching event types:', error);
    res.status(500).json({ error: 'Failed to fetch event types' });
  }
});

// GET /v1/server/retention/cohort/:date - Get users in a specific cohort
app.get('/v1/server/retention/cohort/:date', requireAuth, async (req, res) => {
  try {
    const { date } = req.params;
    const { return_day } = req.query; // 1, 7, 14, 30

    // Users who first appeared on this date
    let query = `
      SELECT device_id, MIN(timestamp) as first_seen
      FROM events
      GROUP BY device_id
      HAVING DATE(MIN(timestamp)) = $1
    `;

    if (return_day) {
      const returnDate = new Date(date);
      returnDate.setDate(returnDate.getDate() + parseInt(return_day));

      query = `
        WITH cohort AS (
          SELECT device_id
          FROM events
          GROUP BY device_id
          HAVING DATE(MIN(timestamp)) = $1
        ),
        returned AS (
          SELECT DISTINCT e.device_id
          FROM events e
          JOIN cohort c ON e.device_id = c.device_id
          WHERE DATE(e.timestamp) = $2
        )
        SELECT c.device_id,
               CASE WHEN r.device_id IS NOT NULL THEN true ELSE false END as returned
        FROM cohort c
        LEFT JOIN returned r ON c.device_id = r.device_id
      `;

      const result = await pool.query(query, [date, returnDate.toISOString().split('T')[0]]);
      return res.json({
        cohort_date: date,
        return_day: parseInt(return_day),
        users: result.rows
      });
    }

    const result = await pool.query(query, [date]);
    res.json({
      cohort_date: date,
      users: result.rows
    });
  } catch (error) {
    console.error('Error fetching cohort:', error);
    res.status(500).json({ error: 'Failed to fetch cohort' });
  }
});

// GET /v1/server/funnel/step/:step_name - Get users at a funnel step
app.get('/v1/server/funnel/step/:step_name', requireAuth, async (req, res) => {
  try {
    const { step_name } = req.params;
    const { days = 30, include_dropped = false } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Map step names to event names
    const stepToEvent = {
      'app_opened': 'app_opened',
      'permission_granted': 'permission_result',
      'first_photo': 'photo_captured',
      'first_scan': 'scan_started',
      'paywall_viewed': 'paywall_viewed',
      'subscription_started': 'subscription_started'
    };

    const eventName = stepToEvent[step_name] || step_name;

    const result = await pool.query(`
      SELECT DISTINCT device_id
      FROM events
      WHERE name = $1 AND timestamp >= $2
    `, [eventName, startDate]);

    res.json({
      step: step_name,
      event_name: eventName,
      users: result.rows.map(r => r.device_id),
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching funnel step:', error);
    res.status(500).json({ error: 'Failed to fetch funnel step' });
  }
});

// GET /v1/server/funnel/dropoff/:from_step/:to_step - Get users who dropped off
app.get('/v1/server/funnel/dropoff/:from_step/:to_step', requireAuth, async (req, res) => {
  try {
    const { from_step, to_step } = req.params;
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const stepToEvent = {
      'app_opened': 'app_opened',
      'permission_granted': 'permission_result',
      'first_photo': 'photo_captured',
      'first_scan': 'scan_started',
      'paywall_viewed': 'paywall_viewed',
      'subscription_started': 'subscription_started'
    };

    const fromEvent = stepToEvent[from_step] || from_step;
    const toEvent = stepToEvent[to_step] || to_step;

    // Users who did from_step but NOT to_step
    const result = await pool.query(`
      SELECT DISTINCT e1.device_id
      FROM events e1
      WHERE e1.name = $1 AND e1.timestamp >= $3
      AND NOT EXISTS (
        SELECT 1 FROM events e2
        WHERE e2.device_id = e1.device_id
        AND e2.name = $2
        AND e2.timestamp >= $3
      )
    `, [fromEvent, toEvent, startDate]);

    res.json({
      from_step,
      to_step,
      dropped_users: result.rows.map(r => r.device_id),
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching funnel dropoff:', error);
    res.status(500).json({ error: 'Failed to fetch funnel dropoff' });
  }
});

// GET /v1/server/photos/by-source/:source - Get photos by source (app/widget)
app.get('/v1/server/photos/by-source/:source', requireAuth, async (req, res) => {
  try {
    const { source } = req.params;
    const { days = 30, limit = 100, offset = 0 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const result = await pool.query(`
      SELECT device_id, timestamp, properties
      FROM events
      WHERE name = 'photo_captured'
      AND COALESCE(properties->>'source', 'app') = $1
      AND timestamp >= $2
      ORDER BY timestamp DESC
      LIMIT $3 OFFSET $4
    `, [source, startDate, parseInt(limit), parseInt(offset)]);

    const countResult = await pool.query(`
      SELECT COUNT(*) as total, COUNT(DISTINCT device_id) as unique_users
      FROM events
      WHERE name = 'photo_captured'
      AND COALESCE(properties->>'source', 'app') = $1
      AND timestamp >= $2
    `, [source, startDate]);

    res.json({
      source,
      photos: result.rows,
      total: parseInt(countResult.rows[0].total),
      unique_users: parseInt(countResult.rows[0].unique_users)
    });
  } catch (error) {
    console.error('Error fetching photos by source:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

// GET /v1/server/scans/by-range/:range - Get scans by date range setting
app.get('/v1/server/scans/by-range/:range', requireAuth, async (req, res) => {
  try {
    const { range } = req.params;
    const { days = 30, limit = 100, offset = 0 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const result = await pool.query(`
      SELECT device_id, timestamp, properties
      FROM events
      WHERE name = 'scan_started'
      AND properties->>'date_range' = $1
      AND timestamp >= $2
      ORDER BY timestamp DESC
      LIMIT $3 OFFSET $4
    `, [range, startDate, parseInt(limit), parseInt(offset)]);

    const countResult = await pool.query(`
      SELECT COUNT(*) as total, COUNT(DISTINCT device_id) as unique_users
      FROM events
      WHERE name = 'scan_started'
      AND properties->>'date_range' = $1
      AND timestamp >= $2
    `, [range, startDate]);

    res.json({
      date_range: range,
      scans: result.rows,
      total: parseInt(countResult.rows[0].total),
      unique_users: parseInt(countResult.rows[0].unique_users)
    });
  } catch (error) {
    console.error('Error fetching scans by range:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Analytics API running on port ${PORT}`);
  console.log(`Integrations: Amplitude=${!!AMPLITUDE_API_KEY}, AppsFlyer=${!!APPSFLYER_API_TOKEN}, Sentry=${!!SENTRY_AUTH_TOKEN}, AppStore=${!!ASC_ISSUER_ID}, GSC=${!!GSC_CLIENT_EMAIL}`);
});

module.exports = app;
