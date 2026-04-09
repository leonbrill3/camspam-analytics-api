const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const path = require('path');
const dns = require('dns');
const twilio = require('twilio');

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

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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

// ============================================
// DASHBOARD API
// ============================================

// GET /v1/stats/overview - Dashboard overview stats
app.get('/v1/stats/overview', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [
      totalUsers,
      dailyActiveUsers,
      totalEvents,
      topEvents,
      revenue
    ] = await Promise.all([
      // Total unique devices (users)
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1
      `, [startDate.toISOString()]),

      // Daily active users (last 7 days trend)
      pool.query(`
        SELECT DATE(timestamp) as date, COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
      `),

      // Total events
      pool.query(`
        SELECT COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
      `, [startDate.toISOString()]),

      // Top 10 events by count
      pool.query(`
        SELECT name, COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
        GROUP BY name
        ORDER BY count DESC
        LIMIT 10
      `, [startDate.toISOString()]),

      // Revenue from purchase events
      pool.query(`
        SELECT
          COALESCE(SUM((properties->>'revenue')::numeric), 0) as total_revenue,
          COUNT(*) as purchase_count
        FROM events
        WHERE name = 'purchase_completed'
        AND timestamp >= $1
      `, [startDate.toISOString()])
    ]);

    res.json({
      total_users: parseInt(totalUsers.rows[0].count),
      daily_active_users: dailyActiveUsers.rows.map(r => ({
        date: r.date,
        count: parseInt(r.count)
      })),
      total_events: parseInt(totalEvents.rows[0].count),
      top_events: topEvents.rows.map(r => ({
        name: r.name,
        count: parseInt(r.count)
      })),
      revenue: {
        total: parseFloat(revenue.rows[0].total_revenue),
        purchases: parseInt(revenue.rows[0].purchase_count)
      }
    });
  } catch (error) {
    console.error('Error fetching overview:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /v1/stats/users - User analytics
app.get('/v1/stats/users', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [
      newUsers,
      usersByTier,
      userRetention,
      avgSessionDuration
    ] = await Promise.all([
      // New users per day
      pool.query(`
        SELECT DATE(MIN(timestamp)) as first_seen, COUNT(DISTINCT device_id) as count
        FROM events
        GROUP BY device_id
        HAVING DATE(MIN(timestamp)) >= $1
        ORDER BY first_seen DESC
      `, [startDate.toISOString()]),

      // Users by subscription tier
      pool.query(`
        SELECT
          COALESCE(properties->>'tier', 'free') as tier,
          COUNT(DISTINCT device_id) as count
        FROM events
        WHERE name IN ('purchase_completed', 'subscription_expired', 'app_opened')
        AND timestamp >= $1
        GROUP BY COALESCE(properties->>'tier', 'free')
      `, [startDate.toISOString()]),

      // Session counts per user (engagement proxy)
      pool.query(`
        SELECT
          CASE
            WHEN session_count = 1 THEN '1 session'
            WHEN session_count BETWEEN 2 AND 5 THEN '2-5 sessions'
            WHEN session_count BETWEEN 6 AND 10 THEN '6-10 sessions'
            ELSE '10+ sessions'
          END as bucket,
          COUNT(*) as user_count
        FROM (
          SELECT device_id, COUNT(DISTINCT session_id) as session_count
          FROM events
          WHERE timestamp >= $1
          GROUP BY device_id
        ) user_sessions
        GROUP BY bucket
      `, [startDate.toISOString()]),

      // Average session duration
      pool.query(`
        SELECT AVG(max_duration) as avg_duration
        FROM (
          SELECT session_id, MAX(session_duration_seconds) as max_duration
          FROM events
          WHERE timestamp >= $1 AND session_duration_seconds > 0
          GROUP BY session_id
        ) sessions
      `, [startDate.toISOString()])
    ]);

    res.json({
      new_users_by_day: newUsers.rows,
      users_by_tier: usersByTier.rows,
      engagement_buckets: userRetention.rows,
      avg_session_duration_seconds: parseFloat(avgSessionDuration.rows[0].avg_duration) || 0
    });
  } catch (error) {
    console.error('Error fetching user stats:', error);
    res.status(500).json({ error: 'Failed to fetch user stats' });
  }
});

// GET /v1/stats/features - Feature usage analytics
app.get('/v1/stats/features', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [
      photosCaptured,
      photosDeleted,
      scheduleDistribution,
      spamTypeDistribution,
      featureUsage
    ] = await Promise.all([
      // Photos captured over time
      pool.query(`
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
      `, [startDate.toISOString()]),

      // Photos deleted (manual vs auto)
      pool.query(`
        SELECT
          properties->>'was_manual' as was_manual,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_deleted' AND timestamp >= $1
        GROUP BY properties->>'was_manual'
      `, [startDate.toISOString()]),

      // Delete schedule distribution
      pool.query(`
        SELECT
          properties->>'delete_schedule' as schedule,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1
        GROUP BY properties->>'delete_schedule'
      `, [startDate.toISOString()]),

      // Spam type distribution
      pool.query(`
        SELECT
          properties->>'spam_type' as spam_type,
          COUNT(*) as count
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1
        GROUP BY properties->>'spam_type'
      `, [startDate.toISOString()]),

      // Feature toggles
      pool.query(`
        SELECT
          properties->>'feature' as feature,
          SUM(CASE WHEN (properties->>'enabled')::boolean THEN 1 ELSE 0 END) as enabled_count,
          SUM(CASE WHEN NOT (properties->>'enabled')::boolean THEN 1 ELSE 0 END) as disabled_count
        FROM events
        WHERE name = 'feature_toggled' AND timestamp >= $1
        GROUP BY properties->>'feature'
      `, [startDate.toISOString()])
    ]);

    res.json({
      photos_captured_by_day: photosCaptured.rows,
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
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [
      appOpens,
      cameraOpens,
      photoCaptured,
      paywallViews,
      purchaseStarted,
      purchaseCompleted
    ] = await Promise.all([
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'app_opened' AND timestamp >= $1`, [startDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'camera_opened' AND timestamp >= $1`, [startDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'photo_captured' AND timestamp >= $1`, [startDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'paywall_viewed' AND timestamp >= $1`, [startDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'purchase_started' AND timestamp >= $1`, [startDate.toISOString()]),
      pool.query(`SELECT COUNT(DISTINCT device_id) as count FROM events WHERE name = 'purchase_completed' AND timestamp >= $1`, [startDate.toISOString()])
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

// GET /v1/stats/realtime - Real-time stats (last hour)
app.get('/v1/stats/realtime', async (req, res) => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const [activeUsers, recentEvents, eventsByMinute] = await Promise.all([
      // Active users in last hour
      pool.query(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM events
        WHERE timestamp >= $1
      `, [oneHourAgo]),

      // Most recent events
      pool.query(`
        SELECT name, timestamp, device_id, properties
        FROM events
        WHERE timestamp >= $1
        ORDER BY timestamp DESC
        LIMIT 50
      `, [oneHourAgo]),

      // Events per minute
      pool.query(`
        SELECT
          DATE_TRUNC('minute', timestamp) as minute,
          COUNT(*) as count
        FROM events
        WHERE timestamp >= $1
        GROUP BY DATE_TRUNC('minute', timestamp)
        ORDER BY minute DESC
      `, [oneHourAgo])
    ]);

    res.json({
      active_users: parseInt(activeUsers.rows[0].count),
      recent_events: recentEvents.rows,
      events_per_minute: eventsByMinute.rows
    });
  } catch (error) {
    console.error('Error fetching realtime stats:', error);
    res.status(500).json({ error: 'Failed to fetch realtime stats' });
  }
});

// GET /v1/stats/retention - Retention cohort analysis
app.get('/v1/stats/retention', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Get cohort data: users who first appeared on each day and their return rates
    const cohortQuery = await pool.query(`
      WITH user_first_seen AS (
        SELECT
          device_id,
          DATE(MIN(timestamp)) as cohort_date
        FROM events
        WHERE timestamp >= $1
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
        WHERE e.timestamp >= $1
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
    `, [startDate.toISOString()]);

    // Calculate overall retention rates
    const overallRetention = await pool.query(`
      WITH user_first_seen AS (
        SELECT
          device_id,
          DATE(MIN(timestamp)) as cohort_date
        FROM events
        WHERE timestamp >= $1
        GROUP BY device_id
      ),
      retention_data AS (
        SELECT
          ufs.device_id,
          ufs.cohort_date,
          MAX(DATE(e.timestamp) - ufs.cohort_date) as max_days_retained
        FROM user_first_seen ufs
        LEFT JOIN events e ON ufs.device_id = e.device_id
        WHERE e.timestamp >= $1
        GROUP BY ufs.device_id, ufs.cohort_date
      )
      SELECT
        COUNT(DISTINCT device_id) as total_users,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 1 THEN device_id END) as d1_retained,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 7 THEN device_id END) as d7_retained,
        COUNT(DISTINCT CASE WHEN max_days_retained >= 30 THEN device_id END) as d30_retained
      FROM retention_data
    `, [startDate.toISOString()]);

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
    const { days = 30, limit = 100 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [recentEvents, eventSummary, mrr, churnData] = await Promise.all([
      // Recent RevenueCat events
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

      // MRR calculation (simplified - sum of monthly equivalent revenue)
      pool.query(`
        SELECT
          COALESCE(SUM(
            CASE
              WHEN period_type = 'MONTHLY' THEN price * (takehome_percentage / 100)
              WHEN period_type = 'ANNUAL' THEN (price / 12) * (takehome_percentage / 100)
              ELSE 0
            END
          ), 0) as mrr,
          COUNT(DISTINCT app_user_id) as active_subscribers
        FROM revenuecat_events
        WHERE event_type IN ('INITIAL_PURCHASE', 'RENEWAL')
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
      `, [startDate.toISOString()])
    ]);

    res.json({
      recent_events: recentEvents.rows,
      event_summary: eventSummary.rows,
      mrr: {
        value: parseFloat(mrr.rows[0].mrr) || 0,
        active_subscribers: parseInt(mrr.rows[0].active_subscribers) || 0
      },
      churn_by_day: churnData.rows
    });
  } catch (error) {
    console.error('Error fetching RevenueCat events:', error);
    res.status(500).json({ error: 'Failed to fetch RevenueCat events' });
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
      limit = 50,
      offset = 0,
      search = '',
      filter = 'all', // all, purchasers, active, churned
      sort = 'last_active', // last_active, first_seen, events, purchases
      order = 'desc'
    } = req.query;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

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
    }

    let searchClause = '';
    if (search) {
      searchClause = `AND (device_id ILIKE $4 OR user_id ILIKE $4)`;
    }

    const orderColumn = {
      'last_active': 'last_active',
      'first_seen': 'first_seen',
      'events': 'total_events',
      'purchases': 'purchase_count'
    }[sort] || 'last_active';

    const orderDir = order === 'asc' ? 'ASC' : 'DESC';

    const params = [startDate.toISOString(), parseInt(limit), parseInt(offset)];
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
        WHERE timestamp >= $1
        GROUP BY device_id, user_id
      ),
      purchase_stats AS (
        SELECT
          device_id,
          COUNT(*) as purchase_count,
          SUM((properties->>'revenue')::numeric) as total_revenue
        FROM events
        WHERE name = 'purchase_completed' AND timestamp >= $1
        GROUP BY device_id
      ),
      camera_stats AS (
        SELECT
          device_id,
          COUNT(*) as photos_captured
        FROM events
        WHERE name = 'photo_captured' AND timestamp >= $1
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
      LIMIT $2 OFFSET $3
    `, params);

    // Get total count for pagination
    const countParams = [startDate.toISOString()];
    if (search) countParams.push(`%${search}%`);

    const countQuery = await pool.query(`
      WITH user_stats AS (
        SELECT
          device_id,
          MAX(timestamp) as last_active
        FROM events
        WHERE timestamp >= $1
        GROUP BY device_id
      )
      SELECT COUNT(*) as total
      FROM user_stats
      WHERE 1=1 ${filterClause} ${search ? 'AND device_id ILIKE $2' : ''}
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
    const { days = 30, limit = 100, offset = 0 } = req.query;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const usersQuery = await pool.query(`
      WITH event_users AS (
        SELECT
          device_id,
          COUNT(*) as event_count,
          MIN(timestamp) as first_occurrence,
          MAX(timestamp) as last_occurrence,
          MAX(properties) as last_properties
        FROM events
        WHERE name = $1 AND timestamp >= $2
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
      LIMIT $3 OFFSET $4
    `, [event_name, startDate.toISOString(), parseInt(limit), parseInt(offset)]);

    const countQuery = await pool.query(`
      SELECT COUNT(DISTINCT device_id) as total
      FROM events
      WHERE name = $1 AND timestamp >= $2
    `, [event_name, startDate.toISOString()]);

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

// GET /v1/stats/acquisition - Attribution and acquisition analytics
app.get('/v1/stats/acquisition', async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const [
      installsByDay,
      installsBySource,
      organicVsPaid,
      deviceBreakdown,
      geoBreakdown,
      timezoneBreakdown,
      languageBreakdown,
      osBreakdown
    ] = await Promise.all([
      // New installs by day
      pool.query(`
        WITH first_events AS (
          SELECT device_id, MIN(timestamp) as first_seen
          FROM events
          GROUP BY device_id
        )
        SELECT DATE(first_seen) as date, COUNT(*) as installs
        FROM first_events
        WHERE first_seen >= $1
        GROUP BY DATE(first_seen)
        ORDER BY date DESC
      `, [startDate.toISOString()]),

      // Installs by attribution source
      pool.query(`
        WITH first_events AS (
          SELECT device_id, MIN(timestamp) as first_seen,
                 (SELECT properties->>'source' FROM events e2
                  WHERE e2.device_id = events.device_id
                  AND e2.name = 'app_opened'
                  ORDER BY timestamp LIMIT 1) as source
          FROM events
          GROUP BY device_id
        )
        SELECT COALESCE(source, 'organic') as source, COUNT(*) as installs
        FROM first_events
        WHERE first_seen >= $1
        GROUP BY source
        ORDER BY installs DESC
      `, [startDate.toISOString()]),

      // Organic vs Paid
      pool.query(`
        WITH first_events AS (
          SELECT device_id, MIN(timestamp) as first_seen,
                 (SELECT properties->>'is_organic' FROM events e2
                  WHERE e2.device_id = events.device_id
                  AND e2.name = 'app_opened'
                  ORDER BY timestamp LIMIT 1) as is_organic
          FROM events
          GROUP BY device_id
        )
        SELECT
          COUNT(CASE WHEN is_organic = 'true' OR is_organic IS NULL THEN 1 END) as organic,
          COUNT(CASE WHEN is_organic = 'false' THEN 1 END) as paid
        FROM first_events
        WHERE first_seen >= $1
      `, [startDate.toISOString()]),

      // Device model breakdown
      pool.query(`
        SELECT device_model, COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND device_model IS NOT NULL
        GROUP BY device_model
        ORDER BY users DESC
        LIMIT 10
      `, [startDate.toISOString()]),

      // Geographic breakdown by locale/timezone
      pool.query(`
        SELECT
          COALESCE(NULLIF(SPLIT_PART(locale, '_', 2), ''), locale, 'Unknown') as country,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND locale IS NOT NULL
        GROUP BY country
        ORDER BY users DESC
        LIMIT 10
      `, [startDate.toISOString()]),

      // Timezone distribution
      pool.query(`
        SELECT
          timezone,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND timezone IS NOT NULL
        GROUP BY timezone
        ORDER BY users DESC
        LIMIT 15
      `, [startDate.toISOString()]),

      // Language breakdown
      pool.query(`
        SELECT
          COALESCE(SPLIT_PART(locale, '_', 1), 'unknown') as language,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND locale IS NOT NULL
        GROUP BY language
        ORDER BY users DESC
        LIMIT 10
      `, [startDate.toISOString()]),

      // OS version breakdown
      pool.query(`
        SELECT
          os_version,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND os_version IS NOT NULL
        GROUP BY os_version
        ORDER BY users DESC
        LIMIT 10
      `, [startDate.toISOString()])
    ]);

    res.json({
      installs_by_day: installsByDay.rows,
      installs_by_source: installsBySource.rows,
      organic_vs_paid: organicVsPaid.rows[0] || { organic: 0, paid: 0 },
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

// Start server
app.listen(PORT, () => {
  console.log(`Analytics API running on port ${PORT}`);
});

module.exports = app;
