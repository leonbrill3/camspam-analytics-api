const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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
      geoBreakdown
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
          COALESCE(SPLIT_PART(locale, '_', 2), locale, 'Unknown') as country,
          COUNT(DISTINCT device_id) as users
        FROM events
        WHERE timestamp >= $1 AND locale IS NOT NULL
        GROUP BY country
        ORDER BY users DESC
        LIMIT 10
      `, [startDate.toISOString()])
    ]);

    res.json({
      installs_by_day: installsByDay.rows,
      installs_by_source: installsBySource.rows,
      organic_vs_paid: organicVsPaid.rows[0] || { organic: 0, paid: 0 },
      device_breakdown: deviceBreakdown.rows,
      geo_breakdown: geoBreakdown.rows
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
