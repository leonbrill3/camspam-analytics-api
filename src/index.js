const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));

// Rate limiting - 1000 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests' }
});
app.use('/v1/events', limiter);

// Root route
app.get('/', (req, res) => {
  res.json({
    name: 'CamSpam Analytics API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      events: 'POST /v1/events',
      stats: {
        overview: '/v1/stats/overview',
        users: '/v1/stats/users',
        features: '/v1/stats/features',
        funnel: '/v1/stats/funnel',
        realtime: '/v1/stats/realtime'
      }
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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

// Start server
app.listen(PORT, () => {
  console.log(`Analytics API running on port ${PORT}`);
});

module.exports = app;
