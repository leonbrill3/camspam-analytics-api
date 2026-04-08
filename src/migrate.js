const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function migrate() {
  const client = await pool.connect();

  try {
    console.log('Starting database migration...');

    // Create events table
    await client.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        category VARCHAR(50) NOT NULL DEFAULT 'engagement',
        properties JSONB DEFAULT '{}',
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        -- User/Device identification
        user_id VARCHAR(100),
        device_id VARCHAR(100) NOT NULL,
        session_id VARCHAR(100),
        session_duration_seconds INTEGER DEFAULT 0,

        -- App metadata
        app_version VARCHAR(20),
        build_number VARCHAR(20),
        platform VARCHAR(20) DEFAULT 'ios',
        os_version VARCHAR(20),
        device_model VARCHAR(50),
        locale VARCHAR(20),
        timezone VARCHAR(50),

        -- Timestamps
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('Created events table');

    // Create indexes for common queries
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_events_name_timestamp ON events(name, timestamp);
    `);
    console.log('Created indexes');

    // Create daily aggregates table for faster dashboard queries
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_stats (
        id SERIAL PRIMARY KEY,
        date DATE NOT NULL UNIQUE,
        total_events INTEGER DEFAULT 0,
        unique_devices INTEGER DEFAULT 0,
        new_devices INTEGER DEFAULT 0,
        photos_captured INTEGER DEFAULT 0,
        photos_deleted INTEGER DEFAULT 0,
        paywall_views INTEGER DEFAULT 0,
        purchases INTEGER DEFAULT 0,
        revenue DECIMAL(10, 2) DEFAULT 0,
        avg_session_duration INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('Created daily_stats table');

    // Create function to update daily stats
    await client.query(`
      CREATE OR REPLACE FUNCTION update_daily_stats(target_date DATE)
      RETURNS void AS $$
      BEGIN
        INSERT INTO daily_stats (
          date, total_events, unique_devices, photos_captured,
          photos_deleted, paywall_views, purchases, revenue
        )
        SELECT
          target_date,
          COUNT(*),
          COUNT(DISTINCT device_id),
          COUNT(*) FILTER (WHERE name = 'photo_captured'),
          COUNT(*) FILTER (WHERE name = 'photo_deleted'),
          COUNT(*) FILTER (WHERE name = 'paywall_viewed'),
          COUNT(*) FILTER (WHERE name = 'purchase_completed'),
          COALESCE(SUM((properties->>'revenue')::numeric) FILTER (WHERE name = 'purchase_completed'), 0)
        FROM events
        WHERE DATE(timestamp) = target_date
        ON CONFLICT (date) DO UPDATE SET
          total_events = EXCLUDED.total_events,
          unique_devices = EXCLUDED.unique_devices,
          photos_captured = EXCLUDED.photos_captured,
          photos_deleted = EXCLUDED.photos_deleted,
          paywall_views = EXCLUDED.paywall_views,
          purchases = EXCLUDED.purchases,
          revenue = EXCLUDED.revenue,
          updated_at = NOW();
      END;
      $$ LANGUAGE plpgsql;
    `);
    console.log('Created update_daily_stats function');

    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
