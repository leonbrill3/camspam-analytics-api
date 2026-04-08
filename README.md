# CamSpam Analytics API

Backend API for CamSpam iOS app analytics. Deployed on Render.

## Quick Deploy to Render

1. Push this `backend/` folder to a GitHub repo
2. Go to [Render Dashboard](https://dashboard.render.com)
3. Click "New" > "Blueprint"
4. Connect your GitHub repo and select the `render.yaml` file
5. Render will create both the API and PostgreSQL database

## Manual Setup

### Local Development

```bash
# Install dependencies
npm install

# Set environment variable
export DATABASE_URL="postgresql://user:password@localhost:5432/camspam"

# Run migrations
npm run migrate

# Start server
npm run dev
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `PORT` | Server port (default: 3000) |
| `NODE_ENV` | Environment (development/production) |

## API Endpoints

### Events

#### POST /v1/events
Receive batch of events from iOS app.

```json
{
  "events": [
    {
      "name": "photo_captured",
      "category": "camera",
      "properties": { "schedule": "7_days", "spam_type": "camera" },
      "timestamp": "2024-01-15T10:30:00Z",
      "device_id": "abc123",
      "session_id": "session456",
      "app_version": "1.0.0"
    }
  ]
}
```

### Dashboard Stats

#### GET /v1/stats/overview
Get overview stats for dashboard.

Query params:
- `days` - Number of days to look back (default: 30)

Response:
```json
{
  "total_users": 1234,
  "daily_active_users": [{"date": "2024-01-15", "count": 456}],
  "total_events": 50000,
  "top_events": [{"name": "photo_captured", "count": 5000}],
  "revenue": {"total": 299.99, "purchases": 15}
}
```

#### GET /v1/stats/users
User analytics.

#### GET /v1/stats/features
Feature usage analytics.

#### GET /v1/stats/funnel
Conversion funnel from app open to purchase.

#### GET /v1/stats/realtime
Real-time stats (last hour).

## Database Schema

### events table
| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| name | VARCHAR(100) | Event name |
| category | VARCHAR(50) | Event category |
| properties | JSONB | Event properties |
| timestamp | TIMESTAMPTZ | When event occurred |
| device_id | VARCHAR(100) | Device identifier |
| session_id | VARCHAR(100) | Session identifier |
| app_version | VARCHAR(20) | App version |
| ... | ... | See migrate.js for full schema |

## Costs

- Render Starter API: $7/month
- Render Starter PostgreSQL: $7/month
- **Total: $14/month**

Can handle millions of events per month on starter plan.
