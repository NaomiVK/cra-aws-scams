# CRA Scam Detection Dashboard

A monitoring dashboard that analyzes Google Search Console data to detect potential scam-related searches targeting Canada Revenue Agency (CRA) pages on canada.ca.

## What It Does

Detects searches for:
- **Fake/expired benefits** - "grocery rebate 2025", "CERB 2024"
- **Illegitimate payment methods** - "CRA gift card", "CRA bitcoin payment"
- **Threat language** - "CRA arrest warrant", "CRA deportation"
- **Suspicious modifiers** - "claim now", "limited time"

Uses CTR anomaly detection to identify when users are clicking scam sites instead of legitimate CRA pages.

## Tech Stack

- **Monorepo**: Nx 22.1.3
- **Backend**: NestJS 11 (TypeScript)
- **Frontend**: Angular 20 with Bootstrap/ng-bootstrap
- **Shared Types**: `libs/shared-types`
- **External APIs**: Google Search Console, Google Trends

## Project Structure

```
apps/
├── api/                    # NestJS backend (port 3000)
│   ├── controllers/        # REST endpoints
│   ├── services/           # Business logic
│   └── config/             # Keyword patterns
└── frontend/               # Angular frontend (port 4200)
    └── pages/
        ├── dashboard/      # Main KPI view
        ├── comparison/     # Period-over-period analysis
        ├── trends/         # Google Trends visualization
        ├── settings/       # Keyword management
        └── admin/          # Emerging threats

libs/
└── shared-types/           # Shared TypeScript types
```

## Quick Start

```bash
# Install dependencies
npm install

# Start both API and frontend
npm start

# Or run individually
npm run start:api        # Backend on http://localhost:3000
npm run start:frontend   # Frontend on http://localhost:4200
```

## Commands

```bash
# Development
npm start                 # Start all services
npm run start:api         # NestJS API only
npm run start:frontend    # Angular frontend only

# Build
npm run build             # Build all projects
npm run build:api
npm run build:frontend

# Quality
npm run lint              # Lint all projects
npm run test              # Run all tests

# Nx commands
npx nx serve api
npx nx serve frontend
npx nx build <project>
npx nx graph              # Visualize project dependencies
```

## Configuration

### Google Search Console Authentication

Create `service-account-credentials.json` at project root with a Google Cloud service account that has `webmasters.readonly` scope.

### Environment Variables

Create `.env` at project root:

```env
# Google Maps API (for regional interest maps)
GOOGLE_MAPS_API_KEY=your_key_here

# Optional: OpenRouter API (for future AI agent features)
OPENROUTER_API_KEY=your_key_here
```

### Scam Keywords

Configure detection patterns in `apps/api/src/config/scam-keywords.json`:
- Categories with severity levels (critical, high, medium, low)
- Contextual matching via `mustContain`
- Whitelist patterns for legitimate searches
- Seasonal multipliers for tax season

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/scams/dashboard` | Main dashboard data with KPIs and alerts |
| `GET /api/scams/detect` | Run scam detection for date range |
| `GET /api/scams/benchmarks` | Dynamic CTR benchmarks from Search Console |
| `GET /api/comparison/week-over-week` | Period comparison |
| `GET /api/trends/scam-keywords` | Google Trends for keywords |
| `GET /api/trends/region` | Interest by region data |
| `GET /api/export/csv` | Export flagged terms as CSV |
| `GET /api/export/excel` | Export as Excel |
| `GET /api/export/json` | Export as JSON |

## Future: AI Agent Architecture

See [PLAN.md](./PLAN.md) for detailed implementation plan for adding AI-powered agents:
- **Classification Agent** - Semantic query classification using LLM
- **Keyword Manager Agent** - Automated keyword database management
- **Report Generation Agent** - Natural language executive summaries
- **Anomaly Investigation Agent** - Autonomous CTR anomaly investigation

