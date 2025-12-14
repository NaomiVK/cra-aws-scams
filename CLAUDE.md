# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CRA Scam Detection Dashboard - monitors Google Search Console data for potential scam-related searches targeting Canada Revenue Agency (CRA) pages on canada.ca. Detects searches for fake benefits, illegitimate payment methods, and threat language that indicate scam activity.

## Commands

```bash
# Development - starts both API (port 3000) and frontend (port 4200)
npm start

# Individual services
npm run start:api        # NestJS API only
npm run start:frontend   # Angular frontend only

# Build
npm run build            # Build all projects
npm run build:api
npm run build:frontend

# Lint and test
npm run lint             # Lint all projects
npm run test             # Run all tests

# Nx commands
npx nx serve api
npx nx serve frontend
npx nx build <project>
npx nx lint <project>
npx nx test <project>
```

## Architecture

### Nx Monorepo Structure

- **apps/api** - NestJS backend (port 3000)
- **apps/frontend** - Angular 20 frontend with Bootstrap/ng-bootstrap (port 4200)
- **libs/shared-types** - Shared TypeScript types between frontend and API

### Backend Services (apps/api/src/services/)

- **SearchConsoleService** - Google Search Console API integration, fetches search analytics filtered to CRA URLs
- **ScamDetectionService** - Matches search queries against configurable keyword patterns with contextual matching (e.g., "cra" + "gift card")
- **ComparisonService** - Period-over-period analysis for detecting trends
- **TrendsService** - Google Trends API integration for monitoring scam keyword popularity
- **CacheService** - In-memory caching with node-cache

### API Endpoints (apps/api/src/controllers/)

- `/api/scams/dashboard` - Main dashboard data with KPIs and alerts
- `/api/scams/detect` - Run scam detection for date range
- `/api/comparison/week-over-week` - Week-over-week comparison
- `/api/trends/scam-keywords` - Google Trends for monitored keywords
- `/api/export/csv`, `/api/export/excel`, `/api/export/json` - Export flagged terms

### Frontend Pages (apps/frontend/src/app/pages/)

- **dashboard** - Main view with KPI cards, alerts panel, flagged terms table
- **comparison** - Period-over-period analysis
- **trends** - Google Trends visualization
- **settings** - Keyword configuration management

### Configuration

**Scam keywords** are configured in `apps/api/src/config/scam-keywords.json`:
- Categories with severity levels (critical, high, medium, low)
- Contextual matching via `mustContain` (term must appear with CRA-related words)
- Whitelist patterns for legitimate searches
- Seasonal multipliers for tax season and payment dates

**Environment config** in `apps/api/src/environments/environment.ts`:
- `impressionThreshold`: Minimum impressions to flag (default 500)
- `craUrlFilters`: URL patterns for CRA pages on canada.ca

### Authentication

Requires Google Cloud service account credentials at project root:
- File: `service-account-credentials.json`
- Scope: `webmasters.readonly` for Search Console API

## Code Conventions

- Use `type` instead of `interface` for type definitions
- Shared types go in `libs/shared-types`
- Import types from `@cra-scam-detection/shared-types`

## Known Issues & Workarounds

### File Editing Issues
VS Code extensions may modify files between Read and Edit operations, causing "File has been unexpectedly modified" errors.

**Workaround**: Use `sed` via Bash for quick edits:
```bash
sed -i 's/old/new/' path/to/file
```

### Shell Escaping with $ Characters
When writing Angular templates via bash heredocs or node scripts, `$` characters get stripped (interpreted as shell variables).

**Affected patterns**:
- `$event` in `(ngModelChange)="signal.set($event)"`
- `$index` in `@for` loops: `let i = $index`

**Workaround**: Use `sed` with hex codes:
```bash
sed -i 's/let i = )/let i = \x24index)/' file.html
```

### Stopping Nx Dev Server
The Nx dev server (`npm start`) may not respond to single Ctrl+C on Windows.
- Press Ctrl+C multiple times, or
- Close the terminal entirely, or
- Run `taskkill /F /IM node.exe` (WARNING: kills ALL node processes)

## Dependencies Added

### Frontend
- `apexcharts` + `ng-apexcharts` - Charting library for trends visualization

## Trends Page Features

The trends page (`/trends`) supports:
- **Time period selection**: Past hour, 4 hours, day, 7 days, 30 days, 90 days, 12 months, 5 years
- **Single phrase search**: Input is treated as one search term (e.g., "cra rent relief")
- **ApexCharts visualization**: Area chart showing interest over time
- **Stats cards**: Peak Interest, Average Interest, Data Points
- **Related queries**: Shows related search terms from Google Trends

### Time Range Values (Google Trends API)
- `now 1-H` - Past hour
- `now 4-H` - Past 4 hours
- `now 1-d` - Past day
- `now 7-d` - Past 7 days
- `today 1-m` - Past 30 days
- `today 3-m` - Past 90 days
- `today 12-m` - Past 12 months
- `today 5-y` - Past 5 years

### Interest by Region (Google Charts GeoChart)
- Displays interactive map of Canada showing search interest by province
- Uses Google Charts GeoChart (same as Google Trends uses)
- Requires Google Maps API key configured in `.env`

## Environment Variables

Create a `.env` file at project root with:
```
GOOGLE_MAPS_API_KEY=your_api_key_here
```

The API key is:
- Loaded by the backend via dotenv in `main.ts`
- Served to frontend via `GET /api/config/maps-key`
- Used by Google Charts GeoChart for map rendering

To get a Google Maps API key:
1. Go to https://console.cloud.google.com/apis/credentials
2. Create or select a project
3. Enable "Maps JavaScript API"
4. Create an API key
5. (Optional) Restrict to HTTP referrers: `http://localhost:4200/*`

## API Endpoints Added (2025-12-05)

- `/api/config/maps-key` - Returns Google Maps API key for frontend
- `/api/trends/region` - Returns interest by region data for a keyword
- `/api/scams/benchmarks` - Returns dynamic CTR benchmarks calculated from Search Console data

## Dynamic CTR Benchmarks

The emerging threat detection uses dynamic CTR benchmarks calculated from actual Search Console data:
- Position 1-3: Expected ~20% CTR
- Position 4-8: Expected ~10% CTR
- Position 9-15: Expected ~5% CTR
- Position 16+: Expected ~2% CTR

Low CTR at good position = users clicking scam sites instead of CRA pages (key signal for scam detection)
