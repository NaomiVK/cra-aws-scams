# Emerging Threats Improvements

**Date:** December 13, 2025
**Status:** Implemented

## Overview

This document describes the improvements made to the Emerging Threats detection system in the CRA Scam Detection Dashboard. The changes enhance threat detection accuracy, add new detection signals (velocity and Google Trends), and improve the admin UI.

---

## Issues Fixed

### 1. Whitelist Not Filtering Emerging Threats

**Problem:** Adding terms to the whitelist cleared the cache but whitelisted terms still appeared in emerging threats. The code had a comment saying "We'll check this in the controller instead" but it was never implemented.

**Solution:** Added whitelist check directly in `analyzeTermForThreats()` method:
```typescript
// Skip if whitelisted
if (this.scamDetectionService.isWhitelisted(query)) {
  return null;
}
```

**Files Changed:**
- `apps/api/src/services/scam-detection.service.ts` - Made `isWhitelisted()` public
- `apps/api/src/services/emerging-threat.service.ts` - Added whitelist check

---

### 2. New Keywords Not Added to Embeddings

**Problem:** When adding keywords via the admin console, they only went to the runtime config for regex-based detection. The embedding cache (`seed-embeddings-v1`) was NOT invalidated, so new keywords had zero impact on semantic detection.

**Solution:**
1. Added `addSeedPhrase()` method to EmbeddingService that:
   - Adds term to runtime seedPhrases array
   - Persists to `seed-phrases.json` file
   - Invalidates embedding cache
   - Recomputes embeddings

2. Updated `addKeyword()` in ScamDetectionService to call `embeddingService.addSeedPhrase()`

**Files Changed:**
- `apps/api/src/services/embedding.service.ts` - Added `addSeedPhrase()` method
- `apps/api/src/services/scam-detection.service.ts` - Injected EmbeddingService, updated `addKeyword()`

---

### 3. Detection Thresholds Too Loose

**Problem:** Too many results were being shown, making it hard to focus on real threats.

**Changes:**
- `PAGE_SIZE`: 1000 → 500 (fewer items per page)
- `MAX_PAGES`: 5 → 10 (to still allow browsing all results)
- Embedding threshold: 0.75 → 0.80 (stricter semantic matching)

**File Changed:**
- `apps/api/src/services/emerging-threat.service.ts`

---

## New Features

### 4. Velocity Detection

**Concept:** Track how fast a term is growing (impressions per day). A term gaining 1000 impressions in 1 day is more concerning than one gaining 1000 impressions over 7 days.

**Implementation:**
```typescript
type VelocityMetrics = {
  impressionsPerDay: number;     // Average daily impression growth
  velocityScore: number;         // 0-1, normalized (500+ impressions/day = max)
  trend: 'accelerating' | 'steady' | 'decelerating';
};
```

**Trend Classification:**
- `accelerating`: New term OR >100% impression growth
- `steady`: Positive growth but <100%
- `decelerating`: Negative or no growth

**Files Changed:**
- `libs/shared-types/src/lib/scam-detection.types.ts` - Added `VelocityMetrics` type
- `apps/api/src/services/emerging-threat.service.ts` - Added `calculateVelocity()` method

---

### 5. Google Trends Integration

**Concept:** If a suspicious term is also trending on Google Trends, it's a stronger signal. Scam campaigns often cause spikes in both Search Console impressions AND public search interest.

**Implementation:**
```typescript
type TrendsData = {
  interest: number;          // 0-100 interest score
  trend: 'up' | 'down' | 'stable';
  changePercent: number;     // Recent change in interest
  isTrending: boolean;       // True if interest > 50 and trending up
};
```

**Behavior:**
- Only checks top 30 high-risk threats (score ≥50) to avoid rate limits
- Uses 7-day timeframe for emerging threat relevance
- Adds +10 risk score boost if term is actively trending
- 150ms delay between requests for rate limiting

**Files Changed:**
- `libs/shared-types/src/lib/scam-detection.types.ts` - Added `TrendsData` type
- `apps/api/src/services/emerging-threat.service.ts` - Added `enrichWithTrendsData()` method, injected TrendsService

---

### 6. Updated Risk Score Formula

**New Weights (with velocity):**

| Factor | Without Embedding | With Embedding |
|--------|-------------------|----------------|
| Embedding Match | — | 30% |
| CTR Anomaly | 35% | 22% |
| Position | 22% | 13% |
| Volume | 18% | 13% |
| Emergence | 13% | 10% |
| **Velocity** | **12%** | **12%** |

**Additional Boosts:**
- Pattern matches: +5 per pattern (max +20)
- Similar scams (no embedding): +5 per match (max +15)
- **Trending on Google Trends: +10**

**File Changed:**
- `apps/api/src/services/emerging-threat.service.ts` - Updated `calculateRiskScore()`

---

### 7. Admin UI Improvements

**New Table Columns:**

| Column | Description | Visual |
|--------|-------------|--------|
| Position | Average ranking position | `#.#` |
| Clicks | Click count | Number |
| Velocity | Impressions growth/day | `N ↑` (accelerating), `N →` (steady), `N ↓` (decelerating) |
| Trends | Google Trends interest | Badge with interest score + trend icon |

**Column Layout:**
```
Query | Risk | CTR Anomaly | Pos | Impr | Clicks | Velocity | Trends | Patterns | Actions
```

**Visual Indicators:**
- Velocity `accelerating`: Red up arrow (danger)
- Velocity `steady`: Yellow dash (warning)
- Velocity `decelerating`: Green down arrow (success)
- Trends `isTrending`: Red badge + up graph icon
- Trends stable: Gray badge + dash icon

**File Changed:**
- `apps/frontend/src/app/pages/admin/admin.component.html`

---

## Files Modified Summary

### Backend (API)

1. **`apps/api/src/services/emerging-threat.service.ts`**
   - Added whitelist check
   - Updated thresholds (PAGE_SIZE, embedding threshold)
   - Added velocity calculation
   - Added Google Trends enrichment
   - Updated risk score formula
   - Injected TrendsService

2. **`apps/api/src/services/scam-detection.service.ts`**
   - Made `isWhitelisted()` public
   - Injected EmbeddingService
   - Updated `addKeyword()` to sync with embeddings

3. **`apps/api/src/services/embedding.service.ts`**
   - Added `addSeedPhrase()` method
   - Persists to `seed-phrases.json`
   - Invalidates and recomputes embedding cache

4. **`apps/api/src/services/trends.service.ts`**
   - Minor lint fix (`let` → `const`)

### Shared Types

5. **`libs/shared-types/src/lib/scam-detection.types.ts`**
   - Added `VelocityMetrics` type
   - Added `TrendsData` type
   - Added optional `velocity` and `trendsData` fields to `EmergingThreat`

### Frontend

6. **`apps/frontend/src/app/pages/admin/admin.component.html`**
   - Added Position column
   - Added Clicks column
   - Added Velocity column with trend indicators
   - Added Trends column with interest score and icons
   - Updated About section with new formula

---

## Testing Checklist

- [ ] Add term to whitelist → Verify it disappears from emerging threats immediately
- [ ] Add term to scam keywords → Verify it appears in embedding comparisons (may take a moment for re-computation)
- [ ] Check emerging threats page shows ≤500 items per page
- [ ] Verify semantic matching uses 0.80 threshold
- [ ] Check Position and Clicks columns display correctly
- [ ] Check Velocity shows impressions/day with appropriate trend arrow
- [ ] Check Trends shows interest score with trend indicator (for high-risk items)
- [ ] Verify high-velocity terms get appropriate score boost
- [ ] Verify trending terms get +10 score boost

---

## Deployment Notes

1. Build shared-types first: `npx nx build shared-types`
2. Build API: `npx nx build api`
3. Build frontend: `npx nx build frontend`
4. Restart API service to pick up new code
5. The embedding cache will be invalidated on first keyword add

---

## DynamoDB Integration (Cloud Persistence)

**Date Added:** December 13, 2025

### Problem Solved

The original implementation wrote new seed phrases to `seed-phrases.json` on the local filesystem. This worked locally but had issues in cloud:
- Changes lost on redeployment (code overwrites `dist/` folder)
- Not shared across multiple instances (if scaling)
- Lost if instance terminates

### Solution

Added DynamoDB persistence for admin-added seed phrases:

1. **Table:** `cra-scam-seed-phrases`
   - Partition Key: `category` (String)
   - Sort Key: `term` (String)
   - Attributes: `severity`, `createdAt`

2. **Flow:**
   - On startup: Load from local `seed-phrases.json` THEN load from DynamoDB (merged)
   - On add keyword: Save to DynamoDB + add to memory + recompute embeddings

### Files Changed

1. **`apps/api/src/services/aws-config.service.ts`**
   - Added DynamoDB client initialization
   - Added `getDynamoDbClient()` method

2. **`apps/api/src/services/dynamodb.service.ts`** (NEW)
   - `getAllSeedPhrases()` - Scan table
   - `addSeedPhrase()` - Put item
   - `deleteSeedPhrase()` - Delete item

3. **`apps/api/src/services/embedding.service.ts`**
   - Inject `DynamoDbService`
   - Added `loadSeedPhrasesFromDynamoDB()` method
   - Updated `addSeedPhrase()` to persist to DynamoDB instead of file

4. **`apps/api/src/app/app.module.ts`**
   - Added `DynamoDbService` to providers

### AWS Setup Required

**1. Create DynamoDB Table:**
```bash
aws dynamodb create-table \
  --table-name cra-scam-seed-phrases \
  --attribute-definitions \
    AttributeName=category,AttributeType=S \
    AttributeName=term,AttributeType=S \
  --key-schema \
    AttributeName=category,KeyType=HASH \
    AttributeName=term,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-2
```

**2. Update IAM Policy:**

Add DynamoDB permissions to your EC2 instance role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:Scan",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-2:YOUR_ACCOUNT_ID:table/cra-scam-seed-phrases"
    }
  ]
}
```

Replace `YOUR_ACCOUNT_ID` with your AWS account ID (visible in console top-right).

---

## Future Improvements (Not Implemented)

1. **Geographic Anomaly Detection** - Track regional spikes
2. **Time-of-Day Patterns** - Scam campaigns often run at specific times
3. **Phone Number/Email Detection** - Flag queries containing contact patterns
4. **Historical Velocity** - Track acceleration/deceleration over multiple periods
5. **Batch Trends Lookup** - More efficient trends checking for large result sets
