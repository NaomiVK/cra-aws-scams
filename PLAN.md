# Agentic Architecture Implementation Plan for CRA Scam Detection Dashboard

> **Purpose**: This document provides a comprehensive, step-by-step implementation guide for adding AI-powered agentic workflows to the CRA Scam Detection Dashboard. It is designed to be self-contained so that a future Claude session can implement it without additional context.

---

## Table of Contents

1. [Project Context](#project-context)
2. [Current Architecture Overview](#current-architecture-overview)
3. [Proposed Agents](#proposed-agents)
4. [Technical Architecture](#technical-architecture)
5. [Detailed Implementation Guide](#detailed-implementation-guide)
6. [Type Definitions](#type-definitions)
7. [Service Implementations](#service-implementations)
8. [Controller Implementations](#controller-implementations)
9. [Frontend Components](#frontend-components)
10. [Integration Points](#integration-points)
11. [Testing Strategy](#testing-strategy)
12. [Deployment Checklist](#deployment-checklist)

---

## Project Context

### What This Project Does
The CRA Scam Detection Dashboard monitors Google Search Console data for potential scam-related searches targeting Canada Revenue Agency (CRA) pages on canada.ca. It detects:
- Fake/expired benefits (e.g., "grocery rebate 2025", "CERB 2024")
- Illegitimate payment methods (e.g., "CRA gift card", "CRA bitcoin payment")
- Threat language (e.g., "CRA arrest warrant", "CRA deportation")
- Suspicious modifiers (e.g., "claim now", "limited time")

### Project Location
```
F:\vscode_projects\vs-code-projects\google_search\cra-scam-detection\
```

### Technology Stack
- **Monorepo**: Nx 22.1.3
- **Backend**: NestJS 11 (TypeScript)
- **Frontend**: Angular 20 with Bootstrap/ng-bootstrap
- **Shared Types**: `libs/shared-types`
- **External APIs**: Google Search Console, Google Trends

### Current Limitations (Why We Need Agents)
1. **Rule-based only**: Cannot understand semantic meaning or context
2. **Manual keyword management**: Humans must add new patterns
3. **No explanation**: Cannot explain *why* a term is flagged
4. **False positives**: Legitimate searches match patterns
5. **Slow adaptation**: New scam patterns require manual config changes

---

## Current Architecture Overview

### Backend Structure
```
apps/api/src/
├── main.ts                          # Entry point, loads dotenv
├── app/
│   ├── app.module.ts                # NestJS module registration
│   ├── app.controller.ts
│   └── app.service.ts
├── controllers/
│   ├── analytics.controller.ts
│   ├── scams.controller.ts          # Main scam detection endpoints
│   ├── comparison.controller.ts
│   ├── trends.controller.ts
│   ├── export.controller.ts
│   └── config.controller.ts
├── services/
│   ├── search-console.service.ts    # Google Search Console API
│   ├── scam-detection.service.ts    # Pattern matching (309 lines)
│   ├── emerging-threat.service.ts   # CTR anomaly detection (210 lines)
│   ├── comparison.service.ts
│   ├── trends.service.ts            # Google Trends API
│   └── cache.service.ts             # node-cache wrapper
├── config/
│   └── scam-keywords.json           # Keyword configuration (320+ lines)
└── environments/
    ├── environment.ts
    └── environment.prod.ts
```

### Frontend Structure
```
apps/frontend/src/app/
├── app.ts                           # Root component
├── app.routes.ts                    # Route configuration
├── app.config.ts
├── services/
│   └── api.service.ts               # HTTP client
└── pages/
    ├── dashboard/                   # Main KPI view
    ├── comparison/                  # Period comparison
    ├── trends/                      # Google Trends visualization
    ├── settings/                    # Keyword management
    ├── admin/                       # Emerging threats (new)
    └── social/                      # Placeholder
```

### Shared Types
```
libs/shared-types/src/lib/
├── scam-detection.types.ts          # FlaggedTerm, Severity, etc.
├── search-analytics.types.ts        # SearchAnalyticsRow, etc.
└── trends.types.ts                  # TrendDataPoint, etc.
```

### Key Existing Types (Reference)
```typescript
// From scam-detection.types.ts
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

type FlaggedTerm = {
  query: string;
  severity: Severity;
  matchedPatterns: string[];
  matchedCategory: string;
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
  firstSeen?: string;
  status: FlaggedTermStatus;
};

type FlaggedTermStatus = 'new' | 'active' | 'reviewed' | 'dismissed' | 'escalated';

type EmergingThreat = {
  id: string;
  query: string;
  riskScore: number;            // 0-100
  riskLevel: RiskLevel;
  indicators: string[];
  patternMatches: string[];
  ctrAnomaly?: CTRAnomaly;
  similarScams: string[];
  firstSeen: string;
  impressions: number;
  clicks: number;
  growth?: number;
};
```

---

## Proposed Agents

### Agent 1: Classification Agent (CORE)
**Purpose**: Semantically classify search queries using LLM

**Input**:
```typescript
{
  query: string;           // e.g., "cra grocery rebate 2025"
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
}
```

**Output**:
```typescript
{
  classification: 'SCAM' | 'MISINFORMATION' | 'SUSPICIOUS' | 'LEGITIMATE';
  confidence: number;      // 0-1
  reasoning: string;       // LLM explanation
  suggestedPatterns: string[];
  suggestedCategory?: string;
}
```

**Integration**: Called by `EmergingThreatService` for uncertain cases (risk 30-70)

---

### Agent 2: Keyword Manager Agent
**Purpose**: Autonomously manage `scam-keywords.json`

**Decision Flow**:
```
Classification result received
        │
        ▼
confidence >= 0.85 AND classification in [SCAM, MISINFORMATION]?
        │
    YES │                    NO
        │                    │
        ▼                    ▼
Auto-add to keywords    Add to review queue
        │                    │
        ▼                    ▼
Notify admin via       Await human approval
webhook/email
```

**Auto-Add Logic**:
1. Normalize the term (lowercase, trim)
2. Determine category based on classification type
3. Check if similar term exists (fuzzy match >90%)
4. If unique, add to `scam-keywords.json`
5. Reload config in `ScamDetectionService`
6. Log action for audit trail

---

### Agent 3: Report Generation Agent
**Purpose**: Generate natural language executive summaries

**Report Types**:
- **Daily Digest**: Top threats, new terms, severity breakdown
- **Weekly Report**: Trends, comparisons, recommendations
- **Executive Summary**: High-level overview for leadership
- **Alert Notification**: Critical threat notifications

**Output Formats**:
- Markdown (for preview)
- HTML (for email)
- PDF (for download)
- Slack webhook payload

---

### Agent 4: Anomaly Investigation Agent
**Purpose**: Autonomously investigate CTR anomalies

**Investigation Process**:
1. **Trigger**: CTR anomaly detected (CTR < 50% of expected for position)
2. **Correlation Check**: Query Google Trends for sudden popularity
3. **Linguistic Analysis**: Check for scam indicators
4. **Historical Check**: Is this a recurring pattern?
5. **Verdict Generation**: Synthesize findings into verdict

**Verdicts**:
- `CONFIRMED_THREAT`: High confidence scam, recommend auto-add
- `LIKELY_THREAT`: Probable scam, needs human review
- `NEEDS_REVIEW`: Inconclusive, requires analyst attention
- `FALSE_POSITIVE`: Legitimate search, suggest whitelist

---

## Technical Architecture

### LLM Provider: OpenRouter

**Why OpenRouter**:
- Single API, multiple model access
- OpenAI-compatible API (easy integration)
- Pay-per-use pricing
- Model flexibility (switch models without code changes)

**Configuration**:
```env
# .env file
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet  # default, configurable
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

**OpenRouter Models (configurable)**:
- `anthropic/claude-3.5-sonnet` - Best reasoning (~$3/1M input, $15/1M output)
- `openai/gpt-4o` - Alternative (~$2.5/1M input, $10/1M output)
- `meta-llama/llama-3.1-70b-instruct` - Budget option (~$0.6/1M tokens)

---

### New Files to Create

```
apps/api/src/
├── services/
│   └── ai/
│       ├── llm.service.ts                    # OpenRouter abstraction
│       ├── agent-orchestrator.service.ts     # Coordinates agents
│       ├── classification.agent.ts           # Scam classification
│       ├── keyword-manager.agent.ts          # Keyword automation
│       ├── report-generation.agent.ts        # Report generation
│       └── anomaly-investigation.agent.ts    # Investigation agent
├── controllers/
│   └── agent.controller.ts                   # Agent API endpoints
└── config/
    └── agent.config.ts                       # Agent configuration

apps/frontend/src/app/pages/
├── agent-review/
│   ├── agent-review.component.ts
│   ├── agent-review.component.html
│   └── agent-review.component.scss
└── reports/
    ├── reports.component.ts
    ├── reports.component.html
    └── reports.component.scss

libs/shared-types/src/lib/
└── agent.types.ts                            # Agent type definitions
```

---

### Dependencies to Install

```bash
cd F:\vscode_projects\vs-code-projects\google_search\cra-scam-detection
npm install openai zod
```

**Package Versions**:
```json
{
  "openai": "^4.70.0",
  "zod": "^3.23.0"
}
```

**Why These Dependencies**:
- `openai`: OpenRouter uses OpenAI-compatible API
- `zod`: Runtime schema validation for LLM responses

---

### Environment Configuration

**Update `.env`**:
```env
# Existing
GOOGLE_MAPS_API_KEY=your_key

# NEW: OpenRouter Configuration
OPENROUTER_API_KEY=sk-or-v1-your_key_here
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# NEW: Agent Settings
AGENT_AUTO_APPROVE_THRESHOLD=85
AGENT_HUMAN_REVIEW_THRESHOLD=60
AGENT_BATCH_SIZE=50
AGENT_RATE_LIMIT_RPM=60
AGENT_DAILY_BUDGET_USD=10
AGENT_CACHE_TTL_SECONDS=86400
```

**Update `apps/api/src/environments/environment.ts`**:
```typescript
export const environment = {
  production: false,
  port: 3000,

  // Existing config...

  // NEW: Agent Configuration
  agent: {
    enabled: true,
    openRouterApiKey: process.env.OPENROUTER_API_KEY || '',
    openRouterBaseUrl: process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1',
    model: process.env.OPENROUTER_MODEL || 'anthropic/claude-3.5-sonnet',

    // Thresholds
    autoApproveThreshold: parseInt(process.env.AGENT_AUTO_APPROVE_THRESHOLD || '85'),
    humanReviewThreshold: parseInt(process.env.AGENT_HUMAN_REVIEW_THRESHOLD || '60'),

    // Rate limiting
    batchSize: parseInt(process.env.AGENT_BATCH_SIZE || '50'),
    rateLimitRpm: parseInt(process.env.AGENT_RATE_LIMIT_RPM || '60'),

    // Cost control
    dailyBudgetUsd: parseFloat(process.env.AGENT_DAILY_BUDGET_USD || '10'),

    // Caching
    cacheTtlSeconds: parseInt(process.env.AGENT_CACHE_TTL_SECONDS || '86400'),

    // Fallback
    fallbackToRulesOnError: true,
  },
};
```

---

## Detailed Implementation Guide

### Phase 1: Type Definitions

**File**: `libs/shared-types/src/lib/agent.types.ts`

```typescript
/**
 * Agent Types for CRA Scam Detection Dashboard
 *
 * This file defines all types used by the AI agent system.
 */

// ============================================================
// Classification Agent Types
// ============================================================

/**
 * Classification categories for search queries
 */
export type AgentClassification = 'SCAM' | 'MISINFORMATION' | 'SUSPICIOUS' | 'LEGITIMATE';

/**
 * Confidence level derived from confidence score
 */
export type AgentConfidenceLevel = 'very_high' | 'high' | 'medium' | 'low';

/**
 * Context provided to the classification agent
 */
export type ClassificationContext = {
  query: string;
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
};

/**
 * Result from the classification agent
 */
export type AgentClassificationResult = {
  id: string;
  query: string;
  classification: AgentClassification;
  confidence: number;              // 0-1 scale
  confidenceLevel: AgentConfidenceLevel;
  reasoning: string;               // LLM-generated explanation
  suggestedPatterns: string[];     // Patterns agent suggests adding
  suggestedCategory?: string;      // Category for new patterns

  // Context that was provided
  context: ClassificationContext;

  // Rule-based comparison
  ruleBasedMatch: {
    wasMatched: boolean;
    severity?: string;
    matchedCategory?: string;
    matchedPatterns?: string[];
  };

  // Agreement metric
  agreesWithRules: boolean;

  // Metadata
  classifiedAt: string;            // ISO timestamp
  modelUsed: string;               // e.g., "anthropic/claude-3.5-sonnet"
  processingTimeMs: number;
};

// ============================================================
// Keyword Management Types
// ============================================================

/**
 * Status of a keyword proposal in the review queue
 */
export type KeywordProposalStatus = 'pending' | 'approved' | 'rejected' | 'auto_approved';

/**
 * A proposal to add a new keyword
 */
export type KeywordProposal = {
  id: string;
  term: string;                    // Original query term
  normalizedTerm: string;          // Lowercase, trimmed
  category: string;                // Target category
  severity: string;                // Suggested severity
  confidence: number;              // From classification
  reasoning: string;               // Why this should be added

  // Supporting evidence
  sampleQueries: string[];         // Example queries that would match
  impressions: number;             // Total impressions seen
  occurrences: number;             // How many times detected

  // Status
  status: KeywordProposalStatus;
  createdAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
  reviewerNotes?: string;
};

/**
 * Item in the human review queue
 */
export type ReviewQueueItem = {
  id: string;
  type: 'keyword_addition' | 'keyword_removal' | 'whitelist_addition';
  proposal: KeywordProposal;
  priority: 'high' | 'medium' | 'low';
  createdAt: string;
};

// ============================================================
// Human Feedback Types
// ============================================================

/**
 * Human feedback on an agent classification
 */
export type AgentFeedback = {
  id: string;
  classificationId: string;
  query: string;

  // Original agent decision
  agentClassification: AgentClassification;
  agentConfidence: number;

  // Human review
  reviewerDecision: 'approve' | 'reject' | 'modify';
  correctClassification?: AgentClassification;  // If modified
  reviewerNotes?: string;
  reviewedAt: string;
  reviewedBy?: string;

  // Training data flag
  isTrainingExample: boolean;
};

// ============================================================
// Report Generation Types
// ============================================================

/**
 * Types of reports the agent can generate
 */
export type ReportType = 'daily_digest' | 'weekly_report' | 'executive_summary' | 'alert';

/**
 * Report generation request
 */
export type ReportRequest = {
  type: ReportType;
  dateRange: {
    startDate: string;
    endDate: string;
  };
  format: 'markdown' | 'html' | 'json';
  includeCharts?: boolean;
};

/**
 * Generated report
 */
export type GeneratedReport = {
  id: string;
  type: ReportType;
  title: string;
  content: string;                 // Formatted content
  format: string;

  // Summary data
  summary: {
    totalThreats: number;
    criticalCount: number;
    newTermsCount: number;
    trend: 'escalating' | 'stable' | 'improving';
  };

  generatedAt: string;
  dateRange: {
    startDate: string;
    endDate: string;
  };
};

// ============================================================
// Investigation Agent Types
// ============================================================

/**
 * Verdict from anomaly investigation
 */
export type InvestigationVerdict =
  | 'CONFIRMED_THREAT'
  | 'LIKELY_THREAT'
  | 'NEEDS_REVIEW'
  | 'FALSE_POSITIVE';

/**
 * Evidence gathered during investigation
 */
export type InvestigationEvidence = {
  trendsCorrelation: {
    found: boolean;
    changePercent?: number;
    peakDate?: string;
  };
  linguisticSignals: string[];      // e.g., "contains dollar amount", "urgency word"
  historicalAnalysis: {
    isRecurring: boolean;
    firstSeen?: string;
    previousOccurrences: number;
  };
  seasonalRelevance: {
    isRelevant: boolean;
    reason?: string;               // e.g., "Tax season", "GST payment date"
  };
  similarKnownScams: string[];
};

/**
 * Result of anomaly investigation
 */
export type InvestigationResult = {
  id: string;
  threatId: string;
  query: string;

  verdict: InvestigationVerdict;
  confidenceScore: number;         // 0-100

  evidence: InvestigationEvidence;

  recommendedAction: 'ADD_TO_KEYWORDS' | 'ADD_TO_WHITELIST' | 'MONITOR' | 'DISMISS';

  investigatedAt: string;
  investigationTimeMs: number;
};

// ============================================================
// API Request/Response Types
// ============================================================

/**
 * Request to classify a single query
 */
export type ClassifyQueryRequest = {
  query: string;
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
};

/**
 * Request to classify multiple queries
 */
export type BatchClassifyRequest = {
  queries: ClassifyQueryRequest[];
  includeReasoning?: boolean;
  minConfidenceThreshold?: number;
};

/**
 * Response from batch classification
 */
export type BatchClassifyResponse = {
  results: AgentClassificationResult[];
  summary: {
    total: number;
    scam: number;
    misinformation: number;
    suspicious: number;
    legitimate: number;
    averageConfidence: number;
    processingTimeMs: number;
  };
  suggestedPatterns: Array<{
    pattern: string;
    category: string;
    occurrences: number;
    confidence: number;
  }>;
};

// ============================================================
// Agent Configuration Types
// ============================================================

/**
 * Runtime configuration for agents
 */
export type AgentConfig = {
  enabled: boolean;
  model: string;

  // Thresholds
  autoApproveThreshold: number;    // 0-100, auto-approve above this
  humanReviewThreshold: number;    // 0-100, require review below this

  // Rate limiting
  batchSize: number;
  rateLimitRpm: number;

  // Cost control
  dailyBudgetUsd: number;

  // Caching
  cacheTtlSeconds: number;

  // Fallback
  fallbackToRulesOnError: boolean;
};

/**
 * Agent statistics
 */
export type AgentStats = {
  totalClassifications: number;
  classificationsToday: number;
  feedbackCount: number;
  approvalRate: number;            // 0-1
  averageConfidence: number;       // 0-1
  suggestionsCount: number;
  autoApprovedCount: number;
  rejectedCount: number;
  costToday: number;              // USD
};
```

**Update exports in `libs/shared-types/src/index.ts`**:
```typescript
export * from './lib/scam-detection.types';
export * from './lib/search-analytics.types';
export * from './lib/trends.types';
export * from './lib/agent.types';  // ADD THIS
```

---

### Phase 2: LLM Service

**File**: `apps/api/src/services/ai/llm.service.ts`

See the full implementation in the detailed plan file. Key features:
- OpenRouter API integration via OpenAI SDK
- Zod schema validation for responses
- Daily token/cost tracking
- Budget monitoring
- Detailed system prompts for CRA scam classification

---

### Phase 3: Classification Agent

**File**: `apps/api/src/services/ai/classification.agent.ts`

See the full implementation in the detailed plan file. Key features:
- Single query and batch classification
- Cache integration (24h TTL)
- Rule-based comparison
- Fallback when LLM unavailable
- Pattern suggestion aggregation

---

### Phase 4: Agent Controller

**File**: `apps/api/src/controllers/agent.controller.ts`

See the full implementation in the detailed plan file. API endpoints:
- `POST /api/agent/classify` - Single query
- `POST /api/agent/classify/batch` - Batch queries
- `GET /api/agent/review-queue` - Pending reviews
- `POST /api/agent/review/:id/approve` - Approve
- `POST /api/agent/review/:id/reject` - Reject
- `POST /api/agent/feedback` - Human feedback
- `GET /api/agent/stats` - Statistics

---

## Implementation Checklist

### Phase 1: Foundation (Types & LLM Service)
- [ ] Create `libs/shared-types/src/lib/agent.types.ts`
- [ ] Update `libs/shared-types/src/index.ts` to export agent types
- [ ] Create `apps/api/src/services/ai/` directory
- [ ] Implement `apps/api/src/services/ai/llm.service.ts`
- [ ] Install dependencies: `npm install openai zod`
- [ ] Add environment variables to `.env`
- [ ] Update `apps/api/src/environments/environment.ts`

### Phase 2: Classification Agent
- [ ] Implement `apps/api/src/services/ai/classification.agent.ts`
- [ ] Add `getKeywordsConfig()` method to `ScamDetectionService` if not exists
- [ ] Test classification with sample queries

### Phase 3: Keyword Manager Agent
- [ ] Implement `apps/api/src/services/ai/keyword-manager.agent.ts`
- [ ] Create review queue storage (in-memory Map initially)
- [ ] Implement auto-approve logic
- [ ] Add keyword file update functionality

### Phase 4: Agent Controller & Integration
- [ ] Implement `apps/api/src/controllers/agent.controller.ts`
- [ ] Update `apps/api/src/app/app.module.ts`
- [ ] Test API endpoints

### Phase 5: Report Generation Agent
- [ ] Implement `apps/api/src/services/ai/report-generation.agent.ts`
- [ ] Create report templates
- [ ] Add report endpoints

### Phase 6: Anomaly Investigation Agent
- [ ] Implement `apps/api/src/services/ai/anomaly-investigation.agent.ts`
- [ ] Integrate with `EmergingThreatService`

### Phase 7: Frontend
- [ ] Create `apps/frontend/src/app/pages/agent-review/`
- [ ] Create `apps/frontend/src/app/pages/reports/`
- [ ] Update `apps/frontend/src/app/app.routes.ts`
- [ ] Add agent methods to `apps/frontend/src/app/services/api.service.ts`

### Phase 8: Testing & Polish
- [ ] Add unit tests for agents
- [ ] Integration testing
- [ ] Update README documentation

---

## Notes for Future Claude

1. **Start with Phase 1** - Types and LLM service are foundational
2. **Test each phase** - Use `npm run start:api` and test endpoints manually
3. **Check `.env`** - Make sure `OPENROUTER_API_KEY` is set
4. **Budget monitoring** - Watch the daily cost estimate
5. **Caching is important** - Same queries shouldn't call LLM twice
6. **Fallback behavior** - When LLM fails, system should still work (rule-based)

---

## API Endpoint Summary

```
POST /api/agent/classify           - Classify single query
POST /api/agent/classify/batch     - Batch classify queries
POST /api/agent/feedback           - Record human feedback
GET  /api/agent/review-queue       - Get pending reviews
POST /api/agent/review/:id/approve - Approve proposal
POST /api/agent/review/:id/reject  - Reject proposal
GET  /api/agent/stats              - Agent statistics
GET  /api/reports/daily            - Daily threat summary
GET  /api/reports/weekly           - Weekly report
```
