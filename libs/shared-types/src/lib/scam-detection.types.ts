/**
 * Scam Detection Types
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FlaggedTermStatus = 'new' | 'active' | 'reviewed' | 'dismissed' | 'escalated';

/**
 * A flagged search term that matches scam patterns
 */
export type FlaggedTerm = {
  id: string;
  query: string;
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
  severity: Severity;
  matchedCategory: string; // Which category triggered the flag
  matchedPatterns: string[]; // Specific patterns that matched
  firstDetected: string; // ISO date
  lastSeen: string; // ISO date
  status: FlaggedTermStatus;
  notes?: string;
};

/**
 * Previous period metrics for comparison display
 */
export type PreviousPeriodMetrics = {
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
};

/**
 * Flagged term with comparison to previous period
 * Used for dashboard display with period-over-period comparison
 */
export type FlaggedTermWithComparison = FlaggedTerm & {
  previous: PreviousPeriodMetrics | null; // null if term is new
  isNew: boolean; // true if term didn't exist in previous period
  change?: {
    impressions: number;
    impressionsPercent: number;
    position: number; // positive = worse position (moved down), negative = improved
  };
};

/**
 * Scam detection result for a date range
 */
export type ScamDetectionResult = {
  analysisDate: string;
  period: {
    startDate: string;
    endDate: string;
  };
  totalQueriesAnalyzed: number;
  flaggedTerms: FlaggedTerm[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
};

/**
 * Keyword category configuration
 */
export type KeywordCategory = {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  terms: string[];
  // For contextual matching (must contain one of these + a term)
  mustContain?: string[];
  // Regex patterns for complex matching
  patterns?: string[];
};

/**
 * Full scam keywords configuration
 */
export type ScamKeywordsConfig = {
  version: string;
  lastUpdated: string;
  categories: {
    fakeExpiredBenefits: KeywordCategory;
    illegitimatePaymentMethods: KeywordCategory;
    threatLanguage: KeywordCategory;
    suspiciousModifiers: KeywordCategory;
  };
  seasonalMultipliers: {
    taxSeason: {
      startMonth: number;
      startDay: number;
      endMonth: number;
      endDay: number;
      multiplier: number;
    };
    gstPayment: {
      days: number[];
      months: number[];
      multiplier: number;
    };
    ccrPayment: {
      days: number[];
      months: number[];
      multiplier: number;
    };
  };
};

/**
 * Dashboard KPI summary
 */
export type DashboardSummary = {
  period: {
    startDate: string;
    endDate: string;
  };
  flaggedTermsCount: number;
  newTermsCount: number;
  totalSuspiciousImpressions: number;
  averagePosition: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  comparisonToPrevious?: {
    flaggedTermsChange: number;
    impressionsChange: number;
    newTermsInPeriod: number;
  };
};

/**
 * Export data format
 */
export type ExportData = {
  generatedAt: string;
  period: {
    startDate: string;
    endDate: string;
  };
  summary: DashboardSummary;
  flaggedTerms: FlaggedTerm[];
};

/**
 * Trending term with comparison data
 */
export type TrendingTermData = {
  query: string;
  severity: Severity;
  matchedCategory: string;
  currentImpressions: number;
  previousImpressions: number;
  changeAmount: number;
  changePercent: number;
};

/**
 * Dashboard data response
 */
export type DashboardData = {
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  criticalAlerts: FlaggedTermWithComparison[];
  highAlerts: FlaggedTermWithComparison[];
  totalQueriesAnalyzed: number;
  period: {
    startDate: string;
    endDate: string;
  };
  previousPeriod: {
    startDate: string;
    endDate: string;
  };
};

/**
 * Comparison result data
 */
export type ComparisonResult = {
  period1: {
    startDate: string;
    endDate: string;
    totalFlagged: number;
    criticalCount: number;
    totalImpressions: number;
  };
  period2: {
    startDate: string;
    endDate: string;
    totalFlagged: number;
    criticalCount: number;
    totalImpressions: number;
  };
  changes: {
    totalFlaggedChange: number;
    criticalChange: number;
    impressionsChange: number;
  };
  newTerms: FlaggedTerm[];
  removedTerms: FlaggedTerm[];
  trendingTerms: Array<{
    query: string;
    severity: Severity;
    currentImpressions: number;
    previousImpressions: number;
    changePercent: number;
  }>;
};

/**
 * CTR Anomaly Detection
 * Key signal: Low CTR indicates users are clicking scam sites instead of CRA pages
 */
export type CTRAnomaly = {
  expectedCTR: number;      // Based on position benchmarks (e.g., position 1-3 expects 15-30%)
  actualCTR: number;        // Actual CTR from Search Console
  anomalyScore: number;     // 0-1, how far from expected (1 = maximum anomaly)
  isAnomalous: boolean;     // True if actual CTR significantly below expected
};

/**
 * Risk level for emerging threats
 */
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

/**
 * Status for emerging threat review workflow
 */
export type EmergingThreatStatus = 'pending' | 'added' | 'dismissed';

/**
 * Velocity metrics for emerging threat detection
 * Tracks how fast a term is growing (impressions per day)
 */
export type VelocityMetrics = {
  impressionsPerDay: number;     // Average daily impression growth
  velocityScore: number;         // 0-1, normalized velocity (1 = very fast growth)
  trend: 'accelerating' | 'steady' | 'decelerating';
};

/**
 * Google Trends data for cross-referencing
 * Terms trending on Google Trends get higher risk scores
 */
export type TrendsData = {
  interest: number;          // 0-100 interest score
  trend: 'up' | 'down' | 'stable';
  changePercent: number;     // Recent change in interest
  isTrending: boolean;       // True if interest > 50 and trending up
};

/**
 * Emerging Threat - a potential scam term detected through CTR anomaly analysis
 * The key insight: High impressions + Low CTR = users seeing CRA result but clicking scam sites
 */
export type EmergingThreat = {
  id: string;
  query: string;
  riskScore: number;        // 0-100 composite score
  riskLevel: RiskLevel;

  // CTR-based analysis (KEY SIGNAL)
  ctrAnomaly: CTRAnomaly;

  // Pattern matching results
  matchedPatterns: string[];  // e.g., ["DOLLAR_AMOUNT: $500", "YEAR: 2025"]
  similarScams: string[];     // Known scam terms with >70% similarity

  // Current period metrics
  current: {
    impressions: number;
    clicks: number;
    ctr: number;
    position: number;
  };

  // Previous period metrics (for comparison)
  previous: {
    impressions: number;
    clicks: number;
    ctr: number;
    position: number;
  };

  // Changes between periods
  change: {
    impressions: number;
    impressionsPercent: number;
    ctrDelta: number;       // Current CTR - Previous CTR (negative = worsening)
  };

  // Velocity metrics (NEW) - how fast the term is growing
  velocity?: VelocityMetrics;

  // Google Trends data (NEW) - cross-reference with public search trends
  trendsData?: TrendsData;

  isNew: boolean;           // First appearance in current period
  firstSeen: string;        // ISO date
  status: EmergingThreatStatus;
};

/**
 * Pagination info for paginated responses
 */
export type PaginationInfo = {
  page: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPrevPage: boolean;
};

/**
 * Response type for emerging threats API
 */
export type EmergingThreatsResponse = {
  currentPeriod: { startDate: string; endDate: string };
  previousPeriod: { startDate: string; endDate: string };
  threats: EmergingThreat[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  pagination: PaginationInfo;
};

/**
 * Request to add a term to keywords
 */
export type AddKeywordRequest = {
  term: string;
  category: 'fakeExpiredBenefits' | 'illegitimatePaymentMethods' | 'threatLanguage' | 'suspiciousModifiers';
};

/**
 * CTR Benchmark for a position range
 * Calculated dynamically from actual Search Console data
 */
export type CTRBenchmark = {
  positionRange: string;     // e.g., "1-3", "4-8", "9-15", "16+"
  min: number;               // 10th percentile - below this is anomalous
  expected: number;          // Median (50th percentile) CTR for this position
  max: number;               // 90th percentile - for reference
  sampleSize: number;        // Number of queries used to calculate
};

/**
 * Full CTR benchmarks object with all position ranges
 */
export type CTRBenchmarks = {
  '1-3': CTRBenchmark;
  '4-8': CTRBenchmark;
  '9-15': CTRBenchmark;
  '16+': CTRBenchmark;
  calculatedAt: string;      // ISO date when benchmarks were calculated
  dataRange: {               // Date range of data used
    startDate: string;
    endDate: string;
  };
  totalQueriesAnalyzed: number;
};

// ============================================================================
// SEMANTIC ZONE DETECTION TYPES
// Used for embedding-based legitimate query classification
// ============================================================================

/**
 * Semantic category classification result
 * Used to determine if a query is in a "legitimate zone" based on embedding similarity
 */
export type SemanticCategory = {
  name: string;                     // Category name (e.g., "accountAccess", "taxFiling")
  type: 'legitimate' | 'suspicious' | 'neutral';
  similarity: number;               // Cosine similarity to category centroid (0-1)
  distance: number;                 // Distance from centroid (1 - similarity)
  confidence: number;               // Confidence level (0-1)
};

/**
 * Classification result from semantic zone check
 */
export type SemanticZoneResult = {
  query: string;
  isLegitimate: boolean;            // True if query is in a legitimate zone
  nearestCategory: string;          // Name of nearest legitimate category
  similarity: number;               // Similarity to nearest category centroid
  allCategories: SemanticCategory[]; // Similarity to all categories (for debugging)
};

/**
 * Signal type for detection convergence
 */
export type DetectionSignalType =
  | 'embedding'       // Semantic similarity to known scam patterns
  | 'ctr_anomaly'     // CTR below expected for position
  | 'pattern_match'   // Dynamic pattern matches (dollar amounts, urgency)
  | 'velocity'        // Rapid impression growth
  | 'trends'          // Google Trends correlation
  | 'semantic_zone';  // Proximity to scam semantic zones

/**
 * Individual detection signal
 * Each signal type provides independent evidence of scam potential
 */
export type DetectionSignal = {
  type: DetectionSignalType;
  active: boolean;                  // True if this signal fires
  strength: number;                 // 0-1, how strong the signal is
  confidence: number;               // 0-1, confidence in the signal
  details: string;                  // Human-readable explanation
  metadata?: Record<string, unknown>; // Additional signal-specific data
};

/**
 * Signal weights for convergence calculation
 */
export type SignalWeights = {
  embedding: number;
  ctr_anomaly: number;
  pattern_match: number;
  velocity: number;
  trends: number;
  semantic_zone: number;
};

/**
 * Result of signal convergence evaluation
 * Used to determine if multiple signals agree on scam potential
 */
export type SignalConvergenceResult = {
  query: string;
  signals: DetectionSignal[];       // All evaluated signals
  activeSignals: DetectionSignal[]; // Only signals that fired
  convergenceScore: number;         // Weighted sum of active signals (0-100)
  activeSignalCount: number;        // Number of signals that fired
  shouldFlag: boolean;              // True if convergence threshold met
  flagReason: string;               // Explanation of why flagged
  semanticZone?: SemanticZoneResult; // Semantic zone check result
};

/**
 * Enhanced FlaggedTerm with signal convergence data
 */
export type FlaggedTermWithConvergence = FlaggedTerm & {
  convergence: SignalConvergenceResult;
  semanticZone?: SemanticZoneResult;
};

/**
 * Category centroid for semantic classification
 */
export type CategoryCentroid = {
  name: string;
  type: 'legitimate' | 'suspicious';
  description: string;
  centroid: number[];               // Embedding vector (3072 dimensions for text-embedding-3-large)
  exemplarCount: number;            // Number of exemplars used to compute centroid
  threshold: number;                // Similarity threshold for membership
};

/**
 * Legitimate queries configuration (loaded from legitimate-queries.json)
 */
export type LegitimateQueriesConfig = {
  version: string;
  description: string;
  settings: {
    legitimateThreshold: number;
    model: string;
    cacheHours: number;
  };
  categories: Record<string, {
    description: string;
    exemplars: string[];
  }>;
};

/**
 * Excluded terms response for admin console
 */
export type ExcludedTermsResponse = {
  status: {
    ready: boolean;
    threshold: number;
    totalExemplars: number;
    categoryCount: number;
  };
  categories: Array<{
    name: string;
    exemplarCount: number;
    description: string;
  }>;
};

// ============================================================================
// SEED PHRASES CONFIGURATION TYPES
// Used for embedding-based scam detection
// ============================================================================

/**
 * Seed phrase category with severity and terms
 */
export type SeedPhraseCategory = {
  severity: Severity;
  terms: string[];
};

/**
 * Individual seed phrase with metadata
 */
export type SeedPhrase = {
  term: string;
  category: string;
  severity: Severity;
};

/**
 * Seed phrases configuration (from seed-phrases.json)
 */
export type SeedPhrasesConfig = {
  version: string;
  lastUpdated: string;
  description: string;
  phrases: Record<string, SeedPhraseCategory>;
  settings: {
    similarityThreshold: number;
    model: string;
    dimensions: number;
  };
};

/**
 * Seed phrase record from DynamoDB
 */
export type SeedPhraseRecord = {
  category: string;
  term: string;
  severity: string;
  createdAt: string;
};
