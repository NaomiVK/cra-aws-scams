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
  whitelist: {
    description: string;
    patterns: string[];
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
  // Keywords to monitor in Google Trends
  trendsKeywords: string[];
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
  flaggedTerms: FlaggedTerm[];
  criticalAlerts: FlaggedTerm[];
  newTerms: FlaggedTerm[];
  trendingTerms: FlaggedTerm[];
  totalQueriesAnalyzed: number;
  period: {
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
export type EmergingThreatStatus = 'pending' | 'added' | 'whitelisted' | 'dismissed';

/**
 * Emerging Threat - a potential scam term detected through CTR anomaly analysis
 * The key insight: High impressions + Low CTR = users seeing CRA result but clicking scam sites
 */
export type EmergingThreat = {
  id: string;
  query: string;
  riskScore: number;        // 0-100 composite score
  riskLevel: RiskLevel;

  // CTR-based analysis (KEY SIGNAL - 40% of risk score)
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
 * Request to add a pattern to whitelist
 */
export type AddWhitelistRequest = {
  pattern: string;
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
