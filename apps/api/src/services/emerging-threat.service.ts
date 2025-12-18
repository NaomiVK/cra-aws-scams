import { Injectable, Logger } from '@nestjs/common';
import { CacheService } from './cache.service';
import { ComparisonService } from './comparison.service';
import { ScamDetectionService } from './scam-detection.service';
import { SearchConsoleService } from './search-console.service';
import { EmbeddingService } from './embedding.service';
import {
  EmergingThreat,
  EmergingThreatsResponse,
  CTRAnomaly,
  CTRBenchmarks,
  RiskLevel,
  TermComparison,
  PaginationInfo,
  VelocityMetrics,
} from '@cra-scam-detection/shared-types';

/**
 * Pagination constants
 */
const MAX_TOTAL_THREATS = 5000;
const PAGE_SIZE = 500;
const MAX_PAGES = 10;
import { environment } from '../environments/environment';
import { v4 as uuidv4 } from 'uuid';
import * as stringSimilarity from 'string-similarity';

/**
 * Dynamic pattern detection regexes
 */
const DYNAMIC_PATTERNS = {
  dollarAmount: /\$\s*\d+(?:,\d{3})*(?:\.\d{2})?|\d+\s*(?:dollars?|bucks)/i,
  urgencyWords: /\b(urgent|immediate|immediately|act now|claim now|apply now|hurry|limited time|expires|last chance|final notice)\b/i,
  freeMoneyPattern: /\b(bonus|extra|secret|hidden)\s+(money|cash|payment|benefit|refund|cheque|check)\b/i,
};

/**
 * Legitimate query patterns - queries matching these should NOT be flagged as threats
 * These are legitimate searches that may contain words like "free" but in a non-scam context
 */
const LEGITIMATE_QUERY_PATTERNS = [
  /\b(software|app|application|program|tool|service)\b/i,  // tax software, filing app, etc.
  /\bfile\s+(my\s+)?taxes?\s+(online\s+)?free\b/i,         // "file my taxes online free"
  /\bfree\s+(tax\s+)?(filing|return|preparation)\b/i,      // "free tax filing", "free return"
  /\b(turbotax|wealthsimple|h&r block|simpletax|ufile|netfile|studiotax|genutax)\b/i,  // known tax software brands
  /\btax\s+(clinic|volunteer|help)\b/i,                    // community tax help programs
];

/**
 * Common CRA-related terms that should NOT be the sole basis for semantic similarity matching
 * If these are the only shared significant words between a query and seed phrase, skip the match
 */
const CRA_CONTEXT_WORDS = new Set([
  'cra', 'canada', 'revenue', 'agency', 'tax', 'taxes', 'government', 'federal',
  'canada revenue agency', 'canada revenue',
]);

@Injectable()
export class EmergingThreatService {
  private readonly logger = new Logger(EmergingThreatService.name);
  private dynamicBenchmarks: CTRBenchmarks | null = null;

  constructor(
    private readonly cacheService: CacheService,
    private readonly comparisonService: ComparisonService,
    private readonly scamDetectionService: ScamDetectionService,
    private readonly searchConsoleService: SearchConsoleService,
    private readonly embeddingService: EmbeddingService,
  ) {}

  /**
   * Get CTR benchmarks - dynamic from your data, with fallback to industry defaults
   */
  async getCTRBenchmarks(): Promise<CTRBenchmarks> {
    if (this.dynamicBenchmarks) {
      return this.dynamicBenchmarks;
    }

    try {
      this.dynamicBenchmarks = await this.searchConsoleService.calculateCTRBenchmarks(90, 10);
      this.logger.log(
        `Using dynamic CTR benchmarks from ${this.dynamicBenchmarks.totalQueriesAnalyzed} queries`
      );
      return this.dynamicBenchmarks;
    } catch (error) {
      this.logger.warn(`Failed to calculate dynamic benchmarks, using fallbacks: ${error.message}`);
      // Return a CTRBenchmarks object using fallback values
      return {
        '1-3': { positionRange: '1-3', min: 0.03, expected: 0.20, max: 0.30, sampleSize: 0 },
        '4-8': { positionRange: '4-8', min: 0.02, expected: 0.10, max: 0.15, sampleSize: 0 },
        '9-15': { positionRange: '9-15', min: 0.01, expected: 0.05, max: 0.08, sampleSize: 0 },
        '16+': { positionRange: '16+', min: 0.005, expected: 0.02, max: 0.03, sampleSize: 0 },
        calculatedAt: new Date().toISOString(),
        dataRange: { startDate: '', endDate: '' },
        totalQueriesAnalyzed: 0,
      };
    }
  }

  /**
   * Get emerging threats by analyzing comparison data
   * Compares current period vs previous period and identifies suspicious terms
   * Supports pagination with max 5000 results, 1000 per page, 5 pages max
   *
   * NEW: Uses embedding-based similarity for better scam pattern detection
   */
  async getEmergingThreats(days = 7, page = 1): Promise<EmergingThreatsResponse> {
    // Validate page number
    const validPage = Math.max(1, Math.min(page, MAX_PAGES));
    const cacheKey = `emerging-threats:${days}:page-${validPage}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        this.logger.log(`Analyzing emerging threats for ${days}-day comparison (page ${validPage})`);

        // Get dynamic CTR benchmarks from actual data
        const benchmarks = await this.getCTRBenchmarks();

        // Get comparison data
        const comparison = days === 7
          ? await this.comparisonService.compareWeekOverWeek()
          : await this.comparisonService.compareMonthOverMonth();

        // STEP 1: Pre-filter terms that are worth analyzing
        // Focus on NEW terms and GROWING terms (not all 25k+ queries)
        // Also exclude terms already added to the scam keywords list
        const candidateTerms = comparison.terms.filter(term => {
          // CRITICAL: Skip terms that have already been added as scam keywords
          // These should NEVER appear in emerging threats again
          if (this.scamDetectionService.isExactKeywordMatch(term.query)) {
            return false;
          }

          // Include if: new term with decent impressions
          if (term.isNew && term.current.impressions >= 20) return true;

          // Include if: significant impression growth (>50%)
          if (term.change.impressionsPercent >= 50 && term.current.impressions >= 50) return true;

          // Include if: high volume (might be ongoing scam)
          if (term.current.impressions >= 500) return true;

          return false;
        });

        this.logger.log(
          `Pre-filtered to ${candidateTerms.length} candidate terms from ${comparison.terms.length} total`
        );

        // STEP 2: Batch analyze candidates with embeddings (if service is ready)
        const embeddingResults: Map<string, { similarity: number; matchedPhrase: string; category: string; severity: string }> = new Map();

        if (this.embeddingService.isReady() && candidateTerms.length > 0) {
          try {
            const queries = candidateTerms.map(t => t.query);
            const results = await this.embeddingService.analyzeQueries(queries, 0.80); // Match seed-phrases.json threshold

            for (const result of results) {
              if (result.topMatch) {
                embeddingResults.set(result.query.toLowerCase(), {
                  similarity: result.topMatch.similarity,
                  matchedPhrase: result.topMatch.phrase,
                  category: result.topMatch.category,
                  severity: result.topMatch.severity,
                });
              }
            }

            this.logger.log(
              `Embedding analysis found ${embeddingResults.size} queries with scam similarity`
            );
          } catch (error) {
            this.logger.warn(`Embedding analysis failed, falling back to string matching: ${error.message}`);
          }
        }

        // STEP 3: Analyze candidate terms for scam patterns
        // Only terms that match scam patterns will be flagged (no whitelist needed)
        const HIGH_SENSITIVITY_THRESHOLD = 20;
        const allThreats: EmergingThreat[] = [];

        for (const term of candidateTerms) {
          const query = term.query.toLowerCase();
          const embeddingMatch = embeddingResults.get(query);
          const threat = this.analyzeTermForThreats(term, benchmarks, days, embeddingMatch);

          // Only add if it has scam signals and meets threshold
          if (threat && threat.riskScore >= HIGH_SENSITIVITY_THRESHOLD) {
            allThreats.push(threat);
          }
        }

        this.logger.log(
          `[EMERGING] Analysis complete: ${allThreats.length} threats identified (threshold: ${HIGH_SENSITIVITY_THRESHOLD})`
        );

        // Sort by risk score descending
        allThreats.sort((a, b) => b.riskScore - a.riskScore);

        // Limit to max total threats
        const limitedThreats = allThreats.slice(0, MAX_TOTAL_THREATS);
        const totalItems = limitedThreats.length;
        const totalPages = Math.min(MAX_PAGES, Math.ceil(totalItems / PAGE_SIZE));

        // Calculate pagination
        const startIndex = (validPage - 1) * PAGE_SIZE;
        const endIndex = Math.min(startIndex + PAGE_SIZE, totalItems);
        const paginatedThreats = limitedThreats.slice(startIndex, endIndex);

        const pagination: PaginationInfo = {
          page: validPage,
          pageSize: PAGE_SIZE,
          totalItems,
          totalPages,
          hasNextPage: validPage < totalPages,
          hasPrevPage: validPage > 1,
        };

        // Summary is based on ALL threats (not just current page)
        const response: EmergingThreatsResponse = {
          currentPeriod: comparison.currentPeriod,
          previousPeriod: comparison.previousPeriod,
          threats: paginatedThreats,
          summary: {
            critical: limitedThreats.filter(t => t.riskLevel === 'critical').length,
            high: limitedThreats.filter(t => t.riskLevel === 'high').length,
            medium: limitedThreats.filter(t => t.riskLevel === 'medium').length,
            low: limitedThreats.filter(t => t.riskLevel === 'low').length,
            total: totalItems,
          },
          pagination,
        };

        this.logger.log(
          `Found ${response.summary.total} emerging threats ` +
          `(${response.summary.critical} critical, ${response.summary.high} high) - ` +
          `showing page ${validPage}/${totalPages} (${paginatedThreats.length} items)`
        );

        return response;
      },
      environment.cache.analyticsTtl
    );
  }

  /**
   * Calculate velocity metrics for a term
   * Velocity = how fast impressions are growing per day
   */
  private calculateVelocity(term: TermComparison, days: number): VelocityMetrics {
    const impressionDelta = term.change.impressions;
    const impressionsPerDay = days > 0 ? impressionDelta / days : 0;

    // Normalize to 0-1 (500+ impressions/day = max velocity)
    const velocityScore = Math.min(1, Math.max(0, impressionsPerDay / 500));

    // Determine trend based on growth pattern
    let trend: 'accelerating' | 'steady' | 'decelerating';
    if (term.isNew || term.change.impressionsPercent > 100) {
      trend = 'accelerating';
    } else if (term.change.impressionsPercent > 0) {
      trend = 'steady';
    } else {
      trend = 'decelerating';
    }

    return {
      impressionsPerDay: Math.round(impressionsPerDay),
      velocityScore,
      trend,
    };
  }

  /**
   * Check if a query matches legitimate patterns that should not be flagged
   */
  private isLegitimateQuery(query: string): boolean {
    return LEGITIMATE_QUERY_PATTERNS.some(pattern => pattern.test(query));
  }

  /**
   * Check if an embedding match is based only on CRA context words
   * If the query and matched phrase share only common CRA-related terms (cra, tax, canada, etc.),
   * the match is likely spurious and should be skipped
   */
  private isOnlyCraContextMatch(query: string, matchedPhrase: string): boolean {
    const queryWords = new Set(
      query.toLowerCase().split(/\s+/).filter(w => w.length > 2)
    );
    const phraseWords = new Set(
      matchedPhrase.toLowerCase().split(/\s+/).filter(w => w.length > 2)
    );

    // Find shared words between query and matched phrase
    const sharedWords = [...queryWords].filter(w => phraseWords.has(w));

    // If no shared words, the match is purely semantic - allow it
    if (sharedWords.length === 0) {
      return false;
    }

    // Check if ALL shared words are just CRA context words
    const nonContextSharedWords = sharedWords.filter(w => !CRA_CONTEXT_WORDS.has(w));

    // If there are no non-context shared words, this match is only based on CRA context
    return nonContextSharedWords.length === 0;
  }

  /**
   * Analyze a single term for threat indicators
   * @param embeddingMatch Optional embedding match result from batch analysis
   * @param days Number of days in the comparison period (for velocity calculation)
   *
   * NOTE: Whitelist/semantic zone filtering is now done in batch in getEmergingThreats()
   * Terms reaching this method have already passed semantic zone checks
   */
  private analyzeTermForThreats(
    term: TermComparison,
    benchmarks: CTRBenchmarks,
    days: number,
    embeddingMatch?: { similarity: number; matchedPhrase: string; category: string; severity: string }
  ): EmergingThreat | null {
    const query = term.query.toLowerCase();

    // Skip queries that match legitimate patterns (e.g., "free tax software")
    if (this.isLegitimateQuery(query)) {
      return null;
    }

    // Note: Semantic zone filtering is done in batch before this method is called
    // No need for redundant whitelist checks here

    // Filter out embedding matches that are only based on CRA context words
    // e.g., "cra my account" matching "cra gift card" just because both have "cra"
    let filteredEmbeddingMatch = embeddingMatch;
    if (embeddingMatch && this.isOnlyCraContextMatch(query, embeddingMatch.matchedPhrase)) {
      filteredEmbeddingMatch = undefined;
    }

    // Calculate CTR anomaly using dynamic benchmarks
    const ctrAnomaly = this.calculateCTRAnomaly(
      term.current.ctr,
      term.current.position,
      benchmarks
    );

    // Find matching dynamic patterns
    const matchedPatterns = this.checkDynamicPatterns(query);

    // Find similar known scam terms using embeddings
    // Only fall back to string similarity if embedding service is NOT available
    let similarScams: string[] = [];
    if (filteredEmbeddingMatch) {
      // Embedding match found - use it
      similarScams = [`${filteredEmbeddingMatch.matchedPhrase} (${Math.round(filteredEmbeddingMatch.similarity * 100)}% semantic match)`];
    } else if (!this.embeddingService.isReady()) {
      // Embedding service not available - fall back to string similarity
      similarScams = this.findSimilarScams(query);
    }
    // If embedding service IS ready but no match found, similarScams stays empty (no fallback)

    // Calculate velocity metrics
    const velocity = this.calculateVelocity(term, days);

    // Calculate composite risk score (now includes velocity)
    const riskScore = this.calculateRiskScore(term, ctrAnomaly, matchedPatterns, similarScams, filteredEmbeddingMatch, velocity);

    // Determine risk level
    const riskLevel = this.getRiskLevel(riskScore);

    // CRITICAL FIX: Require at least one POSITIVE scam indicator before flagging.
    // CTR anomaly alone is NOT enough - irrelevant queries (e.g., "stat holidays ontario 2025")
    // naturally have low CTR when they show CRA pages because users don't want CRA results.
    // We must have evidence the query is SCAM-RELATED, not just that CTR is low.
    const hasScamSignal = filteredEmbeddingMatch || matchedPatterns.length > 0 || similarScams.length > 0;

    if (!hasScamSignal) {
      // No scam indicators at all - this query is not related to scams
      return null;
    }

    // Additional threshold check for queries with weak signals
    const MIN_RISK_THRESHOLD = 15;
    if (riskScore < MIN_RISK_THRESHOLD) {
      return null;
    }

    return {
      id: uuidv4(),
      query: term.query,
      riskScore,
      riskLevel,
      ctrAnomaly,
      matchedPatterns,
      similarScams,
      current: term.current,
      previous: term.previous,
      change: {
        impressions: term.change.impressions,
        impressionsPercent: term.change.impressionsPercent,
        ctrDelta: term.current.ctr - term.previous.ctr,
      },
      velocity,
      isNew: term.isNew,
      firstSeen: new Date().toISOString(),
      status: 'pending',
    };
  }

  /**
   * Calculate CTR anomaly based on position benchmarks
   * KEY INSIGHT: Low CTR at good position = users clicking scam sites instead
   *
   * @param actualCTR The actual CTR from Search Console
   * @param position The average position for this query
   * @param benchmarks Dynamic benchmarks calculated from your actual data
   */
  calculateCTRAnomaly(actualCTR: number, position: number, benchmarks: CTRBenchmarks): CTRAnomaly {
    // Get benchmark for this position range
    let benchmarkKey: '1-3' | '4-8' | '9-15' | '16+';
    if (position <= 3) {
      benchmarkKey = '1-3';
    } else if (position <= 8) {
      benchmarkKey = '4-8';
    } else if (position <= 15) {
      benchmarkKey = '9-15';
    } else {
      benchmarkKey = '16+';
    }

    const benchmark = benchmarks[benchmarkKey];
    const expectedCTR = benchmark.expected;
    const minCTR = benchmark.min;

    // Calculate anomaly score (0-1)
    // Higher score = more anomalous (actual CTR much lower than expected)
    let anomalyScore = 0;
    if (actualCTR < expectedCTR) {
      anomalyScore = Math.min(1, (expectedCTR - actualCTR) / expectedCTR);
    }

    // Is it anomalous? (below minimum threshold for position)
    const isAnomalous = actualCTR < minCTR;

    return {
      expectedCTR,
      actualCTR,
      anomalyScore,
      isAnomalous,
    };
  }

  /**
   * Check for dynamic scam patterns (dollar amounts, urgency, free money)
   */
  checkDynamicPatterns(query: string): string[] {
    const matched: string[] = [];

    // Check for dollar amounts
    const dollarMatch = query.match(DYNAMIC_PATTERNS.dollarAmount);
    if (dollarMatch) {
      matched.push(`DOLLAR_AMOUNT: ${dollarMatch[0]}`);
    }

    // Check for urgency words
    const urgencyMatch = query.match(DYNAMIC_PATTERNS.urgencyWords);
    if (urgencyMatch) {
      matched.push(`URGENCY: ${urgencyMatch[0]}`);
    }

    // Check for free money patterns
    const freeMoneyMatch = query.match(DYNAMIC_PATTERNS.freeMoneyPattern);
    if (freeMoneyMatch) {
      matched.push(`FREE_MONEY: ${freeMoneyMatch[0]}`);
    }

    return matched;
  }

  /**
   * Find known scam terms similar to this query
   * Uses fuzzy string matching with 70% similarity threshold
   */
  findSimilarScams(query: string): string[] {
    const config = this.scamDetectionService.getKeywordsConfig();
    const allScamTerms: string[] = [
      ...config.categories.fakeExpiredBenefits.terms,
      ...config.categories.illegitimatePaymentMethods.terms,
      ...config.categories.threatLanguage.terms,
    ];

    const similar: string[] = [];
    const queryLower = query.toLowerCase();

    for (const scamTerm of allScamTerms) {
      const similarity = stringSimilarity.compareTwoStrings(
        queryLower,
        scamTerm.toLowerCase()
      );

      if (similarity >= 0.7) {
        similar.push(`${scamTerm} (${Math.round(similarity * 100)}%)`);
      }
    }

    // Also check for shared keywords (at least 2 meaningful words in common)
    const queryWords = new Set(queryLower.split(/\s+/).filter(w => w.length > 2));
    for (const scamTerm of allScamTerms) {
      const scamWords = new Set(scamTerm.toLowerCase().split(/\s+/).filter(w => w.length > 2));
      const intersection = [...queryWords].filter(w => scamWords.has(w));

      if (intersection.length >= 2) {
        const matchStr = `${scamTerm} (shared: ${intersection.join(', ')})`;
        if (!similar.includes(matchStr)) {
          similar.push(matchStr);
        }
      }
    }

    return similar.slice(0, 5); // Limit to top 5
  }

  /**
   * Calculate composite risk score (0-100)
   *
   * Formula includes velocity factor (5-8% weight):
   * - Without embedding: CTR (35%) + Position (22%) + Volume (18%) + Emergence (13%) + Velocity (12%)
   * - With embedding: Embedding (30%) + CTR (22%) + Position (13%) + Volume (13%) + Emergence (10%) + Velocity (12%)
   */
  calculateRiskScore(
    term: TermComparison,
    ctrAnomaly: CTRAnomaly,
    matchedPatterns: string[],
    similarScams: string[],
    embeddingMatch?: { similarity: number; matchedPhrase: string; category: string; severity: string },
    velocity?: VelocityMetrics
  ): number {
    // 1. CTR Factor - Low CTR at good position = users clicking elsewhere (scam sites)
    let ctrFactor = ctrAnomaly.anomalyScore;
    if (ctrAnomaly.isAnomalous) {
      ctrFactor = Math.min(1, ctrFactor + 0.3); // Boost if definitely anomalous
    }

    // 2. Position Factor - Good position + low clicks = very suspicious
    let positionFactor = 0;
    const position = term.current.position;
    const clicks = term.current.clicks;
    const impressions = term.current.impressions;

    if (position <= 3 && clicks < 50 && impressions > 100) {
      positionFactor = 0.9;
    } else if (position <= 8 && clicks < 20 && impressions > 50) {
      positionFactor = 0.7;
    } else if (position <= 15 && clicks < 10 && impressions > 30) {
      positionFactor = 0.5;
    }

    // 3. Volume Factor - Sudden spike in impressions
    let volumeFactor = 0;
    const impressionGrowth = term.change.impressionsPercent;
    if (impressionGrowth >= 300) {
      volumeFactor = 1.0;
    } else if (impressionGrowth >= 200) {
      volumeFactor = 0.8;
    } else if (impressionGrowth >= 100) {
      volumeFactor = 0.6;
    } else if (impressionGrowth >= 50) {
      volumeFactor = 0.3;
    }

    // 4. Emergence Factor - New terms appearing with volume are emerging threats
    let emergenceFactor = 0;
    if (term.isNew) {
      if (impressions > 100) {
        emergenceFactor = 0.9;
      } else if (impressions > 50) {
        emergenceFactor = 0.6;
      } else if (impressions > 20) {
        emergenceFactor = 0.3;
      }
    }

    // 5. Velocity Factor - Fast-growing terms are more suspicious
    const velocityFactor = velocity?.velocityScore || 0;

    // Calculate base score - use different weights if we have embedding match
    let score: number;

    if (embeddingMatch) {
      // 6. Embedding Factor - Semantic similarity to known scam phrases (STRONGEST signal)
      const embeddingFactor = embeddingMatch.similarity;

      // Severity boost based on matched category
      let severityMultiplier = 1.0;
      if (embeddingMatch.severity === 'critical') {
        severityMultiplier = 1.3;
      } else if (embeddingMatch.severity === 'high') {
        severityMultiplier = 1.15;
      }

      // With embedding: give semantic match the highest weight, include velocity
      score = (
        (embeddingFactor * 0.30 * severityMultiplier) +
        (ctrFactor * 0.22) +
        (positionFactor * 0.13) +
        (volumeFactor * 0.13) +
        (emergenceFactor * 0.10) +
        (velocityFactor * 0.12)
      ) * 100;
    } else {
      // Without embedding: include velocity in score
      score = (
        (ctrFactor * 0.35) +
        (positionFactor * 0.22) +
        (volumeFactor * 0.18) +
        (emergenceFactor * 0.13) +
        (velocityFactor * 0.12)
      ) * 100;
    }

    // Boost for pattern matches (regex patterns like dollar amounts, urgency words)
    if (matchedPatterns.length > 0) {
      const patternBoost = Math.min(20, matchedPatterns.length * 5);
      score += patternBoost;
    }

    // Boost for similar known scams (only if no embedding match - avoid double counting)
    if (!embeddingMatch && similarScams.length > 0) {
      const similarBoost = Math.min(15, similarScams.length * 5);
      score += similarBoost;
    }

    return Math.min(100, Math.round(score));
  }

  /**
   * Convert risk score to risk level
   */
  private getRiskLevel(score: number): RiskLevel {
    if (score >= 76) return 'critical';
    if (score >= 51) return 'high';
    if (score >= 31) return 'medium';
    return 'low';
  }
}
