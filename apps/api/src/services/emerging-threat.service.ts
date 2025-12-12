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
  DateRange,
  PaginationInfo,
} from '@cra-scam-detection/shared-types';

/**
 * Pagination constants
 */
const MAX_TOTAL_THREATS = 5000;
const PAGE_SIZE = 1000;
const MAX_PAGES = 5;
import { environment } from '../environments/environment';
import { v4 as uuidv4 } from 'uuid';
import * as stringSimilarity from 'string-similarity';

/**
 * Fallback CTR benchmarks (used when no dynamic data available)
 * Based on typical Google Search Console data for legitimate queries
 */
const FALLBACK_CTR_BENCHMARKS: Record<string, { min: number; expected: number }> = {
  '1-3': { min: 0.03, expected: 0.20 },   // Position 1-3: expect 15-30%, anomaly if < 3%
  '4-8': { min: 0.02, expected: 0.10 },   // Position 4-8: expect 8-15%, anomaly if < 2%
  '9-15': { min: 0.01, expected: 0.05 },  // Position 9-15: expect 3-8%, anomaly if < 1%
  '16+': { min: 0.005, expected: 0.02 },  // Position 16+: expect <3%, anomaly if < 0.5%
};

/**
 * Dynamic pattern detection regexes
 */
const DYNAMIC_PATTERNS = {
  dollarAmount: /\$\s*\d+(?:,\d{3})*(?:\.\d{2})?|\d+\s*(?:dollars?|bucks)/i,
  yearReference: /\b20(2[4-9]|[3-9]\d)\b/,  // Years 2024-2099
  urgencyWords: /\b(urgent|immediate|immediately|act now|claim now|apply now|hurry|limited time|expires|last chance|final notice)\b/i,
  freeMoneyPattern: /\b(free|bonus|extra|secret|hidden|unclaimed)\s+(money|cash|payment|benefit|refund|cheque|check)\b/i,
  craContext: /\b(cra|canada revenue|revenue agency|tax)\b/i,
};

@Injectable()
export class EmergingThreatService {
  private readonly logger = new Logger(EmergingThreatService.name);
  private dynamicBenchmarks: CTRBenchmarks | null = null;

  constructor(
    private readonly cacheService: CacheService,
    private readonly comparisonService: ComparisonService,
    private readonly scamDetectionService: ScamDetectionService,
    private readonly searchConsoleService: SearchConsoleService,
    private readonly embeddingService: EmbeddingService
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
        const candidateTerms = comparison.terms.filter(term => {
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
        let embeddingResults: Map<string, { similarity: number; matchedPhrase: string; category: string; severity: string }> = new Map();

        if (this.embeddingService.isReady() && candidateTerms.length > 0) {
          try {
            const queries = candidateTerms.map(t => t.query);
            const results = await this.embeddingService.analyzeQueries(queries, 0.75); // Lower threshold for candidates

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

        // STEP 3: Analyze all candidate terms for emerging threats
        const allThreats: EmergingThreat[] = [];

        for (const term of candidateTerms) {
          const embeddingMatch = embeddingResults.get(term.query.toLowerCase());
          const threat = this.analyzeTermForThreats(term, benchmarks, embeddingMatch);
          if (threat && threat.riskScore >= 30) {
            allThreats.push(threat);
          }
        }

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
   * Analyze a single term for threat indicators
   * @param embeddingMatch Optional embedding match result from batch analysis
   */
  private analyzeTermForThreats(
    term: TermComparison,
    benchmarks: CTRBenchmarks,
    embeddingMatch?: { similarity: number; matchedPhrase: string; category: string; severity: string }
  ): EmergingThreat | null {
    const query = term.query.toLowerCase();

    // Skip if whitelisted (use scam detection service's whitelist)
    // We'll check this in the controller instead

    // Calculate CTR anomaly using dynamic benchmarks
    const ctrAnomaly = this.calculateCTRAnomaly(
      term.current.ctr,
      term.current.position,
      benchmarks
    );

    // Find matching dynamic patterns
    const matchedPatterns = this.checkDynamicPatterns(query);

    // Find similar known scam terms (uses embedding if available, falls back to string similarity)
    const similarScams = embeddingMatch
      ? [`${embeddingMatch.matchedPhrase} (${Math.round(embeddingMatch.similarity * 100)}% semantic match)`]
      : this.findSimilarScams(query);

    // Calculate composite risk score (embedding match boosts the score significantly)
    const riskScore = this.calculateRiskScore(term, ctrAnomaly, matchedPatterns, similarScams, embeddingMatch);

    // Determine risk level
    const riskLevel = this.getRiskLevel(riskScore);

    // Only return if there's meaningful risk
    // If we have an embedding match, always include it (semantic match is strong signal)
    if (!embeddingMatch && riskScore < 20 && matchedPatterns.length === 0 && similarScams.length === 0) {
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
   * Check for dynamic scam patterns (dollar amounts, years, urgency)
   */
  checkDynamicPatterns(query: string): string[] {
    const matched: string[] = [];

    // Check for dollar amounts
    const dollarMatch = query.match(DYNAMIC_PATTERNS.dollarAmount);
    if (dollarMatch) {
      matched.push(`DOLLAR_AMOUNT: ${dollarMatch[0]}`);
    }

    // Check for year references (future years are more suspicious)
    const yearMatch = query.match(DYNAMIC_PATTERNS.yearReference);
    if (yearMatch) {
      matched.push(`YEAR: ${yearMatch[0]}`);
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

    // Check for CRA context (needed for some patterns to be suspicious)
    const hasCraContext = DYNAMIC_PATTERNS.craContext.test(query);
    if (hasCraContext && matched.length > 0) {
      matched.unshift('CRA_CONTEXT');
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
   * Formula (without embedding):
   *   ctrFactor (40%) + positionFactor (25%) + volumeFactor (20%) + emergenceFactor (15%)
   *
   * With embedding match:
   *   embeddingFactor (35%) + ctrFactor (25%) + positionFactor (15%) + volumeFactor (15%) + emergenceFactor (10%)
   */
  calculateRiskScore(
    term: TermComparison,
    ctrAnomaly: CTRAnomaly,
    matchedPatterns: string[],
    similarScams: string[],
    embeddingMatch?: { similarity: number; matchedPhrase: string; category: string; severity: string }
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

    // Calculate base score - use different weights if we have embedding match
    let score: number;

    if (embeddingMatch) {
      // 5. Embedding Factor - Semantic similarity to known scam phrases (STRONGEST signal)
      const embeddingFactor = embeddingMatch.similarity;

      // Severity boost based on matched category
      let severityMultiplier = 1.0;
      if (embeddingMatch.severity === 'critical') {
        severityMultiplier = 1.3;
      } else if (embeddingMatch.severity === 'high') {
        severityMultiplier = 1.15;
      }

      // With embedding: give semantic match the highest weight
      score = (
        (embeddingFactor * 0.35 * severityMultiplier) +
        (ctrFactor * 0.25) +
        (positionFactor * 0.15) +
        (volumeFactor * 0.15) +
        (emergenceFactor * 0.10)
      ) * 100;
    } else {
      // Without embedding: use original weights
      score = (
        (ctrFactor * 0.40) +
        (positionFactor * 0.25) +
        (volumeFactor * 0.20) +
        (emergenceFactor * 0.15)
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
