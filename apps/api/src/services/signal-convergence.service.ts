import { Injectable, Logger } from '@nestjs/common';
import { EmbeddingService } from './embedding.service';
import { CategoryCentroidService } from './category-centroid.service';
import {
  DetectionSignal,
  SignalConvergenceResult,
  SignalWeights,
  SemanticZoneResult,
  CTRBenchmarks,
  CTRAnomaly,
  TermComparison,
  VelocityMetrics,
} from '@cra-scam-detection/shared-types';

/**
 * Default signal weights for convergence scoring
 * These are used when calculating the weighted convergence score
 */
const DEFAULT_SIGNAL_WEIGHTS: SignalWeights = {
  embedding: 0.35,      // Semantic similarity to known scams (highest weight)
  ctr_anomaly: 0.25,    // CTR below expected for position
  pattern_match: 0.20,  // Dynamic pattern matches (dollar amounts, urgency)
  velocity: 0.12,       // Rapid impression growth
  trends: 0.08,         // Google Trends correlation
  semantic_zone: 0.00,  // Not used for flagging, only for exclusion
};

/**
 * High sensitivity thresholds
 * Lower thresholds = more sensitive = catches more potential scams
 */
const HIGH_SENSITIVITY_THRESHOLDS = {
  embedding: 0.70,          // Lower than default 0.80 to catch more variations
  ctr_anomaly: 0.30,        // Lower to flag more CTR anomalies
  velocity: 0.40,           // Moderate velocity threshold
  convergence: 0.15,        // Very low - flag if ANY meaningful signal fires
  minSignalsToFlag: 1,      // Only need 1 signal (high sensitivity mode)
};

/**
 * Dynamic pattern detection regexes
 */
const DYNAMIC_PATTERNS = {
  dollarAmount: /\$\s*\d+(?:,\d{3})*(?:\.\d{2})?|\d+\s*(?:dollars?|bucks)/i,
  urgencyWords: /\b(urgent|immediate|immediately|act now|claim now|apply now|hurry|limited time|expires|last chance|final notice)\b/i,
  freeMoneyPattern: /\b(free|bonus|extra|secret|hidden|unclaimed)\s+(money|cash|payment|benefit|refund|cheque|check)\b/i,
  yearPattern: /\b20(2[4-9]|[3-9]\d)\b/,  // Years 2024-2099
};

/**
 * SignalConvergenceService
 *
 * Evaluates multiple independent detection signals and determines
 * if they converge to indicate a potential scam.
 *
 * Key concept: Instead of relying on a single detection method,
 * we evaluate multiple signals and flag when they agree.
 * In high sensitivity mode, we flag if ANY signal fires.
 */
@Injectable()
export class SignalConvergenceService {
  private readonly logger = new Logger(SignalConvergenceService.name);

  constructor(
    private readonly embeddingService: EmbeddingService,
    private readonly categoryCentroidService: CategoryCentroidService,
  ) {}

  /**
   * Evaluate all signals for a query and determine if it should be flagged
   *
   * This is the main entry point for signal-based detection.
   * It first checks if the query is in a legitimate zone (auto-exclude),
   * then evaluates all signals and determines if flagging is warranted.
   */
  async evaluateSignals(
    term: TermComparison,
    benchmarks: CTRBenchmarks,
    days: number
  ): Promise<SignalConvergenceResult> {
    const query = term.query.toLowerCase().trim();
    const signals: DetectionSignal[] = [];

    // STEP 1: Check if in legitimate semantic zone (early exit)
    const semanticZone = await this.categoryCentroidService.isInLegitimateZone(query);

    if (semanticZone.isLegitimate && semanticZone.similarity >= 0.85) {
      // Very clearly legitimate - skip all other checks
      return {
        query,
        signals: [],
        activeSignals: [],
        convergenceScore: 0,
        activeSignalCount: 0,
        shouldFlag: false,
        flagReason: `Legitimate query - matched "${semanticZone.nearestCategory}" with ${(semanticZone.similarity * 100).toFixed(1)}% similarity`,
        semanticZone,
      };
    }

    // STEP 2: Evaluate embedding signal (semantic similarity to scam phrases)
    const embeddingSignal = await this.evaluateEmbeddingSignal(query);
    signals.push(embeddingSignal);

    // STEP 3: Evaluate CTR anomaly signal
    const ctrSignal = this.evaluateCTRAnomalySignal(term, benchmarks);
    signals.push(ctrSignal);

    // STEP 4: Evaluate pattern match signal
    const patternSignal = this.evaluatePatternSignal(query);
    signals.push(patternSignal);

    // STEP 5: Evaluate velocity signal
    const velocitySignal = this.evaluateVelocitySignal(term, days);
    signals.push(velocitySignal);

    // STEP 6: Calculate convergence
    const activeSignals = signals.filter(s => s.active);
    const convergenceScore = this.calculateConvergenceScore(activeSignals);

    // STEP 7: Determine if should flag (high sensitivity mode)
    const shouldFlag = this.shouldFlagQuery(activeSignals, convergenceScore, semanticZone);
    const flagReason = this.generateFlagReason(activeSignals, semanticZone);

    return {
      query,
      signals,
      activeSignals,
      convergenceScore,
      activeSignalCount: activeSignals.length,
      shouldFlag,
      flagReason,
      semanticZone,
    };
  }

  /**
   * Evaluate embedding-based semantic similarity to known scam phrases
   */
  private async evaluateEmbeddingSignal(query: string): Promise<DetectionSignal> {
    const signal: DetectionSignal = {
      type: 'embedding',
      active: false,
      strength: 0,
      confidence: 0,
      details: 'No semantic match to known scam patterns',
    };

    if (!this.embeddingService.isReady()) {
      return signal;
    }

    try {
      const matches = await this.embeddingService.findSimilarPhrases(
        query,
        HIGH_SENSITIVITY_THRESHOLDS.embedding
      );

      if (matches.length > 0) {
        const topMatch = matches[0];
        signal.active = true;
        signal.strength = topMatch.similarity;
        signal.confidence = 0.9; // High confidence in embedding matches
        signal.details = `Semantic match to "${topMatch.phrase}" (${(topMatch.similarity * 100).toFixed(1)}% similarity, ${topMatch.category})`;
        signal.metadata = {
          matchedPhrase: topMatch.phrase,
          category: topMatch.category,
          severity: topMatch.severity,
          similarity: topMatch.similarity,
        };
      }
    } catch (error) {
      this.logger.debug(`Embedding evaluation failed for "${query}": ${error.message}`);
    }

    return signal;
  }

  /**
   * Evaluate CTR anomaly signal
   * Low CTR at good position indicates users clicking elsewhere (potentially scam sites)
   */
  private evaluateCTRAnomalySignal(term: TermComparison, benchmarks: CTRBenchmarks): DetectionSignal {
    const ctrAnomaly = this.calculateCTRAnomaly(term.current.ctr, term.current.position, benchmarks);

    const signal: DetectionSignal = {
      type: 'ctr_anomaly',
      active: false,
      strength: ctrAnomaly.anomalyScore,
      confidence: 0.85,
      details: `CTR ${(ctrAnomaly.actualCTR * 100).toFixed(2)}% vs expected ${(ctrAnomaly.expectedCTR * 100).toFixed(2)}%`,
    };

    // Active if anomaly score exceeds threshold
    if (ctrAnomaly.anomalyScore >= HIGH_SENSITIVITY_THRESHOLDS.ctr_anomaly || ctrAnomaly.isAnomalous) {
      signal.active = true;
      signal.details = `CTR anomaly: ${(ctrAnomaly.actualCTR * 100).toFixed(2)}% actual vs ${(ctrAnomaly.expectedCTR * 100).toFixed(2)}% expected (position ${term.current.position.toFixed(1)})`;
      signal.metadata = { ctrAnomaly };
    }

    return signal;
  }

  /**
   * Calculate CTR anomaly based on position benchmarks
   */
  private calculateCTRAnomaly(actualCTR: number, position: number, benchmarks: CTRBenchmarks): CTRAnomaly {
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

    let anomalyScore = 0;
    if (actualCTR < expectedCTR) {
      anomalyScore = Math.min(1, (expectedCTR - actualCTR) / expectedCTR);
    }

    return {
      expectedCTR,
      actualCTR,
      anomalyScore,
      isAnomalous: actualCTR < minCTR,
    };
  }

  /**
   * Evaluate pattern match signal (dollar amounts, urgency words, etc.)
   */
  private evaluatePatternSignal(query: string): DetectionSignal {
    const matchedPatterns: string[] = [];

    // Check for dollar amounts
    const dollarMatch = query.match(DYNAMIC_PATTERNS.dollarAmount);
    if (dollarMatch) {
      matchedPatterns.push(`DOLLAR: ${dollarMatch[0]}`);
    }

    // Check for urgency words
    const urgencyMatch = query.match(DYNAMIC_PATTERNS.urgencyWords);
    if (urgencyMatch) {
      matchedPatterns.push(`URGENCY: ${urgencyMatch[0]}`);
    }

    // Check for free money patterns
    const freeMoneyMatch = query.match(DYNAMIC_PATTERNS.freeMoneyPattern);
    if (freeMoneyMatch) {
      matchedPatterns.push(`FREE_MONEY: ${freeMoneyMatch[0]}`);
    }

    // Check for future year patterns (common in fake benefit scams)
    const yearMatch = query.match(DYNAMIC_PATTERNS.yearPattern);
    if (yearMatch) {
      const year = parseInt(yearMatch[0]);
      const currentYear = new Date().getFullYear();
      if (year > currentYear) {
        matchedPatterns.push(`FUTURE_YEAR: ${yearMatch[0]}`);
      }
    }

    const signal: DetectionSignal = {
      type: 'pattern_match',
      active: matchedPatterns.length > 0,
      strength: Math.min(1, matchedPatterns.length * 0.3),
      confidence: 0.8,
      details: matchedPatterns.length > 0
        ? `Matched patterns: ${matchedPatterns.join(', ')}`
        : 'No suspicious patterns detected',
      metadata: { matchedPatterns },
    };

    return signal;
  }

  /**
   * Evaluate velocity signal (how fast impressions are growing)
   */
  private evaluateVelocitySignal(term: TermComparison, days: number): DetectionSignal {
    const velocity = this.calculateVelocity(term, days);

    const signal: DetectionSignal = {
      type: 'velocity',
      active: false,
      strength: velocity.velocityScore,
      confidence: 0.7,
      details: `${velocity.impressionsPerDay} impressions/day, trend: ${velocity.trend}`,
      metadata: { velocity },
    };

    // Active if velocity exceeds threshold or is accelerating with volume
    if (velocity.velocityScore >= HIGH_SENSITIVITY_THRESHOLDS.velocity ||
        (velocity.trend === 'accelerating' && term.current.impressions >= 50)) {
      signal.active = true;
      signal.details = `High velocity: ${velocity.impressionsPerDay} impressions/day (${velocity.trend})`;
    }

    return signal;
  }

  /**
   * Calculate velocity metrics for a term
   */
  private calculateVelocity(term: TermComparison, days: number): VelocityMetrics {
    const impressionDelta = term.change.impressions;
    const impressionsPerDay = days > 0 ? impressionDelta / days : 0;
    const velocityScore = Math.min(1, Math.max(0, impressionsPerDay / 500));

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
   * Calculate weighted convergence score from active signals
   */
  private calculateConvergenceScore(activeSignals: DetectionSignal[]): number {
    if (activeSignals.length === 0) {
      return 0;
    }

    let score = 0;
    for (const signal of activeSignals) {
      const weight = DEFAULT_SIGNAL_WEIGHTS[signal.type] || 0.1;
      score += signal.strength * signal.confidence * weight;
    }

    // Normalize to 0-100 scale
    return Math.min(100, Math.round(score * 100));
  }

  /**
   * Determine if query should be flagged based on signals
   * HIGH SENSITIVITY MODE: Flag if ANY meaningful signal fires
   */
  private shouldFlagQuery(
    activeSignals: DetectionSignal[],
    convergenceScore: number,
    semanticZone: SemanticZoneResult
  ): boolean {
    // If in a legitimate zone with decent confidence, don't flag
    if (semanticZone.isLegitimate && semanticZone.similarity >= 0.80) {
      return false;
    }

    // HIGH SENSITIVITY: Flag if any signal is active (minSignalsToFlag = 1)
    if (activeSignals.length >= HIGH_SENSITIVITY_THRESHOLDS.minSignalsToFlag) {
      return true;
    }

    // Also flag if convergence score is above threshold
    if (convergenceScore >= HIGH_SENSITIVITY_THRESHOLDS.convergence * 100) {
      return true;
    }

    return false;
  }

  /**
   * Generate human-readable flag reason
   */
  private generateFlagReason(
    activeSignals: DetectionSignal[],
    semanticZone: SemanticZoneResult
  ): string {
    if (activeSignals.length === 0) {
      return 'No suspicious signals detected';
    }

    const reasons: string[] = [];

    for (const signal of activeSignals) {
      switch (signal.type) {
        case 'embedding':
          reasons.push(`semantic match (${signal.details})`);
          break;
        case 'ctr_anomaly':
          reasons.push(`CTR anomaly (${signal.details})`);
          break;
        case 'pattern_match':
          reasons.push(`pattern match (${signal.details})`);
          break;
        case 'velocity':
          reasons.push(`high velocity (${signal.details})`);
          break;
        case 'trends':
          reasons.push(`trending (${signal.details})`);
          break;
      }
    }

    // Add note about semantic zone if close to legitimate
    if (semanticZone.similarity >= 0.60 && semanticZone.similarity < 0.80) {
      reasons.push(`note: ${(semanticZone.similarity * 100).toFixed(0)}% similar to "${semanticZone.nearestCategory}"`);
    }

    return reasons.join('; ');
  }

  /**
   * Batch evaluate signals for multiple queries
   * More efficient than calling evaluateSignals for each query
   */
  async batchEvaluateSignals(
    terms: TermComparison[],
    benchmarks: CTRBenchmarks,
    days: number
  ): Promise<SignalConvergenceResult[]> {
    const results: SignalConvergenceResult[] = [];

    // First, batch check semantic zones
    const queries = terms.map(t => t.query);
    const semanticZones = await this.categoryCentroidService.batchCheckLegitimateZone(queries);

    // Create a map for quick lookup
    const semanticZoneMap = new Map<string, SemanticZoneResult>();
    for (const zone of semanticZones) {
      semanticZoneMap.set(zone.query, zone);
    }

    // Batch get embedding matches for non-legitimate queries
    const nonLegitimateTerms = terms.filter((t, i) => {
      const zone = semanticZones[i];
      return !zone.isLegitimate || zone.similarity < 0.85;
    });

    // Get embedding matches for all non-legitimate queries at once
    const embeddingResultsMap = new Map<string, { phrase: string; category: string; severity: string; similarity: number }>();

    if (this.embeddingService.isReady() && nonLegitimateTerms.length > 0) {
      try {
        const embeddingResults = await this.embeddingService.analyzeQueries(
          nonLegitimateTerms.map(t => t.query),
          HIGH_SENSITIVITY_THRESHOLDS.embedding
        );

        for (const result of embeddingResults) {
          if (result.topMatch) {
            embeddingResultsMap.set(result.query.toLowerCase(), {
              phrase: result.topMatch.phrase,
              category: result.topMatch.category,
              severity: result.topMatch.severity,
              similarity: result.topMatch.similarity,
            });
          }
        }
      } catch (error) {
        this.logger.warn(`Batch embedding analysis failed: ${error.message}`);
      }
    }

    // Now evaluate each term with pre-computed data
    for (let i = 0; i < terms.length; i++) {
      const term = terms[i];
      const query = term.query.toLowerCase().trim();
      const semanticZone = semanticZoneMap.get(query) || semanticZones[i];
      const signals: DetectionSignal[] = [];

      // Early exit for clearly legitimate queries
      if (semanticZone.isLegitimate && semanticZone.similarity >= 0.85) {
        results.push({
          query,
          signals: [],
          activeSignals: [],
          convergenceScore: 0,
          activeSignalCount: 0,
          shouldFlag: false,
          flagReason: `Legitimate query - matched "${semanticZone.nearestCategory}" with ${(semanticZone.similarity * 100).toFixed(1)}% similarity`,
          semanticZone,
        });
        continue;
      }

      // Embedding signal (from pre-computed results)
      const embeddingMatch = embeddingResultsMap.get(query);
      const embeddingSignal: DetectionSignal = {
        type: 'embedding',
        active: !!embeddingMatch,
        strength: embeddingMatch?.similarity || 0,
        confidence: 0.9,
        details: embeddingMatch
          ? `Semantic match to "${embeddingMatch.phrase}" (${(embeddingMatch.similarity * 100).toFixed(1)}% similarity)`
          : 'No semantic match to known scam patterns',
        metadata: embeddingMatch,
      };
      signals.push(embeddingSignal);

      // CTR signal
      const ctrSignal = this.evaluateCTRAnomalySignal(term, benchmarks);
      signals.push(ctrSignal);

      // Pattern signal
      const patternSignal = this.evaluatePatternSignal(query);
      signals.push(patternSignal);

      // Velocity signal
      const velocitySignal = this.evaluateVelocitySignal(term, days);
      signals.push(velocitySignal);

      // Calculate convergence
      const activeSignals = signals.filter(s => s.active);
      const convergenceScore = this.calculateConvergenceScore(activeSignals);
      const shouldFlag = this.shouldFlagQuery(activeSignals, convergenceScore, semanticZone);
      const flagReason = this.generateFlagReason(activeSignals, semanticZone);

      results.push({
        query,
        signals,
        activeSignals,
        convergenceScore,
        activeSignalCount: activeSignals.length,
        shouldFlag,
        flagReason,
        semanticZone,
      });
    }

    return results;
  }

  /**
   * Get current thresholds configuration
   */
  getThresholds(): typeof HIGH_SENSITIVITY_THRESHOLDS {
    return { ...HIGH_SENSITIVITY_THRESHOLDS };
  }

  /**
   * Get current signal weights configuration
   */
  getWeights(): SignalWeights {
    return { ...DEFAULT_SIGNAL_WEIGHTS };
  }
}
