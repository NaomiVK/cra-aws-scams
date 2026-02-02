import { Injectable, Logger, forwardRef, Inject, OnModuleInit } from '@nestjs/common';
import { CacheService } from './cache.service';
import { SearchConsoleService } from './search-console.service';
import { EmbeddingService } from './embedding.service';
import { DynamoDbService } from './dynamodb.service';
import { TermService } from './term.service';
import {
  FlaggedTerm,
  Severity,
  ScamDetectionResult,
  ScamKeywordsConfig,
  DateRange,
  UnifiedTerm,
  TermCategory,
} from '@cra-scam-detection/shared-types';
import { SearchAnalyticsRow } from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';
import * as scamKeywordsJson from '../config/scam-keywords.json';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ScamDetectionService implements OnModuleInit {
  private readonly logger = new Logger(ScamDetectionService.name);
  private keywordsConfig: ScamKeywordsConfig;

  constructor(
    private readonly cacheService: CacheService,
    private readonly searchConsoleService: SearchConsoleService,
    @Inject(forwardRef(() => EmbeddingService))
    private readonly embeddingService: EmbeddingService,
    private readonly dynamoDbService: DynamoDbService,
    @Inject(forwardRef(() => TermService))
    private readonly termService: TermService,
  ) {
    this.keywordsConfig = scamKeywordsJson as unknown as ScamKeywordsConfig;
    this.logger.log(
      `Loaded scam keywords config v${this.keywordsConfig.version}`
    );
  }

  async onModuleInit(): Promise<void> {
    // Wait for TermService to be ready
    await this.waitForTermService();
  }

  /**
   * Wait for TermService to initialize (max 10 seconds)
   */
  private async waitForTermService(): Promise<void> {
    const maxWait = 10000; // 10 seconds
    const checkInterval = 100; // 100ms
    let waited = 0;

    while (!this.termService.isReady() && waited < maxWait) {
      await new Promise(resolve => setTimeout(resolve, checkInterval));
      waited += checkInterval;
    }

    if (this.termService.isReady()) {
      this.logger.log(`[STARTUP] TermService ready after ${waited}ms`);
    } else {
      this.logger.warn(`[STARTUP] TermService not ready after ${maxWait}ms`);
    }
  }

  /**
   * Run scam detection analysis for a date range
   */
  async detectScams(dateRange: DateRange): Promise<ScamDetectionResult> {
    const cacheKey = `scams:${dateRange.startDate}:${dateRange.endDate}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        this.logger.log(
          `[DETECT] Running scam detection for ${dateRange.startDate} to ${dateRange.endDate}`
        );

        // Get pattern match terms from TermService
        const patternMatchTerms = this.termService.getPatternMatchTerms();
        this.logger.log(`[DETECT] Using ${patternMatchTerms.length} pattern match terms from TermService`);

        // Get search analytics data
        const analyticsData =
          await this.searchConsoleService.getQueriesAboveThreshold(
            dateRange,
            environment.scamDetection.impressionThreshold
          );

        this.logger.log(
          `Analyzing ${analyticsData.length} queries with ${environment.scamDetection.impressionThreshold}+ impressions`
        );

        // Analyze each query
        const flaggedTerms: FlaggedTerm[] = [];

        for (const row of analyticsData) {
          const result = this.analyzeQuery(row, patternMatchTerms);
          if (result) {
            flaggedTerms.push(result);
          }
        }

        // Sort by severity then impressions
        flaggedTerms.sort((a, b) => {
          const severityOrder: Record<Severity, number> = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            info: 4,
          };
          const severityDiff =
            severityOrder[a.severity] - severityOrder[b.severity];
          if (severityDiff !== 0) return severityDiff;
          return b.impressions - a.impressions;
        });

        const result: ScamDetectionResult = {
          analysisDate: new Date().toISOString(),
          period: dateRange,
          totalQueriesAnalyzed: analyticsData.length,
          flaggedTerms,
          summary: {
            critical: flaggedTerms.filter((t) => t.severity === 'critical')
              .length,
            high: flaggedTerms.filter((t) => t.severity === 'high').length,
            medium: flaggedTerms.filter((t) => t.severity === 'medium').length,
            low: flaggedTerms.filter((t) => t.severity === 'low').length,
            info: flaggedTerms.filter((t) => t.severity === 'info').length,
            total: flaggedTerms.length,
          },
        };

        this.logger.log(
          `Detection complete: ${result.summary.total} flagged terms ` +
            `(${result.summary.critical} critical, ${result.summary.high} high)`
        );

        return result;
      },
      environment.cache.keywordsTtl
    );
  }

  /**
   * Analyze a single query for scam patterns
   * Checks against pattern match terms from TermService
   */
  private analyzeQuery(row: SearchAnalyticsRow, patternMatchTerms: UnifiedTerm[]): FlaggedTerm | null {
    const query = row.keys[0]?.toLowerCase() || '';

    // Check against pattern match terms
    const matchResult = this.checkPatternMatchTerms(query, patternMatchTerms);
    if (!matchResult.matched) {
      return null;
    }

    let severity = this.mapSeverity(matchResult.severity);

    // Apply seasonal multiplier (could upgrade severity)
    severity = this.applySeasonalAdjustment(severity);

    return {
      id: uuidv4(),
      query,
      impressions: row.impressions,
      clicks: row.clicks,
      ctr: row.ctr,
      position: row.position,
      severity,
      matchedCategory: matchResult.category,
      matchedPatterns: matchResult.patterns,
      firstDetected: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'new',
    };
  }

  /**
   * Check if query exactly matches an existing keyword or seed phrase
   * Used for filtering emerging threats that have already been added
   */
  isExactKeywordMatch(query: string): boolean {
    return this.termService.termExists(query);
  }

  /**
   * Check query against pattern match terms from TermService
   */
  private checkPatternMatchTerms(
    query: string,
    terms: UnifiedTerm[]
  ): { matched: boolean; patterns: string[]; category: string; severity: string } {
    const matched: string[] = [];
    let category = '';
    let severity = 'medium';

    const normalizedQuery = query.toLowerCase().trim();

    for (const term of terms) {
      // Exact match only - query must exactly match the term
      if (normalizedQuery === term.term.toLowerCase().trim()) {
        matched.push(term.term);
        if (!category) {
          category = term.category;
          severity = term.severity;
        }
      }
    }

    return { matched: matched.length > 0, patterns: matched, category, severity };
  }

  /**
   * Map severity string to Severity type
   */
  private mapSeverity(severityStr: string): Severity {
    const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const normalized = severityStr.toLowerCase() as Severity;
    return validSeverities.includes(normalized) ? normalized : 'medium';
  }

  /**
   * Apply seasonal adjustments to severity
   */
  private applySeasonalAdjustment(baseSeverity: Severity): Severity {
    const now = new Date();
    const month = now.getMonth() + 1; // 1-12
    const day = now.getDate();

    const seasonal = this.keywordsConfig.seasonalMultipliers;

    // Check tax season
    if (
      (month === seasonal.taxSeason.startMonth &&
        day >= seasonal.taxSeason.startDay) ||
      (month > seasonal.taxSeason.startMonth &&
        month < seasonal.taxSeason.endMonth) ||
      (month === seasonal.taxSeason.endMonth &&
        day <= seasonal.taxSeason.endDay)
    ) {
      // During tax season, upgrade medium to high
      if (baseSeverity === 'medium') {
        return 'high';
      }
    }

    // Check GST/CCR payment dates
    const isPaymentDate =
      (seasonal.gstPayment.months.includes(month) &&
        seasonal.gstPayment.days.includes(day)) ||
      (seasonal.ccrPayment.months.includes(month) &&
        seasonal.ccrPayment.days.includes(day));

    if (isPaymentDate) {
      // On payment dates, upgrade high to critical
      if (baseSeverity === 'high') {
        return 'critical';
      }
    }

    return baseSeverity;
  }

  getKeywordsConfig(): ScamKeywordsConfig {
    return this.keywordsConfig;
  }

  /**
   * Get all seed phrases for UI dropdowns
   * Returns terms from TermService
   */
  getSeedPhrases(): { term: string; category: string }[] {
    return this.termService.getPatternMatchTerms().map(t => ({
      term: t.term,
      category: t.category,
    }));
  }

  /**
   * Add a keyword (legacy method - delegates to TermService)
   * Kept for backward compatibility with existing API
   */
  async addKeyword(term: string, category: keyof ScamKeywordsConfig['categories']): Promise<void> {
    this.logger.log(`[ADD_KEYWORD] Request to add "${term}" to category "${category}"`);

    const severity = this.keywordsConfig.categories[category]?.severity || 'medium';

    // Add via TermService with both pattern match and embedding enabled
    const success = await this.termService.addTerm({
      term,
      category: category as TermCategory,
      severity: severity as Severity,
      useForPatternMatch: true,
      useForEmbedding: true,
      mustContainCra: false,
    });

    if (success) {
      // Also add to embedding service for semantic matching (immediate effect)
      await this.embeddingService.addSeedPhrase(term, category, severity);
      this.logger.log(`[ADD_KEYWORD] Complete. "${term}" is now active in ${category}`);
    } else {
      this.logger.warn(`[ADD_KEYWORD] Failed to add "${term}" to ${category}`);
    }
  }
}
