import { Injectable, Logger } from '@nestjs/common';
import { CacheService } from './cache.service';
import { SearchConsoleService } from './search-console.service';
import {
  FlaggedTerm,
  Severity,
  ScamDetectionResult,
  ScamKeywordsConfig,
  DateRange,
} from '@cra-scam-detection/shared-types';
import { SearchAnalyticsRow } from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';
import * as scamKeywordsJson from '../config/scam-keywords.json';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ScamDetectionService {
  private readonly logger = new Logger(ScamDetectionService.name);
  private keywordsConfig: ScamKeywordsConfig;

  constructor(
    private readonly cacheService: CacheService,
    private readonly searchConsoleService: SearchConsoleService
  ) {
    this.keywordsConfig = scamKeywordsJson as unknown as ScamKeywordsConfig;
    this.logger.log(
      `Loaded scam keywords config v${this.keywordsConfig.version}`
    );
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
          `Running scam detection for ${dateRange.startDate} to ${dateRange.endDate}`
        );

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
          const result = this.analyzeQuery(row);
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
   */
  private analyzeQuery(row: SearchAnalyticsRow): FlaggedTerm | null {
    const query = row.keys[0]?.toLowerCase() || '';

    // Check whitelist first
    if (this.isWhitelisted(query)) {
      return null;
    }

    const matchedPatterns: string[] = [];
    let matchedCategory = '';
    let severity: Severity = 'info';

    // Check fake/expired benefits (standalone terms)
    const fakeMatch = this.checkFakeExpiredBenefits(query);
    if (fakeMatch.matched) {
      matchedPatterns.push(...fakeMatch.patterns);
      matchedCategory = 'Fake/Expired Benefits';
      severity = 'critical';
    }

    // Check illegitimate payment methods (contextual - must contain CRA reference)
    const paymentMatch = this.checkIllegitimatePaymentMethods(query);
    if (paymentMatch.matched) {
      matchedPatterns.push(...paymentMatch.patterns);
      if (!matchedCategory) {
        matchedCategory = 'Illegitimate Payment Methods';
        severity = 'critical';
      }
    }

    // Check threat language (contextual - must contain CRA reference)
    const threatMatch = this.checkThreatLanguage(query);
    if (threatMatch.matched) {
      matchedPatterns.push(...threatMatch.patterns);
      if (!matchedCategory) {
        matchedCategory = 'Threat Language';
        severity = 'high';
      }
    }

    // Check suspicious modifiers
    const modifierMatch = this.checkSuspiciousModifiers(query);
    if (modifierMatch.matched) {
      matchedPatterns.push(...modifierMatch.patterns);
      if (!matchedCategory) {
        matchedCategory = 'Suspicious Modifiers';
        severity = 'medium';
      }
    }

    // If no patterns matched, not flagged
    if (matchedPatterns.length === 0) {
      return null;
    }

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
      matchedCategory,
      matchedPatterns,
      firstDetected: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'new',
    };
  }

  /**
   * Check if query is whitelisted (legitimate search)
   * Uses word-boundary matching to prevent partial matches
   * e.g., "t4" should not whitelist "fake t4 scam"
   */
  private isWhitelisted(query: string): boolean {
    const whitelist = this.keywordsConfig.whitelist.patterns;
    return whitelist.some((pattern) => {
      // Escape special regex characters in the pattern
      const escapedPattern = pattern.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Use word boundary matching for better accuracy
      const regex = new RegExp(`\\b${escapedPattern}\\b`, 'i');
      return regex.test(query);
    });
  }

  /**
   * Check for fake/expired benefit terms
   */
  private checkFakeExpiredBenefits(
    query: string
  ): { matched: boolean; patterns: string[] } {
    const category = this.keywordsConfig.categories.fakeExpiredBenefits;
    const matched: string[] = [];

    for (const term of category.terms) {
      if (query.includes(term.toLowerCase())) {
        matched.push(term);
      }
    }

    return { matched: matched.length > 0, patterns: matched };
  }

  /**
   * Check for illegitimate payment methods (contextual)
   */
  private checkIllegitimatePaymentMethods(
    query: string
  ): { matched: boolean; patterns: string[] } {
    const category = this.keywordsConfig.categories.illegitimatePaymentMethods;
    const mustContain = category.mustContain || [];

    // Check if query contains CRA context
    const hasCraContext = mustContain.some((ctx) =>
      query.includes(ctx.toLowerCase())
    );

    if (!hasCraContext) {
      return { matched: false, patterns: [] };
    }

    // Check for payment method terms
    const matched: string[] = [];
    for (const term of category.terms) {
      if (query.includes(term.toLowerCase())) {
        matched.push(`CRA + ${term}`);
      }
    }

    return { matched: matched.length > 0, patterns: matched };
  }

  /**
   * Check for threat language (contextual)
   */
  private checkThreatLanguage(
    query: string
  ): { matched: boolean; patterns: string[] } {
    const category = this.keywordsConfig.categories.threatLanguage;
    const mustContain = category.mustContain || [];

    // Check if query contains CRA context
    const hasCraContext = mustContain.some((ctx) =>
      query.includes(ctx.toLowerCase())
    );

    if (!hasCraContext) {
      return { matched: false, patterns: [] };
    }

    // Check for threat terms
    const matched: string[] = [];
    for (const term of category.terms) {
      if (query.includes(term.toLowerCase())) {
        matched.push(`CRA + ${term}`);
      }
    }

    return { matched: matched.length > 0, patterns: matched };
  }

  /**
   * Check for suspicious modifiers
   */
  private checkSuspiciousModifiers(
    query: string
  ): { matched: boolean; patterns: string[] } {
    const category = this.keywordsConfig.categories.suspiciousModifiers;
    const matched: string[] = [];

    for (const term of category.terms) {
      if (query.includes(term.toLowerCase())) {
        matched.push(term);
      }
    }

    return { matched: matched.length > 0, patterns: matched };
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

  getTrendsKeywords(): string[] {
    return this.keywordsConfig.trendsKeywords;
  }

  addKeyword(term: string, category: keyof ScamKeywordsConfig['categories']): void {
    if (this.keywordsConfig.categories[category]) {
      const terms = this.keywordsConfig.categories[category].terms;
      if (!terms.includes(term.toLowerCase())) {
        terms.push(term.toLowerCase());
        this.logger.log(`Added "${term}" to ${category}`);
        this.cacheService.flush();
      }
    }
  }

  addWhitelistPattern(pattern: string): void {
    const patterns = this.keywordsConfig.whitelist.patterns;
    if (!patterns.includes(pattern.toLowerCase())) {
      patterns.push(pattern.toLowerCase());
      this.logger.log(`Added "${pattern}" to whitelist`);
      this.cacheService.flush();
    }
  }
}
