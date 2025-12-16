import { Injectable, Logger, forwardRef, Inject, OnModuleInit } from '@nestjs/common';
import { CacheService } from './cache.service';
import { SearchConsoleService } from './search-console.service';
import { EmbeddingService } from './embedding.service';
import { DynamoDbService } from './dynamodb.service';
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

// Seed phrase for matching
type SeedPhraseMatch = {
  term: string;
  category: string;
  severity: string;
};

@Injectable()
export class ScamDetectionService implements OnModuleInit {
  private readonly logger = new Logger(ScamDetectionService.name);
  private keywordsConfig: ScamKeywordsConfig;
  private seenTerms: Map<string, string> = new Map(); // query -> firstSeen ISO date
  private allSeedPhrases: SeedPhraseMatch[] = []; // All DynamoDB seed phrases (except whitelist/seen-term)

  constructor(
    private readonly cacheService: CacheService,
    private readonly searchConsoleService: SearchConsoleService,
    @Inject(forwardRef(() => EmbeddingService))
    private readonly embeddingService: EmbeddingService,
    private readonly dynamoDbService: DynamoDbService,
  ) {
    this.keywordsConfig = scamKeywordsJson as unknown as ScamKeywordsConfig;
    this.logger.log(
      `Loaded scam keywords config v${this.keywordsConfig.version}`
    );
  }

  async onModuleInit(): Promise<void> {
    // Wait for DynamoDB service to be ready before loading
    await this.waitForDynamoDB();
    await this.loadFromDynamoDB();
  }

  /**
   * Wait for DynamoDB service to initialize (max 10 seconds)
   */
  private async waitForDynamoDB(): Promise<void> {
    const maxWait = 10000; // 10 seconds
    const checkInterval = 100; // 100ms
    let waited = 0;

    while (!this.dynamoDbService.isReady() && waited < maxWait) {
      await new Promise(resolve => setTimeout(resolve, checkInterval));
      waited += checkInterval;
    }

    if (this.dynamoDbService.isReady()) {
      this.logger.log(`[STARTUP] DynamoDB service ready after ${waited}ms`);
    } else {
      this.logger.warn(`[STARTUP] DynamoDB service not ready after ${maxWait}ms, proceeding with JSON config only`);
    }
  }

  /**
   * Load keywords from DynamoDB and merge with JSON config
   */
  private async loadFromDynamoDB(): Promise<void> {
    try {
      // Log initial state from JSON
      this.logger.log(`[STARTUP] Initial keyword counts from JSON config:`);
      for (const [catName, cat] of Object.entries(this.keywordsConfig.categories)) {
        this.logger.log(`  - ${catName}: ${cat.terms.length} terms`);
      }

      // Load keywords from DynamoDB
      const dbKeywords = await this.dynamoDbService.getAllKeywords();
      this.logger.log(`[STARTUP] Found ${dbKeywords.length} keyword records in DynamoDB`);

      let keywordsAdded = 0;
      const addedByCategory: Record<string, string[]> = {};

      for (const record of dbKeywords) {
        const categoryName = record.category.replace('keyword:', '');
        const category = this.keywordsConfig.categories[categoryName as keyof ScamKeywordsConfig['categories']];
        if (category && !category.terms.includes(record.term)) {
          category.terms.push(record.term);
          keywordsAdded++;
          if (!addedByCategory[categoryName]) {
            addedByCategory[categoryName] = [];
          }
          addedByCategory[categoryName].push(record.term);
        }
      }

      if (keywordsAdded > 0) {
        this.logger.log(`[STARTUP] Merged ${keywordsAdded} keywords from DynamoDB:`);
        for (const [catName, terms] of Object.entries(addedByCategory)) {
          this.logger.log(`  - ${catName}: +${terms.length} terms (${terms.slice(0, 5).join(', ')}${terms.length > 5 ? '...' : ''})`);
        }
      } else {
        this.logger.log(`[STARTUP] No new keywords to merge from DynamoDB`);
      }

      // Log final state
      this.logger.log(`[STARTUP] Final keyword counts after DynamoDB merge:`);
      for (const [catName, cat] of Object.entries(this.keywordsConfig.categories)) {
        this.logger.log(`  - ${catName}: ${cat.terms.length} terms`);
      }

      // Load seen flagged terms (for new vs returning tracking)
      this.seenTerms = await this.dynamoDbService.getSeenTerms();
      this.logger.log(`[STARTUP] Loaded ${this.seenTerms.size} previously seen flagged terms`);

      // Load ALL seed phrases from DynamoDB (excludes whitelist and seen-term)
      // These are used for Dashboard detection in addition to keyword categories
      const dbSeedPhrases = await this.dynamoDbService.getAllSeedPhrases();
      this.allSeedPhrases = dbSeedPhrases.map(record => ({
        term: record.term.toLowerCase(),
        category: record.category,
        severity: record.severity,
      }));
      this.logger.log(`[STARTUP] Loaded ${this.allSeedPhrases.length} seed phrases for Dashboard matching`);

    } catch (error) {
      this.logger.warn(`[STARTUP] Failed to load from DynamoDB: ${error.message}`);
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

        this.logger.log(`[DETECT] Using ${this.allSeedPhrases.length} seed phrases from DynamoDB`);

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

        // Update status based on whether terms have been seen before
        // Terms seen within 7 days are still "new", older ones are "active" (returning)
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const newlySeenTerms: string[] = [];

        for (const term of flaggedTerms) {
          const normalizedQuery = term.query.toLowerCase().trim();
          const previousFirstSeen = this.seenTerms.get(normalizedQuery);

          if (previousFirstSeen) {
            // Term was seen before
            term.firstDetected = previousFirstSeen;
            const firstSeenDate = new Date(previousFirstSeen);
            if (firstSeenDate < sevenDaysAgo) {
              // Seen more than 7 days ago = returning/active
              term.status = 'active';
            } else {
              // Seen within last 7 days = still "new"
              term.status = 'new';
            }
          } else {
            // Truly new term - never seen before
            term.firstDetected = new Date().toISOString();
            term.status = 'new';
            newlySeenTerms.push(normalizedQuery);
            // Update local cache
            this.seenTerms.set(normalizedQuery, term.firstDetected);
          }
        }

        // Persist newly seen terms to DynamoDB (don't await to avoid blocking)
        if (newlySeenTerms.length > 0) {
          this.logger.log(`[DETECT] Found ${newlySeenTerms.length} truly new terms, persisting to DynamoDB`);
          this.dynamoDbService.markTermsAsSeen(newlySeenTerms).catch((err) => {
            this.logger.warn(`[DETECT] Failed to persist seen terms: ${err.message}`);
          });
        }

        const newCount = flaggedTerms.filter((t) => t.status === 'new').length;
        const activeCount = flaggedTerms.filter((t) => t.status === 'active').length;
        this.logger.log(`[DETECT] Term status breakdown: ${newCount} new (within 7 days), ${activeCount} returning`);

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
   * Only checks against DynamoDB seed phrases - no static JSON pattern matching
   */
  private analyzeQuery(row: SearchAnalyticsRow): FlaggedTerm | null {
    const query = row.keys[0]?.toLowerCase() || '';

    // Only check against DynamoDB seed phrases
    const seedPhraseMatch = this.checkSeedPhrases(query);
    if (!seedPhraseMatch.matched) {
      return null;
    }

    let severity = this.mapSeverity(seedPhraseMatch.severity);

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
      matchedCategory: seedPhraseMatch.category,
      matchedPatterns: seedPhraseMatch.patterns,
      firstDetected: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'new',
    };
  }

  /**
   * Check against all DynamoDB seed phrases (excludes whitelist and seen-term)
   */
  private checkSeedPhrases(
    query: string
  ): { matched: boolean; patterns: string[]; category: string; severity: string } {
    const matched: string[] = [];
    let category = '';
    let severity = 'medium';

    for (const seedPhrase of this.allSeedPhrases) {
      if (query.includes(seedPhrase.term)) {
        matched.push(seedPhrase.term);
        if (!category) {
          category = seedPhrase.category;
          severity = seedPhrase.severity;
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

  getTrendsKeywords(): string[] {
    return this.keywordsConfig.trendsKeywords;
  }

  async addKeyword(term: string, category: keyof ScamKeywordsConfig['categories']): Promise<void> {
    this.logger.log(`[ADD_KEYWORD] Request to add "${term}" to category "${category}"`);

    if (this.keywordsConfig.categories[category]) {
      const terms = this.keywordsConfig.categories[category].terms;
      const termLower = term.toLowerCase();

      if (!terms.includes(termLower)) {
        const countBefore = terms.length;
        terms.push(termLower);
        this.logger.log(`[ADD_KEYWORD] Added "${termLower}" to in-memory config (${category}: ${countBefore} → ${terms.length} terms)`);

        this.logger.log(`[ADD_KEYWORD] Flushing cache...`);
        this.cacheService.flush();

        // Persist to DynamoDB
        this.logger.log(`[ADD_KEYWORD] Persisting to DynamoDB...`);
        const dbSuccess = await this.dynamoDbService.addKeyword(term, category);
        this.logger.log(`[ADD_KEYWORD] DynamoDB persist: ${dbSuccess ? 'SUCCESS' : 'FAILED'}`);

        // Also add to embedding service for semantic matching
        const severity = this.keywordsConfig.categories[category].severity;
        this.logger.log(`[ADD_KEYWORD] Adding to embedding service...`);
        await this.embeddingService.addSeedPhrase(term, category, severity);

        this.logger.log(`[ADD_KEYWORD] Complete. "${termLower}" is now active in ${category}`);
      } else {
        this.logger.log(`[ADD_KEYWORD] Term "${termLower}" already exists in ${category}, skipping`);
      }
    } else {
      this.logger.warn(`[ADD_KEYWORD] Category "${category}" not found in config`);
    }
  }
}
