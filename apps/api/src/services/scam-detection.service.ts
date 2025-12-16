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
   * Load keywords and whitelist from DynamoDB and merge with JSON config
   */
  private async loadFromDynamoDB(): Promise<void> {
    try {
      // Log initial state from JSON
      this.logger.log(`[STARTUP] Initial keyword counts from JSON config:`);
      for (const [catName, cat] of Object.entries(this.keywordsConfig.categories)) {
        this.logger.log(`  - ${catName}: ${cat.terms.length} terms`);
      }
      this.logger.log(`  - whitelist: ${this.keywordsConfig.whitelist.patterns.length} patterns`);

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

      // Load whitelist from DynamoDB
      const dbWhitelist = await this.dynamoDbService.getAllWhitelist();
      this.logger.log(`[STARTUP] Found ${dbWhitelist.length} whitelist records in DynamoDB`);

      let whitelistAdded = 0;
      const addedWhitelist: string[] = [];

      for (const record of dbWhitelist) {
        if (!this.keywordsConfig.whitelist.patterns.includes(record.term)) {
          this.keywordsConfig.whitelist.patterns.push(record.term);
          whitelistAdded++;
          addedWhitelist.push(record.term);
        }
      }

      if (whitelistAdded > 0) {
        this.logger.log(`[STARTUP] Merged ${whitelistAdded} whitelist patterns from DynamoDB: ${addedWhitelist.slice(0, 5).join(', ')}${addedWhitelist.length > 5 ? '...' : ''}`);
      } else {
        this.logger.log(`[STARTUP] No new whitelist patterns to merge from DynamoDB`);
      }

      // Log final state
      this.logger.log(`[STARTUP] Final keyword counts after DynamoDB merge:`);
      for (const [catName, cat] of Object.entries(this.keywordsConfig.categories)) {
        this.logger.log(`  - ${catName}: ${cat.terms.length} terms`);
      }
      this.logger.log(`  - whitelist: ${this.keywordsConfig.whitelist.patterns.length} patterns`);

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

        // Log current keyword counts being used for detection
        this.logger.log(`[DETECT] Current keyword counts in memory:`);
        for (const [catName, cat] of Object.entries(this.keywordsConfig.categories)) {
          this.logger.log(`  - ${catName}: ${cat.terms.length} terms`);
        }
        this.logger.log(`  - whitelist: ${this.keywordsConfig.whitelist.patterns.length} patterns`);

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
   * Note: No whitelist filtering - Dashboard only checks against known scam keywords
   */
  private analyzeQuery(row: SearchAnalyticsRow): FlaggedTerm | null {
    const query = row.keys[0]?.toLowerCase() || '';

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

    // Check against ALL DynamoDB seed phrases (excludes whitelist and seen-term)
    const seedPhraseMatch = this.checkSeedPhrases(query);
    if (seedPhraseMatch.matched) {
      matchedPatterns.push(...seedPhraseMatch.patterns);
      if (!matchedCategory) {
        matchedCategory = seedPhraseMatch.category;
        severity = this.mapSeverity(seedPhraseMatch.severity);
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
   * Uses regex pattern matching
   */
  isWhitelisted(query: string): boolean {
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
   * Check if query exactly matches a whitelisted term
   * Used for filtering emerging threats that have been explicitly whitelisted
   */
  isExactWhitelistMatch(query: string): boolean {
    const normalizedQuery = query.toLowerCase().trim();
    return this.keywordsConfig.whitelist.patterns.some(
      (pattern) => pattern.toLowerCase().trim() === normalizedQuery
    );
  }

  /**
   * Check if query exactly matches an existing keyword in any category
   * Used for filtering emerging threats that have already been added as keywords
   * (Config is synced with DynamoDB on startup and on every add)
   */
  isExactKeywordMatch(query: string): boolean {
    const normalizedQuery = query.toLowerCase().trim();
    const categories = this.keywordsConfig.categories;

    for (const categoryKey of Object.keys(categories)) {
      const category = categories[categoryKey as keyof typeof categories];
      if (category.terms.some((term) => term.toLowerCase().trim() === normalizedQuery)) {
        return true;
      }
    }
    return false;
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

  async addWhitelistPattern(pattern: string): Promise<void> {
    this.logger.log(`[ADD_WHITELIST] Request to add "${pattern}" to whitelist`);

    const patterns = this.keywordsConfig.whitelist.patterns;
    const patternLower = pattern.toLowerCase();

    if (!patterns.includes(patternLower)) {
      const countBefore = patterns.length;
      patterns.push(patternLower);
      this.logger.log(`[ADD_WHITELIST] Added "${patternLower}" to in-memory config (whitelist: ${countBefore} → ${patterns.length} patterns)`);

      this.logger.log(`[ADD_WHITELIST] Flushing cache...`);
      this.cacheService.flush();

      // Persist to DynamoDB
      this.logger.log(`[ADD_WHITELIST] Persisting to DynamoDB...`);
      const dbSuccess = await this.dynamoDbService.addWhitelist(pattern);
      this.logger.log(`[ADD_WHITELIST] DynamoDB persist: ${dbSuccess ? 'SUCCESS' : 'FAILED'}`);

      this.logger.log(`[ADD_WHITELIST] Complete. "${patternLower}" is now active in whitelist`);
    } else {
      this.logger.log(`[ADD_WHITELIST] Pattern "${patternLower}" already exists in whitelist, skipping`);
    }
  }
}
