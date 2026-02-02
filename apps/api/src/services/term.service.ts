import { Injectable, Logger, OnModuleInit, Inject, forwardRef } from '@nestjs/common';
import { DynamoDbService } from './dynamodb.service';
import { CacheService } from './cache.service';
import { EmbeddingService } from './embedding.service';
import {
  UnifiedTerm,
  Severity,
  TermCategory,
  AddTermRequest,
  UnifiedTermsResponse,
} from '@cra-scam-detection/shared-types';
import * as scamKeywordsJson from '../config/scam-keywords.json';
import * as seedPhrasesJson from '../config/seed-phrases.json';

type ScamKeywordsCategory = {
  id: string;
  name: string;
  description: string;
  severity: string;
  terms: string[];
  mustContain?: string[];
  patterns?: string[];
};

type SeedPhraseCategory = {
  severity: string;
  terms: string[];
};

/**
 * Category display names for UI
 */
const CATEGORY_DISPLAY_NAMES: Record<TermCategory, string> = {
  fakeExpiredBenefits: 'Fake/Expired Benefits',
  illegitimatePaymentMethods: 'Illegitimate Payment Methods',
  threatLanguage: 'Threat Language',
  suspiciousModifiers: 'Suspicious Modifiers',
  scamPatterns: 'Scam Patterns',
};

/**
 * Default severity by category
 */
const CATEGORY_SEVERITY: Record<TermCategory, Severity> = {
  fakeExpiredBenefits: 'critical',
  illegitimatePaymentMethods: 'critical',
  threatLanguage: 'high',
  suspiciousModifiers: 'medium',
  scamPatterns: 'high',
};

/**
 * Categories that require CRA context for pattern matching
 */
const CATEGORIES_REQUIRE_CRA: TermCategory[] = [
  'illegitimatePaymentMethods',
  'threatLanguage',
];

@Injectable()
export class TermService implements OnModuleInit {
  private readonly logger = new Logger(TermService.name);
  private terms: Map<string, UnifiedTerm> = new Map(); // key: `${category}:${term}`
  private initialized = false;

  constructor(
    private readonly dynamoDbService: DynamoDbService,
    private readonly cacheService: CacheService,
    @Inject(forwardRef(() => EmbeddingService))
    private readonly embeddingService: EmbeddingService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.loadTerms();
  }

  /**
   * Load terms from DynamoDB, seed from JSON if empty
   */
  async loadTerms(): Promise<void> {
    this.logger.log('[TERM_SERVICE] Loading terms...');

    // Check if we have unified terms in DynamoDB
    const hasUnifiedTerms = await this.dynamoDbService.hasUnifiedTerms();

    if (!hasUnifiedTerms) {
      this.logger.log('[TERM_SERVICE] No unified terms in DynamoDB');

      // First, migrate any existing keyword:* entries from old format
      await this.migrateExistingKeywords();

      // Then seed from JSON (will merge with migrated terms)
      await this.seedFromJson();
    }

    // Load all terms from DynamoDB
    const dbTerms = await this.dynamoDbService.getAllUnifiedTerms();
    this.terms.clear();

    for (const term of dbTerms) {
      const key = `${term.category}:${term.term.toLowerCase()}`;
      this.terms.set(key, term);
    }

    this.logger.log(`[TERM_SERVICE] Loaded ${this.terms.size} terms from DynamoDB`);
    this.initialized = true;

    // Log summary by category
    const categoryCounts = new Map<string, number>();
    for (const term of this.terms.values()) {
      if (!term.removedAt) {
        const count = categoryCounts.get(term.category) || 0;
        categoryCounts.set(term.category, count + 1);
      }
    }
    for (const [cat, count] of categoryCounts) {
      this.logger.log(`  - ${cat}: ${count} active terms`);
    }
  }

  /**
   * Migrate existing keyword:* entries from old DynamoDB format to new unified format
   * This preserves any terms that were added via the old admin UI
   */
  private async migrateExistingKeywords(): Promise<void> {
    this.logger.log('[TERM_SERVICE] Checking for existing keyword:* entries to migrate...');

    try {
      // Get existing keywords in old format (keyword:categoryName)
      const existingKeywords = await this.dynamoDbService.getAllKeywords();

      if (existingKeywords.length === 0) {
        this.logger.log('[TERM_SERVICE] No existing keyword:* entries to migrate');
        return;
      }

      this.logger.log(`[TERM_SERVICE] Found ${existingKeywords.length} existing keyword:* entries to migrate`);

      let migratedCount = 0;
      for (const record of existingKeywords) {
        // Extract category name (remove "keyword:" prefix)
        const categoryName = record.category.replace('keyword:', '') as TermCategory;

        // Determine severity from category
        const severity = CATEGORY_SEVERITY[categoryName] || 'medium';

        // Create unified term (both pattern match AND embedding enabled for admin-added terms)
        const unifiedTerm: UnifiedTerm = {
          term: record.term.toLowerCase().trim(),
          category: categoryName,
          severity,
          useForPatternMatch: true,
          useForEmbedding: true,
          mustContainCra: CATEGORIES_REQUIRE_CRA.includes(categoryName),
          source: 'admin', // These were added via admin UI, so mark as admin
          createdAt: record.createdAt || new Date().toISOString(),
        };

        const success = await this.dynamoDbService.saveUnifiedTerm(unifiedTerm);
        if (success) {
          migratedCount++;
        }
      }

      this.logger.log(`[TERM_SERVICE] Migrated ${migratedCount} existing keywords to unified format`);
    } catch (error) {
      this.logger.warn(`[TERM_SERVICE] Failed to migrate existing keywords: ${error.message}`);
    }
  }

  /**
   * Seed initial terms from both JSON files
   * Merges scam-keywords.json and seed-phrases.json
   * Skips terms that already exist from migration (admin-added terms take precedence)
   */
  private async seedFromJson(): Promise<void> {
    this.logger.log('[TERM_SERVICE] Seeding from JSON files...');

    // First, load any terms that already exist (from migration)
    const existingUnifiedTerms = await this.dynamoDbService.getAllUnifiedTerms();
    const existingKeys = new Set<string>();
    for (const term of existingUnifiedTerms) {
      existingKeys.add(`${term.category}:${term.term.toLowerCase()}`);
    }
    this.logger.log(`[TERM_SERVICE] Found ${existingKeys.size} already-migrated terms to preserve`);

    // Track terms we've seen to merge duplicates from JSON
    const seenTerms = new Map<string, UnifiedTerm>();

    // Load from scam-keywords.json (useForPatternMatch = true)
    const keywordsCategories = scamKeywordsJson.categories as Record<string, ScamKeywordsCategory>;
    for (const [categoryName, categoryData] of Object.entries(keywordsCategories)) {
      const category = categoryName as TermCategory;
      const mustContainCra = CATEGORIES_REQUIRE_CRA.includes(category);

      for (const term of categoryData.terms) {
        const key = `${category}:${term.toLowerCase()}`;

        // Skip if this term already exists from migration
        if (existingKeys.has(key)) {
          continue;
        }

        const existingTerm = seenTerms.get(key);

        if (existingTerm) {
          // Merge: enable pattern match
          existingTerm.useForPatternMatch = true;
        } else {
          seenTerms.set(key, {
            term: term.toLowerCase(),
            category,
            severity: categoryData.severity as Severity,
            useForPatternMatch: true,
            useForEmbedding: false,
            mustContainCra,
            source: 'json',
            createdAt: new Date().toISOString(),
          });
        }
      }
    }

    // Load from seed-phrases.json (useForEmbedding = true)
    const seedPhrases = seedPhrasesJson.phrases as Record<string, SeedPhraseCategory>;
    for (const [categoryName, categoryData] of Object.entries(seedPhrases)) {
      const category = categoryName as TermCategory;

      for (const term of categoryData.terms) {
        const key = `${category}:${term.toLowerCase()}`;

        // Skip if this term already exists from migration
        if (existingKeys.has(key)) {
          continue;
        }

        const existingTerm = seenTerms.get(key);

        if (existingTerm) {
          // Merge: enable embedding
          existingTerm.useForEmbedding = true;
        } else {
          seenTerms.set(key, {
            term: term.toLowerCase(),
            category,
            severity: categoryData.severity as Severity,
            useForPatternMatch: false,
            useForEmbedding: true,
            mustContainCra: false,
            source: 'json',
            createdAt: new Date().toISOString(),
          });
        }
      }
    }

    // Convert to array
    const termsToSeed: UnifiedTerm[] = [];
    for (const term of seenTerms.values()) {
      termsToSeed.push(term);
    }

    this.logger.log(`[TERM_SERVICE] Seeding ${termsToSeed.length} merged terms...`);

    // Save all terms to DynamoDB
    let savedCount = 0;
    for (const term of termsToSeed) {
      const success = await this.dynamoDbService.saveUnifiedTerm(term);
      if (success) savedCount++;
    }

    this.logger.log(`[TERM_SERVICE] Seeded ${savedCount} terms to DynamoDB`);
  }

  /**
   * Get all active terms (excludes removed)
   */
  getAllTerms(): UnifiedTerm[] {
    return Array.from(this.terms.values()).filter(t => !t.removedAt);
  }

  /**
   * Get all removed terms (for restore UI)
   */
  getRemovedTerms(): UnifiedTerm[] {
    return Array.from(this.terms.values()).filter(t => !!t.removedAt);
  }

  /**
   * Get terms for pattern matching (Dashboard)
   * Returns only active terms with useForPatternMatch = true
   */
  getPatternMatchTerms(): UnifiedTerm[] {
    return Array.from(this.terms.values()).filter(
      t => t.useForPatternMatch && !t.removedAt
    );
  }

  /**
   * Get terms for embedding (AI detection)
   * Returns only active terms with useForEmbedding = true
   */
  getEmbeddingTerms(): UnifiedTerm[] {
    return Array.from(this.terms.values()).filter(
      t => t.useForEmbedding && !t.removedAt
    );
  }

  /**
   * Get terms by category
   */
  getTermsByCategory(category: TermCategory): UnifiedTerm[] {
    return Array.from(this.terms.values()).filter(
      t => t.category === category && !t.removedAt
    );
  }

  /**
   * Add a new term
   * Also adds to embedding cache if useForEmbedding is true
   */
  async addTerm(request: AddTermRequest): Promise<boolean> {
    const normalizedTerm = request.term.toLowerCase().trim();
    const key = `${request.category}:${normalizedTerm}`;

    // Check if term already exists
    const existing = this.terms.get(key);
    if (existing) {
      if (!existing.removedAt) {
        this.logger.warn(`Term "${normalizedTerm}" already exists in ${request.category}`);
        return false;
      }
      // If it was removed, we'll restore and update it
    }

    const newTerm: UnifiedTerm = {
      term: normalizedTerm,
      category: request.category,
      severity: request.severity,
      useForPatternMatch: request.useForPatternMatch,
      useForEmbedding: request.useForEmbedding,
      mustContainCra: request.mustContainCra || false,
      source: 'admin',
      createdAt: new Date().toISOString(),
    };

    // Save to DynamoDB
    const success = await this.dynamoDbService.saveUnifiedTerm(newTerm);
    if (!success) return false;

    // Update in-memory cache
    this.terms.set(key, newTerm);

    // Add to embedding cache if needed
    if (request.useForEmbedding) {
      await this.embeddingService.addSeedPhrase(normalizedTerm, request.category, request.severity);
    }

    // Invalidate caches
    this.cacheService.flush();

    this.logger.log(`Added term "${normalizedTerm}" to ${request.category}`);
    return true;
  }

  /**
   * Remove a term
   * - Admin-added terms: hard delete
   * - JSON-seeded terms: soft delete (set removedAt)
   * Also removes from embedding cache so it no longer matches in similarity checks
   */
  async removeTerm(term: string, category: string): Promise<boolean> {
    const normalizedTerm = term.toLowerCase().trim();
    const key = `${category}:${normalizedTerm}`;

    const existingTerm = this.terms.get(key);
    if (!existingTerm) {
      this.logger.warn(`Term "${normalizedTerm}" not found in ${category}`);
      return false;
    }

    let success: boolean;
    if (existingTerm.source === 'admin') {
      // Hard delete for admin-added terms
      success = await this.dynamoDbService.deleteUnifiedTerm(normalizedTerm, category);
      if (success) {
        this.terms.delete(key);
      }
    } else {
      // Soft delete for JSON-seeded terms
      success = await this.dynamoDbService.markTermRemoved(normalizedTerm, category);
      if (success) {
        existingTerm.removedAt = new Date().toISOString();
      }
    }

    if (success) {
      // Remove from embedding cache so it no longer matches in similarity checks
      if (existingTerm.useForEmbedding) {
        this.embeddingService.removeSeedPhrase(normalizedTerm);
      }

      this.cacheService.flush();
      this.logger.log(`Removed term "${normalizedTerm}" from ${category}`);
    }

    return success;
  }

  /**
   * Restore a removed term (only for JSON-seeded terms)
   * Also adds back to embedding cache if useForEmbedding is true
   */
  async restoreTerm(term: string, category: string): Promise<boolean> {
    const normalizedTerm = term.toLowerCase().trim();
    const key = `${category}:${normalizedTerm}`;

    const existingTerm = this.terms.get(key);
    if (!existingTerm) {
      this.logger.warn(`Term "${normalizedTerm}" not found in ${category}`);
      return false;
    }

    if (!existingTerm.removedAt) {
      this.logger.warn(`Term "${normalizedTerm}" is not removed`);
      return false;
    }

    const success = await this.dynamoDbService.restoreTerm(normalizedTerm, category);
    if (success) {
      delete existingTerm.removedAt;

      // Add back to embedding cache if needed
      if (existingTerm.useForEmbedding) {
        await this.embeddingService.addSeedPhrase(normalizedTerm, existingTerm.category, existingTerm.severity);
      }

      this.cacheService.flush();
      this.logger.log(`Restored term "${normalizedTerm}" in ${category}`);
    }

    return success;
  }

  /**
   * Check if a term exists (for filtering emerging threats)
   */
  termExists(term: string): boolean {
    const normalizedTerm = term.toLowerCase().trim();

    for (const unifiedTerm of this.terms.values()) {
      if (unifiedTerm.term === normalizedTerm && !unifiedTerm.removedAt) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get unified terms response for API
   */
  getUnifiedTermsResponse(): UnifiedTermsResponse {
    const activeTerms = this.getAllTerms();
    const removedTerms = this.getRemovedTerms();

    // Build category summary
    const categoryCounts = new Map<TermCategory, number>();
    for (const term of activeTerms) {
      const count = categoryCounts.get(term.category) || 0;
      categoryCounts.set(term.category, count + 1);
    }

    const categories: UnifiedTermsResponse['categories'] = [];
    const allCategories: TermCategory[] = [
      'fakeExpiredBenefits',
      'illegitimatePaymentMethods',
      'threatLanguage',
      'suspiciousModifiers',
      'scamPatterns',
    ];

    for (const cat of allCategories) {
      categories.push({
        name: cat,
        displayName: CATEGORY_DISPLAY_NAMES[cat],
        severity: CATEGORY_SEVERITY[cat],
        count: categoryCounts.get(cat) || 0,
      });
    }

    return {
      terms: activeTerms,
      removedTerms,
      categories,
    };
  }

  /**
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
  }
}
