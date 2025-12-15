import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EmbeddingService } from './embedding.service';
import { CacheService } from './cache.service';
import { DynamoDbService } from './dynamodb.service';
import {
  SemanticZoneResult,
  SemanticCategory,
  CategoryCentroid,
  LegitimateQueriesConfig,
} from '@cra-scam-detection/shared-types';
import * as legitimateQueriesConfig from '../config/legitimate-queries.json';

/**
 * CategoryCentroidService
 *
 * Manages semantic zone classification for legitimate CRA queries.
 * Uses embedding centroids to automatically detect legitimate searches
 * without maintaining an exhaustive whitelist.
 *
 * Key concept: Instead of matching against individual patterns,
 * we compute a "centroid" (average embedding) for each category
 * and check if queries are semantically similar to any centroid.
 */
@Injectable()
export class CategoryCentroidService implements OnModuleInit {
  private readonly logger = new Logger(CategoryCentroidService.name);
  private config: LegitimateQueriesConfig;
  private centroids: Map<string, CategoryCentroid> = new Map();
  private initialized = false;

  // Default threshold if not in config
  private readonly defaultThreshold = 0.80;

  constructor(
    private readonly embeddingService: EmbeddingService,
    private readonly cacheService: CacheService,
    private readonly dynamoDbService: DynamoDbService,
  ) {
    this.config = legitimateQueriesConfig as LegitimateQueriesConfig;
  }

  async onModuleInit() {
    // Wait a bit for embedding service to initialize
    await this.waitForEmbeddingService();

    // Load any additional whitelist entries from DynamoDB
    await this.loadAdditionalExemplarsFromDynamoDB();

    // Compute centroids for each category
    await this.initializeCentroids();
  }

  /**
   * Wait for embedding service to be ready
   */
  private async waitForEmbeddingService(maxWaitMs = 30000): Promise<void> {
    const startTime = Date.now();
    while (!this.embeddingService.isReady() && Date.now() - startTime < maxWaitMs) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    if (!this.embeddingService.isReady()) {
      this.logger.warn('Embedding service not ready after waiting - centroid service may not work');
    }
  }

  /**
   * Load whitelist entries from DynamoDB and merge into categories
   * This allows admin-added whitelist patterns to contribute to semantic zones
   */
  private async loadAdditionalExemplarsFromDynamoDB(): Promise<void> {
    try {
      const dbWhitelist = await this.dynamoDbService.getAllWhitelist();

      if (dbWhitelist.length === 0) {
        this.logger.log('No additional whitelist entries in DynamoDB');
        return;
      }

      // Add DynamoDB whitelist entries to the "generalInquiry" category
      // (most flexible category for misc legitimate queries)
      const generalCategory = this.config.categories['generalInquiry'];
      let addedCount = 0;

      for (const record of dbWhitelist) {
        const normalizedTerm = record.term.toLowerCase().trim();
        if (!generalCategory.exemplars.includes(normalizedTerm)) {
          generalCategory.exemplars.push(normalizedTerm);
          addedCount++;
        }
      }

      this.logger.log(`Added ${addedCount} whitelist entries from DynamoDB to semantic zones`);
    } catch (error) {
      this.logger.warn(`Failed to load whitelist from DynamoDB: ${error.message}`);
    }
  }

  /**
   * Initialize centroids for all categories
   */
  private async initializeCentroids(): Promise<void> {
    if (!this.embeddingService.isReady()) {
      this.logger.warn('Embedding service not ready - skipping centroid initialization');
      return;
    }

    const cacheKey = 'category-centroids-v1';
    const cached = this.cacheService.get<Record<string, CategoryCentroid>>(cacheKey);

    if (cached) {
      this.centroids = new Map(Object.entries(cached));
      this.logger.log(`Loaded ${this.centroids.size} category centroids from cache`);
      this.initialized = true;
      return;
    }

    this.logger.log('Computing centroids for legitimate query categories...');

    try {
      for (const [categoryName, categoryData] of Object.entries(this.config.categories)) {
        const exemplars = categoryData.exemplars;

        if (exemplars.length === 0) {
          this.logger.warn(`Category "${categoryName}" has no exemplars, skipping`);
          continue;
        }

        // Get embeddings for all exemplars
        const embeddings = await this.embeddingService.getEmbeddings(
          exemplars.map(e => e.toLowerCase())
        );

        // Compute centroid (average of all embeddings)
        const centroid = this.computeCentroid(embeddings);

        this.centroids.set(categoryName, {
          name: categoryName,
          type: 'legitimate',
          description: categoryData.description,
          centroid,
          exemplarCount: exemplars.length,
          threshold: this.config.settings.legitimateThreshold || this.defaultThreshold,
        });

        this.logger.debug(
          `Computed centroid for "${categoryName}" from ${exemplars.length} exemplars`
        );
      }

      // Cache for configured hours (default 24)
      const cacheHours = this.config.settings.cacheHours || 24;
      this.cacheService.set(
        cacheKey,
        Object.fromEntries(this.centroids),
        cacheHours * 3600
      );

      this.logger.log(
        `Computed and cached ${this.centroids.size} category centroids`
      );
      this.initialized = true;
    } catch (error) {
      this.logger.error('Failed to initialize category centroids:', error);
    }
  }

  /**
   * Compute centroid (average) of multiple embeddings
   */
  private computeCentroid(embeddings: number[][]): number[] {
    if (embeddings.length === 0) {
      return [];
    }

    const dimension = embeddings[0].length;
    const centroid = new Array(dimension).fill(0);

    for (const embedding of embeddings) {
      for (let i = 0; i < dimension; i++) {
        centroid[i] += embedding[i];
      }
    }

    // Average
    for (let i = 0; i < dimension; i++) {
      centroid[i] /= embeddings.length;
    }

    return centroid;
  }

  /**
   * Compute cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Check if a query is in a legitimate semantic zone
   *
   * This is the main method that replaces the old regex whitelist.
   * Returns true if the query is semantically similar to any legitimate category.
   */
  async isInLegitimateZone(query: string): Promise<SemanticZoneResult> {
    const normalizedQuery = query.toLowerCase().trim();

    // Default result for when service is not ready
    if (!this.initialized || this.centroids.size === 0) {
      return {
        query: normalizedQuery,
        isLegitimate: false,
        nearestCategory: '',
        similarity: 0,
        allCategories: [],
      };
    }

    try {
      // Get embedding for the query
      const [queryEmbedding] = await this.embeddingService.getEmbeddings([normalizedQuery]);

      let nearestCategory = '';
      let maxSimilarity = 0;
      const allCategories: SemanticCategory[] = [];

      // Check similarity to each category centroid
      for (const [categoryName, centroidData] of this.centroids) {
        const similarity = this.cosineSimilarity(queryEmbedding, centroidData.centroid);
        const distance = 1 - similarity;

        allCategories.push({
          name: categoryName,
          type: 'legitimate',
          similarity,
          distance,
          confidence: this.calculateConfidence(similarity, centroidData.threshold),
        });

        if (similarity > maxSimilarity) {
          maxSimilarity = similarity;
          nearestCategory = categoryName;
        }
      }

      // Sort categories by similarity (highest first)
      allCategories.sort((a, b) => b.similarity - a.similarity);

      const threshold = this.config.settings.legitimateThreshold || this.defaultThreshold;
      const isLegitimate = maxSimilarity >= threshold;

      return {
        query: normalizedQuery,
        isLegitimate,
        nearestCategory,
        similarity: maxSimilarity,
        allCategories,
      };
    } catch (error) {
      this.logger.error(`Error checking semantic zone for "${normalizedQuery}": ${error.message}`);
      return {
        query: normalizedQuery,
        isLegitimate: false,
        nearestCategory: '',
        similarity: 0,
        allCategories: [],
      };
    }
  }

  /**
   * Calculate confidence based on how much similarity exceeds threshold
   */
  private calculateConfidence(similarity: number, threshold: number): number {
    if (similarity < threshold - 0.1) {
      return 0;
    }
    if (similarity >= threshold + 0.1) {
      return 1;
    }
    // Linear interpolation between threshold-0.1 and threshold+0.1
    return (similarity - (threshold - 0.1)) / 0.2;
  }

  /**
   * Batch check multiple queries for legitimate zones
   * More efficient than calling isInLegitimateZone for each query
   */
  async batchCheckLegitimateZone(queries: string[]): Promise<SemanticZoneResult[]> {
    if (!this.initialized || this.centroids.size === 0) {
      return queries.map(query => ({
        query: query.toLowerCase().trim(),
        isLegitimate: false,
        nearestCategory: '',
        similarity: 0,
        allCategories: [],
      }));
    }

    try {
      const normalizedQueries = queries.map(q => q.toLowerCase().trim());
      const queryEmbeddings = await this.embeddingService.getEmbeddings(normalizedQueries);

      const results: SemanticZoneResult[] = [];
      const threshold = this.config.settings.legitimateThreshold || this.defaultThreshold;

      for (let i = 0; i < normalizedQueries.length; i++) {
        const queryEmbedding = queryEmbeddings[i];
        let nearestCategory = '';
        let maxSimilarity = 0;
        const allCategories: SemanticCategory[] = [];

        for (const [categoryName, centroidData] of this.centroids) {
          const similarity = this.cosineSimilarity(queryEmbedding, centroidData.centroid);
          const distance = 1 - similarity;

          allCategories.push({
            name: categoryName,
            type: 'legitimate',
            similarity,
            distance,
            confidence: this.calculateConfidence(similarity, centroidData.threshold),
          });

          if (similarity > maxSimilarity) {
            maxSimilarity = similarity;
            nearestCategory = categoryName;
          }
        }

        allCategories.sort((a, b) => b.similarity - a.similarity);

        results.push({
          query: normalizedQueries[i],
          isLegitimate: maxSimilarity >= threshold,
          nearestCategory,
          similarity: maxSimilarity,
          allCategories,
        });
      }

      return results;
    } catch (error) {
      this.logger.error(`Error in batch semantic zone check: ${error.message}`);
      return queries.map(query => ({
        query: query.toLowerCase().trim(),
        isLegitimate: false,
        nearestCategory: '',
        similarity: 0,
        allCategories: [],
      }));
    }
  }

  /**
   * Add a new exemplar to a category
   * This is called when an admin marks a term as "legitimate"
   */
  async addExemplar(term: string, category?: string): Promise<void> {
    const normalizedTerm = term.toLowerCase().trim();
    const targetCategory = category || 'generalInquiry';

    // Add to runtime config
    const categoryData = this.config.categories[targetCategory];
    if (!categoryData) {
      this.logger.warn(`Unknown category "${targetCategory}", adding to generalInquiry`);
      this.config.categories['generalInquiry'].exemplars.push(normalizedTerm);
    } else if (!categoryData.exemplars.includes(normalizedTerm)) {
      categoryData.exemplars.push(normalizedTerm);
    }

    // Persist to DynamoDB (using whitelist table for now)
    await this.dynamoDbService.addWhitelist(normalizedTerm);

    // Invalidate cache and recompute
    this.cacheService.del('category-centroids-v1');
    this.initialized = false;
    await this.initializeCentroids();

    this.logger.log(`Added exemplar "${normalizedTerm}" to category "${targetCategory}"`);
  }

  /**
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
  }

  /**
   * Get service status
   */
  getStatus(): {
    ready: boolean;
    categoryCount: number;
    totalExemplars: number;
    threshold: number;
  } {
    let totalExemplars = 0;
    for (const categoryData of Object.values(this.config.categories)) {
      totalExemplars += categoryData.exemplars.length;
    }

    return {
      ready: this.initialized,
      categoryCount: this.centroids.size,
      totalExemplars,
      threshold: this.config.settings.legitimateThreshold || this.defaultThreshold,
    };
  }

  /**
   * Get list of categories with their stats
   */
  getCategoryStats(): Array<{ name: string; exemplarCount: number; description: string }> {
    return Object.entries(this.config.categories).map(([name, data]) => ({
      name,
      exemplarCount: data.exemplars.length,
      description: data.description,
    }));
  }
}
