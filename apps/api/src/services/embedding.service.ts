import { Injectable, Logger, OnModuleInit, forwardRef, Inject } from '@nestjs/common';
import OpenAI from 'openai';
import { CacheService } from './cache.service';
import { AwsConfigService } from './aws-config.service';
import { TermService } from './term.service';
import * as seedPhrasesConfig from '../config/seed-phrases.json';

type SeedPhrase = {
  text: string;
  category: string;
  severity: string;
  embedding?: number[];
};

type EmbeddingMatch = {
  phrase: string;
  category: string;
  severity: string;
  similarity: number;
};

type QueryEmbeddingResult = {
  query: string;
  matches: EmbeddingMatch[];
  topMatch: EmbeddingMatch | null;
  isScamRelated: boolean;
};

@Injectable()
export class EmbeddingService implements OnModuleInit {
  private readonly logger = new Logger(EmbeddingService.name);
  private openai: OpenAI | null = null;
  private seedPhrases: SeedPhrase[] = [];
  private seedEmbeddings: Map<string, number[]> = new Map();
  private readonly similarityThreshold: number;
  private readonly model: string;
  private initialized = false;

  constructor(
    private readonly cacheService: CacheService,
    private readonly awsConfigService: AwsConfigService,
    @Inject(forwardRef(() => TermService))
    private readonly termService: TermService,
  ) {
    this.similarityThreshold = seedPhrasesConfig.settings.similarityThreshold;
    this.model = seedPhrasesConfig.settings.model;
  }

  async onModuleInit() {
    // Wait for AwsConfigService to finish loading secrets
    await this.awsConfigService.ready;

    const apiKey = this.awsConfigService.getOpenAiApiKey();

    if (!apiKey) {
      this.logger.warn('OPENAI_API_KEY not set - embedding-based detection disabled');
      return;
    }

    this.openai = new OpenAI({ apiKey });

    // Wait for TermService to be ready
    await this.waitForTermService();

    // Load seed phrases from TermService
    this.loadSeedPhrasesFromTermService();

    // Pre-compute embeddings for seed phrases
    await this.initializeSeedEmbeddings();
  }

  /**
   * Wait for TermService to initialize (max 30 seconds)
   */
  private async waitForTermService(): Promise<void> {
    const maxWait = 30000; // 30 seconds
    const checkInterval = 100; // 100ms
    let waited = 0;

    while (!this.termService.isReady() && waited < maxWait) {
      await new Promise(resolve => setTimeout(resolve, checkInterval));
      waited += checkInterval;
    }

    if (this.termService.isReady()) {
      this.logger.log(`TermService ready after ${waited}ms`);
    } else {
      this.logger.warn(`TermService not ready after ${maxWait}ms`);
    }
  }

  /**
   * Load seed phrases from TermService (unified terms with useForEmbedding = true)
   */
  private loadSeedPhrasesFromTermService(): void {
    const embeddingTerms = this.termService.getEmbeddingTerms();

    this.seedPhrases = embeddingTerms.map(term => ({
      text: term.term,
      category: term.category,
      severity: term.severity,
    }));

    this.logger.log(`Loaded ${this.seedPhrases.length} embedding terms from TermService`);
  }

  private async initializeSeedEmbeddings(): Promise<void> {
    if (!this.openai) return;

    const cacheKey = 'seed-embeddings-v1';
    const cached = this.cacheService.get<Map<string, number[]>>(cacheKey);

    if (cached) {
      this.seedEmbeddings = new Map(Object.entries(cached));
      this.logger.log(`Loaded ${this.seedEmbeddings.size} seed embeddings from cache`);
      this.initialized = true;
      return;
    }

    this.logger.log('Computing embeddings for seed phrases...');

    try {
      const texts = this.seedPhrases.map(p => p.text);
      const embeddings = await this.getEmbeddings(texts);

      for (let i = 0; i < texts.length; i++) {
        this.seedEmbeddings.set(texts[i], embeddings[i]);
      }

      // Cache for 24 hours (seed phrases don't change often)
      this.cacheService.set(cacheKey, Object.fromEntries(this.seedEmbeddings), 86400);

      this.logger.log(`Computed and cached ${this.seedEmbeddings.size} seed embeddings`);
      this.initialized = true;
    } catch (error) {
      this.logger.error('Failed to initialize seed embeddings:', error);
    }
  }

  /**
   * Get embeddings for a batch of texts
   */
  async getEmbeddings(texts: string[]): Promise<number[][]> {
    if (!this.openai) {
      throw new Error('OpenAI client not initialized');
    }

    // OpenAI allows up to 2048 inputs per request
    const batchSize = 2048;
    const allEmbeddings: number[][] = [];

    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);

      const response = await this.openai.embeddings.create({
        model: this.model,
        input: batch,
      });

      const embeddings = response.data.map(d => d.embedding);
      allEmbeddings.push(...embeddings);

      if (texts.length > batchSize) {
        this.logger.debug(`Processed embedding batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(texts.length / batchSize)}`);
      }
    }

    return allEmbeddings;
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
   * Find similar seed phrases for a query
   */
  async findSimilarPhrases(query: string, threshold?: number): Promise<EmbeddingMatch[]> {
    if (!this.initialized || !this.openai) {
      return [];
    }

    const effectiveThreshold = threshold ?? this.similarityThreshold;

    // Get embedding for the query
    const [queryEmbedding] = await this.getEmbeddings([query.toLowerCase()]);

    const matches: EmbeddingMatch[] = [];

    for (const seedPhrase of this.seedPhrases) {
      const seedEmbedding = this.seedEmbeddings.get(seedPhrase.text);
      if (!seedEmbedding) continue;

      const similarity = this.cosineSimilarity(queryEmbedding, seedEmbedding);

      if (similarity >= effectiveThreshold) {
        matches.push({
          phrase: seedPhrase.text,
          category: seedPhrase.category,
          severity: seedPhrase.severity,
          similarity,
        });
      }
    }

    // Sort by similarity descending
    return matches.sort((a, b) => b.similarity - a.similarity);
  }

  /**
   * Batch analyze queries for scam similarity
   */
  async analyzeQueries(queries: string[], threshold?: number): Promise<QueryEmbeddingResult[]> {
    if (!this.initialized || !this.openai) {
      this.logger.debug('Embedding service not initialized, returning empty results');
      return queries.map(query => ({
        query,
        matches: [],
        topMatch: null,
        isScamRelated: false,
      }));
    }

    const effectiveThreshold = threshold ?? this.similarityThreshold;

    // Get embeddings for all queries at once
    const queryEmbeddings = await this.getEmbeddings(queries.map(q => q.toLowerCase()));

    const results: QueryEmbeddingResult[] = [];

    for (let i = 0; i < queries.length; i++) {
      const query = queries[i];
      const queryEmbedding = queryEmbeddings[i];
      const matches: EmbeddingMatch[] = [];

      for (const seedPhrase of this.seedPhrases) {
        const seedEmbedding = this.seedEmbeddings.get(seedPhrase.text);
        if (!seedEmbedding) continue;

        const similarity = this.cosineSimilarity(queryEmbedding, seedEmbedding);

        if (similarity >= effectiveThreshold) {
          matches.push({
            phrase: seedPhrase.text,
            category: seedPhrase.category,
            severity: seedPhrase.severity,
            similarity,
          });
        }
      }

      // Sort by similarity
      matches.sort((a, b) => b.similarity - a.similarity);

      results.push({
        query,
        matches,
        topMatch: matches[0] || null,
        isScamRelated: matches.length > 0,
      });
    }

    return results;
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
  getStatus(): { ready: boolean; seedPhraseCount: number; model: string; threshold: number } {
    return {
      ready: this.initialized,
      seedPhraseCount: this.seedPhrases.length,
      model: this.model,
      threshold: this.similarityThreshold,
    };
  }

  /**
   * Add a new seed phrase to the embedding comparison set
   * Updates in-memory cache and recomputes embeddings
   * Note: DynamoDB persistence is handled by scamDetectionService.addKeyword()
   */
  async addSeedPhrase(term: string, category: string, severity: string): Promise<void> {
    const normalizedTerm = term.toLowerCase().trim();

    // Check if already exists
    if (this.seedPhrases.some(p => p.text === normalizedTerm)) {
      this.logger.warn(`Seed phrase "${normalizedTerm}" already exists`);
      return;
    }

    // Add to runtime array
    this.seedPhrases.push({
      text: normalizedTerm,
      category,
      severity,
    });

    // Invalidate embedding cache
    this.cacheService.del('seed-embeddings-v1');
    this.initialized = false;

    // Recompute embeddings
    await this.initializeSeedEmbeddings();
  }

  /**
   * Remove a seed phrase from the embedding comparison set
   * Updates in-memory cache so deleted terms no longer match in similarity checks
   */
  removeSeedPhrase(term: string): void {
    const normalizedTerm = term.toLowerCase().trim();

    // Find and remove from runtime array
    const index = this.seedPhrases.findIndex(p => p.text === normalizedTerm);
    if (index === -1) {
      this.logger.debug(`Seed phrase "${normalizedTerm}" not found in embedding cache`);
      return;
    }

    this.seedPhrases.splice(index, 1);

    // Remove from embeddings map
    this.seedEmbeddings.delete(normalizedTerm);

    // Invalidate the cache so it gets rebuilt correctly on next restart
    this.cacheService.del('seed-embeddings-v1');

    this.logger.log(`Removed seed phrase "${normalizedTerm}" from embedding cache`);
  }

  /**
   * Reload all seed phrases from TermService
   * Useful after bulk changes to terms
   */
  async reloadSeedPhrases(): Promise<void> {
    this.loadSeedPhrasesFromTermService();
    this.cacheService.del('seed-embeddings-v1');
    this.initialized = false;
    await this.initializeSeedEmbeddings();
    this.logger.log('Reloaded all seed phrases and embeddings');
  }
}
