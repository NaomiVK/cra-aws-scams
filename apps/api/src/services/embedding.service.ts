import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import OpenAI from 'openai';
import { CacheService } from './cache.service';
import * as seedPhrasesConfig from '../config/seed-phrases.json';

type SeedPhraseCategory = {
  severity: string;
  terms: string[];
};

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

  constructor(private readonly cacheService: CacheService) {
    this.similarityThreshold = seedPhrasesConfig.settings.similarityThreshold;
    this.model = seedPhrasesConfig.settings.model;
  }

  async onModuleInit() {
    const apiKey = process.env['OPENAI_API_KEY'];

    if (!apiKey) {
      this.logger.warn('OPENAI_API_KEY not set - embedding-based detection disabled');
      return;
    }

    this.openai = new OpenAI({ apiKey });

    // Load seed phrases from config
    this.loadSeedPhrases();

    // Pre-compute embeddings for seed phrases
    await this.initializeSeedEmbeddings();
  }

  private loadSeedPhrases(): void {
    const phrases = seedPhrasesConfig.phrases as Record<string, SeedPhraseCategory>;

    for (const [category, data] of Object.entries(phrases)) {
      for (const term of data.terms) {
        this.seedPhrases.push({
          text: term,
          category,
          severity: data.severity,
        });
      }
    }

    this.logger.log(`Loaded ${this.seedPhrases.length} seed phrases from config`);
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
}
