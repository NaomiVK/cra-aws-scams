import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import OpenAI from 'openai';
import { CacheService } from './cache.service';
import { AwsConfigService } from './aws-config.service';
import { SentimentLabel, SentimentResult } from '@cra-scam-detection/shared-types';

/**
 * Sentiment Analysis Service
 * Uses GPT-4o-mini for sentiment classification of Reddit posts
 */
@Injectable()
export class SentimentService implements OnModuleInit {
  private readonly logger = new Logger(SentimentService.name);
  private openai: OpenAI | null = null;
  private initialized = false;
  private readonly model = 'gpt-4o-mini';
  private readonly cacheTtl = 86400; // 24 hours

  constructor(
    private readonly cacheService: CacheService,
    private readonly awsConfigService: AwsConfigService,
  ) {}

  async onModuleInit() {
    await this.awsConfigService.ready;

    const apiKey = this.awsConfigService.getOpenAiApiKey();

    if (!apiKey) {
      this.logger.warn('OPENAI_API_KEY not set - sentiment analysis disabled');
      return;
    }

    this.openai = new OpenAI({ apiKey });
    this.initialized = true;
    this.logger.log(`Sentiment service initialized with model: ${this.model}`);
  }

  /**
   * Analyze sentiment of a single text
   */
  async analyzeSentiment(text: string, _postId?: string): Promise<SentimentResult> {
    // Check cache first
    const cacheKey = `sentiment:${this.hashText(text)}`;
    const cached = this.cacheService.get<SentimentResult>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for sentiment analysis`);
      return cached;
    }

    if (!this.openai || !this.initialized) {
      this.logger.warn('Sentiment service not initialized');
      return this.getDefaultResult();
    }

    try {
      const response = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: `You are a sentiment analysis assistant. Analyze the sentiment of Reddit posts about Canada Revenue Agency (CRA) and tax-related topics.

Classify the sentiment as:
- "positive": Helpful, informative, solution-oriented, or expressing satisfaction
- "negative": Complaints, frustration, warnings about scams, expressing anger or dissatisfaction
- "neutral": Factual questions, informational without emotional content

Also provide:
- A score from -1 (very negative) to 1 (very positive)
- A confidence level from 0 to 1

Respond ONLY with valid JSON in this exact format:
{"label": "positive|negative|neutral", "score": <number>, "confidence": <number>}`,
          },
          {
            role: 'user',
            content: text.slice(0, 2000), // Limit text length
          },
        ],
        temperature: 0,
        max_tokens: 100,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error('Empty response from OpenAI');
      }

      // Parse JSON response (strip markdown if present)
      const result = JSON.parse(this.stripMarkdown(content)) as SentimentResult;

      // Validate and normalize
      const normalizedResult: SentimentResult = {
        label: this.validateLabel(result.label),
        score: this.clamp(result.score || 0, -1, 1),
        confidence: this.clamp(result.confidence || 0.5, 0, 1),
      };

      // Cache the result
      this.cacheService.set(cacheKey, normalizedResult, this.cacheTtl);

      return normalizedResult;
    } catch (error) {
      this.logger.error(`Sentiment analysis failed: ${error.message}`);
      return this.getDefaultResult();
    }
  }

  /**
   * Batch analyze sentiment for multiple texts
   * More efficient than individual calls
   */
  async batchAnalyzeSentiment(
    items: Array<{ id: string; text: string }>,
  ): Promise<Map<string, SentimentResult>> {
    const results = new Map<string, SentimentResult>();

    if (!this.openai || !this.initialized) {
      this.logger.warn('Sentiment service not initialized, returning defaults');
      for (const item of items) {
        results.set(item.id, this.getDefaultResult());
      }
      return results;
    }

    // Check cache for each item
    const uncached: Array<{ id: string; text: string }> = [];
    for (const item of items) {
      const cacheKey = `sentiment:${this.hashText(item.text)}`;
      const cached = this.cacheService.get<SentimentResult>(cacheKey);
      if (cached) {
        results.set(item.id, cached);
      } else {
        uncached.push(item);
      }
    }

    this.logger.debug(`Sentiment batch: ${results.size} cached, ${uncached.length} to analyze`);

    // Process uncached items in batches
    const batchSize = 10;
    for (let i = 0; i < uncached.length; i += batchSize) {
      const batch = uncached.slice(i, i + batchSize);

      try {
        const response = await this.openai.chat.completions.create({
          model: this.model,
          messages: [
            {
              role: 'system',
              content: `You are a sentiment analysis assistant. Analyze the sentiment of multiple Reddit posts about Canada Revenue Agency (CRA) and tax-related topics.

For each post, classify the sentiment as:
- "positive": Helpful, informative, solution-oriented, or expressing satisfaction
- "negative": Complaints, frustration, warnings about scams, expressing anger or dissatisfaction
- "neutral": Factual questions, informational without emotional content

Respond ONLY with a JSON array in this exact format:
[{"id": "...", "label": "positive|negative|neutral", "score": <-1 to 1>, "confidence": <0 to 1>}, ...]`,
            },
            {
              role: 'user',
              content: JSON.stringify(
                batch.map(item => ({
                  id: item.id,
                  text: item.text.slice(0, 500), // Shorter for batch
                })),
              ),
            },
          ],
          temperature: 0,
          max_tokens: 1000,
        });

        const content = response.choices[0]?.message?.content;
        if (content) {
          const batchResults = JSON.parse(this.stripMarkdown(content)) as Array<{
            id: string;
            label: string;
            score: number;
            confidence: number;
          }>;

          for (const result of batchResults) {
            const normalizedResult: SentimentResult = {
              label: this.validateLabel(result.label),
              score: this.clamp(result.score || 0, -1, 1),
              confidence: this.clamp(result.confidence || 0.5, 0, 1),
            };

            results.set(result.id, normalizedResult);

            // Cache individual results
            const originalItem = batch.find(item => item.id === result.id);
            if (originalItem) {
              const cacheKey = `sentiment:${this.hashText(originalItem.text)}`;
              this.cacheService.set(cacheKey, normalizedResult, this.cacheTtl);
            }
          }
        }
      } catch (error) {
        this.logger.error(`Batch sentiment analysis failed: ${error.message}`);
        // Set defaults for failed batch
        for (const item of batch) {
          if (!results.has(item.id)) {
            results.set(item.id, this.getDefaultResult());
          }
        }
      }
    }

    // Ensure all items have results
    for (const item of items) {
      if (!results.has(item.id)) {
        results.set(item.id, this.getDefaultResult());
      }
    }

    return results;
  }

  /**
   * Calculate sentiment summary from a list of results
   */
  calculateSummary(
    sentiments: SentimentResult[],
  ): {
    total: number;
    positive: number;
    negative: number;
    neutral: number;
    positivePct: number;
    negativePct: number;
    neutralPct: number;
    avgConfidence: number;
  } {
    const counts = { positive: 0, negative: 0, neutral: 0 };
    let totalConfidence = 0;

    for (const sentiment of sentiments) {
      counts[sentiment.label]++;
      totalConfidence += sentiment.confidence;
    }

    const total = sentiments.length || 1;

    return {
      total: sentiments.length,
      positive: counts.positive,
      negative: counts.negative,
      neutral: counts.neutral,
      positivePct: Math.round((counts.positive / total) * 100),
      negativePct: Math.round((counts.negative / total) * 100),
      neutralPct: Math.round((counts.neutral / total) * 100),
      avgConfidence: totalConfidence / total,
    };
  }

  /**
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
  }

  private getDefaultResult(): SentimentResult {
    return {
      label: 'neutral',
      score: 0,
      confidence: 0,
    };
  }

  private validateLabel(label: string): SentimentLabel {
    const normalized = label?.toLowerCase().trim();
    if (normalized === 'positive' || normalized === 'negative' || normalized === 'neutral') {
      return normalized;
    }
    return 'neutral';
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }

  private hashText(text: string): string {
    // Simple hash for cache key
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(16);
  }

  /**
   * Strip markdown code blocks from response
   */
  private stripMarkdown(content: string): string {
    // Remove ```json ... ``` or ``` ... ```
    return content
      .replace(/^```(?:json)?\s*\n?/i, '')
      .replace(/\n?```\s*$/i, '')
      .trim();
  }
}
