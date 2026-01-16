import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  PutCommand,
  ScanCommand,
  DeleteCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { AwsConfigService } from './aws-config.service';
import { RedditPost } from '@cra-scam-detection/shared-types';

export type SeedPhraseRecord = {
  category: string;
  term: string;
  severity: string;
  createdAt: string;
};

export type KeywordRecord = {
  category: string;  // "keyword:{categoryName}"
  term: string;
  createdAt: string;
};

@Injectable()
export class DynamoDbService implements OnModuleInit {
  private readonly logger = new Logger(DynamoDbService.name);
  private readonly tableName = 'cra-scam-seed-phrases';
  private readonly redditTableName = 'cra-reddit-posts';
  private initialized = false;

  constructor(private readonly awsConfigService: AwsConfigService) {}

  async onModuleInit() {
    await this.awsConfigService.ready;

    const client = this.awsConfigService.getDynamoDbClient();
    if (client) {
      this.initialized = true;
      this.logger.log(`DynamoDB service ready (table: ${this.tableName})`);
    } else {
      this.logger.warn('DynamoDB client not available');
    }
  }

  /**
   * Get all seed phrases from DynamoDB
   * Returns seed phrase categories (fakeExpiredBenefits, threatLanguage, etc.)
   */
  async getAllSeedPhrases(): Promise<SeedPhraseRecord[]> {
    if (!this.initialized) {
      this.logger.warn('DynamoDB not initialized, returning empty list');
      return [];
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new ScanCommand({
        TableName: this.tableName,
      });

      const response = await client.send(command);
      // Filter out keyword: prefixed items and reddit-search (those have their own methods)
      const items = (response.Items || [])
        .filter(item => {
          const category = item.category as string;
          return !category.startsWith('keyword:') && category !== 'reddit-search';
        }) as SeedPhraseRecord[];

      this.logger.log(`Loaded ${items.length} seed phrases from DynamoDB`);
      return items;
    } catch (error) {
      // Table might not exist yet - that's OK in dev
      if (error.name === 'ResourceNotFoundException') {
        this.logger.warn(`Table ${this.tableName} not found - will use local config only`);
        return [];
      }
      // Differentiate error types for better debugging
      if (error.name === 'ProvisionedThroughputExceededException') {
        this.logger.error(`DynamoDB throttled - seed phrases scan: ${error.message}`);
      } else if (error.name === 'AccessDeniedException') {
        this.logger.error(`DynamoDB access denied - check IAM permissions: ${error.message}`);
      } else {
        this.logger.error(`Failed to scan seed phrases [${error.name}]: ${error.message}`);
      }
      return [];
    }
  }

  /**
   * Add a new seed phrase to DynamoDB
   */
  async addSeedPhrase(
    term: string,
    category: string,
    severity: string
  ): Promise<boolean> {
    if (!this.initialized) {
      this.logger.warn('DynamoDB not initialized, skipping persistence');
      return false;
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new PutCommand({
        TableName: this.tableName,
        Item: {
          category,
          term: term.toLowerCase().trim(),
          severity,
          createdAt: new Date().toISOString(),
        },
      });

      await client.send(command);
      this.logger.log(`Persisted seed phrase "${term}" to DynamoDB (${category})`);
      return true;
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        this.logger.warn(`Table ${this.tableName} not found - create it in AWS console or via CLI`);
      } else {
        this.logger.error(`Failed to persist seed phrase: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Delete a seed phrase from DynamoDB
   */
  async deleteSeedPhrase(term: string, category: string): Promise<boolean> {
    if (!this.initialized) {
      return false;
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new DeleteCommand({
        TableName: this.tableName,
        Key: {
          category,
          term: term.toLowerCase().trim(),
        },
      });

      await client.send(command);
      this.logger.log(`Deleted seed phrase "${term}" from DynamoDB`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete seed phrase: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
  }

  // ==================== KEYWORDS ====================

  // Valid keyword category names (without prefix)
  private readonly KEYWORD_CATEGORIES = [
    'fakeExpiredBenefits',
    'illegitimatePaymentMethods',
    'threatLanguage',
    'suspiciousModifiers',
  ];

  /**
   * Get all keywords from DynamoDB
   * Looks for both formats:
   * - category = "keyword:categoryName" (new format)
   * - category = "categoryName" (legacy/seed phrase format)
   */
  async getAllKeywords(): Promise<KeywordRecord[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      // Build filter for all valid keyword categories (both formats)
      const filterParts: string[] = [];
      const expressionValues: Record<string, string> = {};

      this.KEYWORD_CATEGORIES.forEach((cat, idx) => {
        // Match "keyword:categoryName" format
        filterParts.push(`category = :cat${idx}`);
        expressionValues[`:cat${idx}`] = `keyword:${cat}`;
        // Match "categoryName" format (legacy)
        filterParts.push(`category = :catLegacy${idx}`);
        expressionValues[`:catLegacy${idx}`] = cat;
      });

      const command = new ScanCommand({
        TableName: this.tableName,
        FilterExpression: filterParts.join(' OR '),
        ExpressionAttributeValues: expressionValues,
      });

      const response = await client.send(command);
      const items = (response.Items || []).map(item => {
        // Normalize category to "keyword:categoryName" format for consistency
        const category = item.category as string;
        const normalizedCategory = category.startsWith('keyword:')
          ? category
          : `keyword:${category}`;
        return { ...item, category: normalizedCategory } as KeywordRecord;
      });

      this.logger.log(`Loaded ${items.length} keywords from DynamoDB`);
      return items;
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') return [];
      this.logger.error(`Failed to scan keywords: ${error.message}`);
      return [];
    }
  }

  /**
   * Add a keyword to DynamoDB
   */
  async addKeyword(term: string, categoryName: string): Promise<boolean> {
    if (!this.initialized) return false;

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new PutCommand({
        TableName: this.tableName,
        Item: {
          category: `keyword:${categoryName}`,
          term: term.toLowerCase().trim(),
          createdAt: new Date().toISOString(),
        },
      });

      await client.send(command);
      this.logger.log(`Persisted keyword "${term}" to DynamoDB (${categoryName})`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to persist keyword: ${error.message}`);
      return false;
    }
  }

  // ==================== REDDIT POSTS ====================

  /**
   * Save a Reddit post to DynamoDB
   */
  async saveRedditPost(post: RedditPost): Promise<boolean> {
    if (!this.initialized) {
      this.logger.warn('DynamoDB not initialized, skipping Reddit post save');
      return false;
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new PutCommand({
        TableName: this.redditTableName,
        Item: {
          subreddit: post.subreddit,
          reddit_id: post.reddit_id,
          title: post.title,
          content: post.content,
          author: post.author,
          score: post.score,
          upvote_ratio: post.upvote_ratio,
          num_comments: post.num_comments,
          created_utc: post.created_utc,
          url: post.url,
          permalink: post.permalink,
          is_self: post.is_self,
          flair_text: post.flair_text,
          sentiment: post.sentiment,
          sentiment_confidence: post.sentiment_confidence,
          analyzed_at: post.analyzed_at || new Date().toISOString(),
          saved_at: new Date().toISOString(),
        },
      });

      await client.send(command);
      return true;
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        this.logger.warn(`Table ${this.redditTableName} not found - create it in AWS console`);
      } else {
        this.logger.error(`Failed to save Reddit post: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Get Reddit posts by subreddit
   */
  async getRedditPostsBySubreddit(
    subreddit: string,
    limit = 25,
  ): Promise<RedditPost[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new QueryCommand({
        TableName: this.redditTableName,
        KeyConditionExpression: 'subreddit = :sr',
        ExpressionAttributeValues: { ':sr': subreddit },
        ScanIndexForward: false, // Descending order
        Limit: limit,
      });

      const response = await client.send(command);
      return (response.Items || []) as RedditPost[];
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') return [];
      this.logger.error(`Failed to get Reddit posts: ${error.message}`);
      return [];
    }
  }

  /**
   * Get all recent Reddit posts across all subreddits
   */
  async getAllRedditPosts(limit = 100): Promise<RedditPost[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new ScanCommand({
        TableName: this.redditTableName,
        Limit: limit,
      });

      const response = await client.send(command);
      const posts = (response.Items || []) as RedditPost[];

      // Sort by created_utc descending
      return posts.sort(
        (a, b) => new Date(b.created_utc).getTime() - new Date(a.created_utc).getTime(),
      );
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') return [];
      this.logger.error(`Failed to scan Reddit posts: ${error.message}`);
      return [];
    }
  }

  /**
   * Get Reddit posts from the last N days
   */
  async getRecentRedditPosts(days = 7): Promise<RedditPost[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    const cutoffIso = cutoffDate.toISOString();

    try {
      const command = new ScanCommand({
        TableName: this.redditTableName,
        FilterExpression: 'created_utc >= :cutoff',
        ExpressionAttributeValues: { ':cutoff': cutoffIso },
      });

      const response = await client.send(command);
      const posts = (response.Items || []) as RedditPost[];

      // Sort by created_utc descending
      return posts.sort(
        (a, b) => new Date(b.created_utc).getTime() - new Date(a.created_utc).getTime(),
      );
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') return [];
      this.logger.error(`Failed to get recent Reddit posts: ${error.message}`);
      return [];
    }
  }
}
