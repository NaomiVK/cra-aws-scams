import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  PutCommand,
  ScanCommand,
  DeleteCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { AwsConfigService } from './aws-config.service';
import { RedditPost, UnifiedTerm } from '@cra-scam-detection/shared-types';


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
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
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

  // ==================== UNIFIED TERMS ====================

  /**
   * Get all unified terms from DynamoDB
   * Returns terms with the unified structure (useForPatternMatch, useForEmbedding flags)
   */
  async getAllUnifiedTerms(): Promise<UnifiedTerm[]> {
    if (!this.initialized) {
      this.logger.warn('DynamoDB not initialized, returning empty list');
      return [];
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new ScanCommand({
        TableName: this.tableName,
        FilterExpression: 'attribute_exists(useForPatternMatch) OR attribute_exists(useForEmbedding)',
      });

      const response = await client.send(command);
      const items = (response.Items || []) as UnifiedTerm[];

      this.logger.log(`Loaded ${items.length} unified terms from DynamoDB`);
      return items;
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        this.logger.warn(`Table ${this.tableName} not found`);
        return [];
      }
      this.logger.error(`Failed to scan unified terms: ${error.message}`);
      return [];
    }
  }

  /**
   * Save a unified term to DynamoDB
   */
  async saveUnifiedTerm(term: UnifiedTerm): Promise<boolean> {
    if (!this.initialized) {
      this.logger.warn('DynamoDB not initialized, skipping save');
      return false;
    }

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new PutCommand({
        TableName: this.tableName,
        Item: {
          category: term.category,
          term: term.term.toLowerCase().trim(),
          severity: term.severity,
          useForPatternMatch: term.useForPatternMatch,
          useForEmbedding: term.useForEmbedding,
          mustContainCra: term.mustContainCra || false,
          source: term.source,
          createdAt: term.createdAt || new Date().toISOString(),
          ...(term.removedAt && { removedAt: term.removedAt }),
        },
      });

      await client.send(command);
      this.logger.log(`Saved unified term "${term.term}" to DynamoDB (${term.category})`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to save unified term: ${error.message}`);
      return false;
    }
  }

  /**
   * Delete a term from DynamoDB
   */
  async deleteUnifiedTerm(term: string, category: string): Promise<boolean> {
    if (!this.initialized) return false;

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
      this.logger.log(`Deleted unified term "${term}" from DynamoDB`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete unified term: ${error.message}`);
      return false;
    }
  }


}
