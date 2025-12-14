import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  PutCommand,
  ScanCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { AwsConfigService } from './aws-config.service';

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

export type WhitelistRecord = {
  category: string;  // "whitelist"
  term: string;
  createdAt: string;
};

@Injectable()
export class DynamoDbService implements OnModuleInit {
  private readonly logger = new Logger(DynamoDbService.name);
  private readonly tableName = 'cra-scam-seed-phrases';
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
      const items = (response.Items || []) as SeedPhraseRecord[];

      this.logger.log(`Loaded ${items.length} seed phrases from DynamoDB`);
      return items;
    } catch (error) {
      // Table might not exist yet - that's OK
      if (error.name === 'ResourceNotFoundException') {
        this.logger.warn(`Table ${this.tableName} not found - will use local config only`);
        return [];
      }
      this.logger.error(`Failed to scan seed phrases: ${error.message}`);
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

  /**
   * Get all keywords from DynamoDB (category starts with "keyword:")
   */
  async getAllKeywords(): Promise<KeywordRecord[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new ScanCommand({
        TableName: this.tableName,
        FilterExpression: 'begins_with(category, :prefix)',
        ExpressionAttributeValues: { ':prefix': 'keyword:' },
      });

      const response = await client.send(command);
      const items = (response.Items || []) as KeywordRecord[];
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

  // ==================== WHITELIST ====================

  /**
   * Get all whitelist patterns from DynamoDB
   */
  async getAllWhitelist(): Promise<WhitelistRecord[]> {
    if (!this.initialized) return [];

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return [];

    try {
      const command = new ScanCommand({
        TableName: this.tableName,
        FilterExpression: 'category = :cat',
        ExpressionAttributeValues: { ':cat': 'whitelist' },
      });

      const response = await client.send(command);
      const items = (response.Items || []) as WhitelistRecord[];
      this.logger.log(`Loaded ${items.length} whitelist patterns from DynamoDB`);
      return items;
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') return [];
      this.logger.error(`Failed to scan whitelist: ${error.message}`);
      return [];
    }
  }

  /**
   * Add a whitelist pattern to DynamoDB
   */
  async addWhitelist(pattern: string): Promise<boolean> {
    if (!this.initialized) return false;

    const client = this.awsConfigService.getDynamoDbClient();
    if (!client) return false;

    try {
      const command = new PutCommand({
        TableName: this.tableName,
        Item: {
          category: 'whitelist',
          term: pattern.toLowerCase().trim(),
          createdAt: new Date().toISOString(),
        },
      });

      await client.send(command);
      this.logger.log(`Persisted whitelist pattern "${pattern}" to DynamoDB`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to persist whitelist pattern: ${error.message}`);
      return false;
    }
  }
}
