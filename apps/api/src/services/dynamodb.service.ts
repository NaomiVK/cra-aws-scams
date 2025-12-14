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
}
