import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { environment } from '../environments/environment';

@Injectable()
export class AwsConfigService implements OnModuleInit {
  private readonly logger = new Logger(AwsConfigService.name);
  private secretsManagerClient: SecretsManagerClient | null = null;
  private dynamoDbClient: DynamoDBClient | null = null;
  private dynamoDbDocClient: DynamoDBDocumentClient | null = null;

  // Cached secrets
  private secrets: Record<string, string> = {};

  // AWS region
  private readonly region = process.env['AWS_REGION'] || 'us-east-2';

  // Promise that resolves when secrets are loaded
  private readyResolve: (() => void) | null = null;
  private initialized = false;
  public readonly ready: Promise<void> = new Promise((resolve) => {
    this.readyResolve = resolve;
  });

  async onModuleInit() {
    // Prevent multiple initializations
    if (this.initialized) {
      this.logger.warn('AwsConfigService already initialized, skipping');
      return;
    }

    try {
      // Initialize DynamoDB client (works in both dev and prod)
      this.initializeDynamoDb();

      if (environment.production) {
        await this.loadSecretsFromSecretsManager();
      } else {
        this.loadSecretsFromEnv();
      }
    } finally {
      // Always signal ready, even on partial failure
      this.initialized = true;
      if (this.readyResolve) {
        this.readyResolve();
        this.readyResolve = null; // Prevent multiple calls
      }
    }
  }

  private initializeDynamoDb(): void {
    try {
      this.dynamoDbClient = new DynamoDBClient({ region: this.region });
      this.dynamoDbDocClient = DynamoDBDocumentClient.from(this.dynamoDbClient, {
        marshallOptions: {
          removeUndefinedValues: true,
        },
      });
      this.logger.log(`DynamoDB client initialized for region: ${this.region}`);
    } catch (error) {
      this.logger.error('Failed to initialize DynamoDB client:', error);
    }
  }

  private loadSecretsFromEnv() {
    this.logger.log('Loading secrets from environment variables (dev mode)');
    this.secrets = {
      GOOGLE_MAPS_API_KEY: process.env['GOOGLE_MAPS_API_KEY'] || '',
      OPENAI_API_KEY: process.env['OPENAI_API_KEY'] || '',
      REDDIT_CLIENT_ID: process.env['REDDIT_CLIENT_ID'] || '',
      REDDIT_CLIENT_SECRET: process.env['REDDIT_CLIENT_SECRET'] || '',
      REDDIT_USERNAME: process.env['REDDIT_USERNAME'] || '',
      REDDIT_PASSWORD: process.env['REDDIT_PASSWORD'] || '',
    };
  }

  private async loadSecretsFromSecretsManager() {
    this.logger.log('Loading secrets from AWS Secrets Manager');

    try {
      this.secretsManagerClient = new SecretsManagerClient({ region: this.region });

      const command = new GetSecretValueCommand({
        SecretId: 'prod/cra-scam/api-keys',
      });

      const response = await this.secretsManagerClient.send(command);

      if (response.SecretString) {
        const secretData = JSON.parse(response.SecretString);

        // Map the secret keys to our expected format
        this.secrets = {
          GOOGLE_MAPS_API_KEY: secretData.GOOGLE_MAPS_API_KEY || '',
          OPENAI_API_KEY: secretData.OPENAI_API_KEY || '',
          GSC_SERVICE_ACCOUNT: secretData.GSC_SERVICE_ACCOUNT || '',
          REDDIT_CLIENT_ID: secretData.REDDIT_CLIENT_ID || '',
          REDDIT_CLIENT_SECRET: secretData.REDDIT_CLIENT_SECRET || '',
          REDDIT_USERNAME: secretData.REDDIT_USERNAME || '',
          REDDIT_PASSWORD: secretData.REDDIT_PASSWORD || '',
        };

        this.logger.log('Successfully loaded secrets from Secrets Manager');
      }
    } catch (error) {
      this.logger.error('Failed to load secrets from Secrets Manager:', error);
      // Fall back to environment variables
      this.loadSecretsFromEnv();
    }
  }

  getSecret(key: string): string {
    return this.secrets[key] || '';
  }

  getGoogleMapsApiKey(): string {
    return this.getSecret('GOOGLE_MAPS_API_KEY');
  }

  getOpenAiApiKey(): string {
    return this.getSecret('OPENAI_API_KEY');
  }

  getGscServiceAccount(): string {
    return this.getSecret('GSC_SERVICE_ACCOUNT');
  }

  getRedditClientId(): string {
    return this.getSecret('REDDIT_CLIENT_ID');
  }

  getRedditClientSecret(): string {
    return this.getSecret('REDDIT_CLIENT_SECRET');
  }

  getRedditUsername(): string {
    return this.getSecret('REDDIT_USERNAME');
  }

  getRedditPassword(): string {
    return this.getSecret('REDDIT_PASSWORD');
  }

  getDynamoDbClient(): DynamoDBDocumentClient | null {
    return this.dynamoDbDocClient;
  }

  getRegion(): string {
    return this.region;
  }
}
