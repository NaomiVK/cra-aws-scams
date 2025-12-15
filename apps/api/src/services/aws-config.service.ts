import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { environment } from '../environments/environment';

@Injectable()
export class AwsConfigService implements OnModuleInit {
  private readonly logger = new Logger(AwsConfigService.name);
  private ssmClient: SSMClient | null = null;
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
        await this.loadSecretsFromParameterStore();
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
    };
  }

  private async loadSecretsFromParameterStore() {
    this.logger.log('Loading secrets from AWS Parameter Store');

    try {
      this.ssmClient = new SSMClient({ region: this.region });

      const parameterNames = [
        '/cra-scam/GOOGLE_MAPS_API_KEY',
        '/cra-scam/OPENAI_API_KEY',
        '/cra-scam/GSC_SERVICE_ACCOUNT',
      ];

      for (const paramName of parameterNames) {
        try {
          const command = new GetParameterCommand({
            Name: paramName,
            WithDecryption: true,
          });
          const response = await this.ssmClient.send(command);

          // Extract key name from path (e.g., "/cra-scam/GOOGLE_MAPS_API_KEY" -> "GOOGLE_MAPS_API_KEY")
          const keyName = paramName.split('/').pop() || paramName;
          this.secrets[keyName] = response.Parameter?.Value || '';

          this.logger.log(`Loaded parameter: ${paramName}`);
        } catch (err) {
          this.logger.warn(`Failed to load parameter ${paramName}: ${err}`);
        }
      }
    } catch (error) {
      this.logger.error('Failed to initialize SSM client:', error);
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

  getDynamoDbClient(): DynamoDBDocumentClient | null {
    return this.dynamoDbDocClient;
  }

  getRegion(): string {
    return this.region;
  }
}
