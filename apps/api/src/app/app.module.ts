import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';

// Services
import {
  CacheService,
  SearchConsoleService,
  ScamDetectionService,
  ComparisonService,
  TrendsService,
  EmergingThreatService,
  EmbeddingService,
  AwsConfigService,
  DynamoDbService,
  SentimentService,
  RedditService,
  AuthService,
  TermService,
} from '../services';

// Controllers
import {
  AnalyticsController,
  ScamsController,
  ComparisonController,
  TrendsController,
  ExportController,
  ConfigController,
  RedditController,
} from '../controllers';

// Guards
import { AdminAuthGuard } from '../guards';

@Module({
  imports: [],
  controllers: [
    AppController,
    AnalyticsController,
    ScamsController,
    ComparisonController,
    TrendsController,
    ExportController,
    ConfigController,
    RedditController,
  ],
  providers: [
    AppService,
    AwsConfigService,
    DynamoDbService,
    CacheService,
    SearchConsoleService,
    TermService,
    ScamDetectionService,
    ComparisonService,
    TrendsService,
    EmergingThreatService,
    EmbeddingService,
    SentimentService,
    RedditService,
    AuthService,
    AdminAuthGuard,
  ],
})
export class AppModule {}
