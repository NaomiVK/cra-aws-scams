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
} from '../services';

// Controllers
import {
  AnalyticsController,
  ScamsController,
  ComparisonController,
  TrendsController,
  ExportController,
  ConfigController,
} from '../controllers';

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
  ],
  providers: [
    AppService,
    AwsConfigService,
    DynamoDbService,
    CacheService,
    SearchConsoleService,
    ScamDetectionService,
    ComparisonService,
    TrendsService,
    EmergingThreatService,
    EmbeddingService,
  ],
})
export class AppModule {}
