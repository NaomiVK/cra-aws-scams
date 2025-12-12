import { Controller, Get, Query, Logger } from '@nestjs/common';
import { TrendsService } from '../services/trends.service';

@Controller('trends')
export class TrendsController {
  private readonly logger = new Logger(TrendsController.name);

  constructor(private readonly trendsService: TrendsService) {}

  /**
   * GET /api/trends/explore
   * Explore interest over time for keywords (single or comma-separated)
   */
  @Get('explore')
  async exploreKeywords(
    @Query('keyword') keyword?: string,
    @Query('keywords') keywords?: string,
    @Query('timeRange') timeRange?: string
  ) {
    // Support both 'keyword' (single) and 'keywords' (comma-separated)
    const keywordList = keywords
      ? keywords.split(',').map((k) => k.trim()).filter((k) => k.length > 0)
      : keyword
        ? [keyword.trim()]
        : [];

    if (keywordList.length === 0) {
      return {
        success: false,
        error: 'Missing required parameter: keyword or keywords',
      };
    }

    const effectiveTimeRange = timeRange || 'today 3-m';
    this.logger.log(`Exploring trends for keywords: ${keywordList.join(', ')} (timeRange param: "${timeRange}", effective: "${effectiveTimeRange}")`);

    const result = await this.trendsService.exploreKeywords(keywordList, effectiveTimeRange);

    if (!result) {
      return {
        success: false,
        error: 'Failed to fetch trends data. The service may be rate limited.',
      };
    }

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/trends/interest
   * Get interest over time for a keyword
   */
  @Get('interest')
  async getInterestOverTime(
    @Query('keyword') keyword: string,
    @Query('timeRange') timeRange?: string
  ) {
    if (!keyword) {
      return {
        success: false,
        error: 'Missing required parameter: keyword',
      };
    }

    const result = await this.trendsService.getInterestOverTime(
      keyword,
      timeRange || 'today 3-m'
    );

    if (!result) {
      return {
        success: false,
        error: 'Failed to fetch interest data',
      };
    }

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/trends/related
   * Get related queries for a keyword
   */
  @Get('related')
  async getRelatedQueries(@Query('keyword') keyword: string) {
    if (!keyword) {
      return {
        success: false,
        error: 'Missing required parameter: keyword',
      };
    }

    const result = await this.trendsService.getRelatedQueries(keyword);

    if (!result) {
      return {
        success: false,
        error: 'Failed to fetch related queries',
      };
    }

    return {
      success: true,
      data: result,
    };
  }

  @Get('scam-keywords')
  async getScamKeywordsTrends() {
    this.logger.log('Fetching trends for scam keywords');
    const result = await this.trendsService.getScamKeywordsTrends();
    return { success: true, data: result };
  }

  @Get('region')
  async getInterestByRegion(
    @Query('keyword') keyword: string,
    @Query('geo') geo?: string,
    @Query('resolution') resolution?: string
  ) {
    if (!keyword) {
      return { success: false, error: 'Missing required parameter: keyword' };
    }

    const result = await this.trendsService.getInterestByRegion(
      keyword,
      geo || 'CA',
      resolution || 'REGION'
    );

    if (!result) {
      return { success: false, error: 'Failed to fetch interest by region data' };
    }

    return { success: true, data: result };
  }
}
