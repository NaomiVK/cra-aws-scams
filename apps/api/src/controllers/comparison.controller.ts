import { Controller, Get, Query, Logger } from '@nestjs/common';
import { ComparisonService } from '../services/comparison.service';
import { SearchConsoleService } from '../services/search-console.service';
import { ComparisonRequest } from '@cra-scam-detection/shared-types';

@Controller('comparison')
export class ComparisonController {
  private readonly logger = new Logger(ComparisonController.name);

  constructor(private readonly comparisonService: ComparisonService) {}

  /**
   * GET /api/comparison/period
   * Compare metrics between two custom date ranges
   */
  @Get('period')
  async comparePeriods(
    @Query('currentStart') currentStart: string,
    @Query('currentEnd') currentEnd: string,
    @Query('previousStart') previousStart: string,
    @Query('previousEnd') previousEnd: string
  ) {
    if (!currentStart || !currentEnd || !previousStart || !previousEnd) {
      return {
        success: false,
        error:
          'Missing required parameters: currentStart, currentEnd, previousStart, previousEnd',
      };
    }

    const request: ComparisonRequest = {
      currentPeriod: {
        startDate: currentStart,
        endDate: currentEnd,
      },
      previousPeriod: {
        startDate: previousStart,
        endDate: previousEnd,
      },
    };

    this.logger.log(
      `Comparing periods: ${currentStart}-${currentEnd} vs ${previousStart}-${previousEnd}`
    );

    const result = await this.comparisonService.comparePeriods(request);

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/comparison/week-over-week
   * Quick week-over-week comparison
   */
  @Get('week-over-week')
  async compareWeekOverWeek() {
    this.logger.log('Running week-over-week comparison');

    const result = await this.comparisonService.compareWeekOverWeek();

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/comparison/month-over-month
   * Quick month-over-month comparison (28 days)
   */
  @Get('month-over-month')
  async compareMonthOverMonth() {
    this.logger.log('Running month-over-month comparison');

    const result = await this.comparisonService.compareMonthOverMonth();

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/comparison/gainers
   * Get top terms with biggest impression increases
   */
  @Get('gainers')
  async getTopGainers(
    @Query('days') days?: string,
    @Query('limit') limit?: string
  ) {
    const daysNum = days ? parseInt(days, 10) : 7;
    const limitNum = limit ? parseInt(limit, 10) : 20;

    const currentPeriod = SearchConsoleService.getDateRange(daysNum);

    // Calculate previous period
    const prevEnd = new Date(currentPeriod.startDate);
    prevEnd.setDate(prevEnd.getDate() - 1);
    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - daysNum + 1);

    const request: ComparisonRequest = {
      currentPeriod,
      previousPeriod: {
        startDate: prevStart.toISOString().split('T')[0],
        endDate: prevEnd.toISOString().split('T')[0],
      },
    };

    const gainers = await this.comparisonService.getTopGainers(
      request,
      limitNum
    );

    return {
      success: true,
      data: {
        period: request,
        gainers,
      },
    };
  }

  /**
   * GET /api/comparison/new-terms
   * Get terms that appeared in current period but not previous
   */
  @Get('new-terms')
  async getNewTerms(
    @Query('days') days?: string,
    @Query('minImpressions') minImpressions?: string
  ) {
    const daysNum = days ? parseInt(days, 10) : 7;
    const minImp = minImpressions ? parseInt(minImpressions, 10) : 500;

    const currentPeriod = SearchConsoleService.getDateRange(daysNum);

    // Calculate previous period
    const prevEnd = new Date(currentPeriod.startDate);
    prevEnd.setDate(prevEnd.getDate() - 1);
    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - daysNum + 1);

    const request: ComparisonRequest = {
      currentPeriod,
      previousPeriod: {
        startDate: prevStart.toISOString().split('T')[0],
        endDate: prevEnd.toISOString().split('T')[0],
      },
    };

    const newTerms = await this.comparisonService.getNewTerms(request, minImp);

    return {
      success: true,
      data: {
        period: request,
        minImpressions: minImp,
        newTerms,
        count: newTerms.length,
      },
    };
  }
}
