import { Controller, Get, Query, Logger } from '@nestjs/common';
import { SearchConsoleService } from '../services/search-console.service';
import { DateRange } from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';

@Controller('analytics')
export class AnalyticsController {
  private readonly logger = new Logger(AnalyticsController.name);

  constructor(private readonly searchConsoleService: SearchConsoleService) {}

  /**
   * GET /api/analytics/queries
   * Fetch search queries for CRA pages
   */
  @Get('queries')
  async getQueries(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string
  ) {
    let dateRange: DateRange;

    if (startDate && endDate) {
      dateRange = { startDate, endDate };
    } else {
      const daysNum = days
        ? parseInt(days, 10)
        : environment.scamDetection.defaultDateRangeDays;
      dateRange = SearchConsoleService.getDateRange(daysNum);
    }

    this.logger.log(
      `Fetching queries for ${dateRange.startDate} to ${dateRange.endDate}`
    );

    const data = await this.searchConsoleService.getAnalyticsForDateRange(
      dateRange
    );

    return {
      success: true,
      data,
      meta: {
        period: dateRange,
        totalQueries: data.length,
      },
    };
  }

  /**
   * GET /api/analytics/summary
   * Get aggregated summary metrics
   */
  @Get('summary')
  async getSummary(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string
  ) {
    let dateRange: DateRange;

    if (startDate && endDate) {
      dateRange = { startDate, endDate };
    } else {
      const daysNum = days
        ? parseInt(days, 10)
        : environment.scamDetection.defaultDateRangeDays;
      dateRange = SearchConsoleService.getDateRange(daysNum);
    }

    const data = await this.searchConsoleService.getAnalyticsForDateRange(
      dateRange
    );

    // Calculate summary metrics
    const totalImpressions = data.reduce((sum, r) => sum + r.impressions, 0);
    const totalClicks = data.reduce((sum, r) => sum + r.clicks, 0);
    const avgCtr = totalImpressions > 0 ? totalClicks / totalImpressions : 0;
    const avgPosition =
      data.length > 0
        ? data.reduce((sum, r) => sum + r.position, 0) / data.length
        : 0;

    // Queries above threshold
    const aboveThreshold = data.filter(
      (r) => r.impressions >= environment.scamDetection.impressionThreshold
    );

    return {
      success: true,
      data: {
        period: dateRange,
        totalQueries: data.length,
        queriesAboveThreshold: aboveThreshold.length,
        impressionThreshold: environment.scamDetection.impressionThreshold,
        metrics: {
          totalImpressions,
          totalClicks,
          avgCtr,
          avgPosition,
        },
      },
    };
  }
}
