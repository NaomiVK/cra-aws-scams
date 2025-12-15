import { Controller, Get, Post, Query, Body, Param, Logger } from '@nestjs/common';
import { ScamDetectionService } from '../services/scam-detection.service';
import { SearchConsoleService } from '../services/search-console.service';
import { EmergingThreatService } from '../services/emerging-threat.service';
import { ComparisonService } from '../services/comparison.service';
import {
  DateRange,
  AddKeywordRequest,
  TrendingTermData,
} from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';

@Controller('scams')
export class ScamsController {
  private readonly logger = new Logger(ScamsController.name);

  constructor(
    private readonly scamDetectionService: ScamDetectionService,
    private readonly searchConsoleService: SearchConsoleService,
    private readonly emergingThreatService: EmergingThreatService,
    private readonly comparisonService: ComparisonService
  ) {}

  /**
   * GET /api/scams/detect
   * Run scam detection analysis for a date range
   */
  @Get('detect')
  async detectScams(
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
      `Running scam detection for ${dateRange.startDate} to ${dateRange.endDate}`
    );

    const result = await this.scamDetectionService.detectScams(dateRange);

    return {
      success: true,
      data: result,
    };
  }

  /**
   * GET /api/scams/flagged
   * Get flagged terms (alias for detect, for clearer API)
   */
  @Get('flagged')
  async getFlaggedTerms(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string,
    @Query('severity') severity?: string
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

    const result = await this.scamDetectionService.detectScams(dateRange);

    // Filter by severity if specified
    let flaggedTerms = result.flaggedTerms;
    if (severity) {
      const severities = severity.split(',').map((s) => s.trim().toLowerCase());
      flaggedTerms = flaggedTerms.filter((t) =>
        severities.includes(t.severity)
      );
    }

    return {
      success: true,
      data: {
        period: result.period,
        flaggedTerms,
        summary: result.summary,
      },
    };
  }

  /**
   * GET /api/scams/keywords
   * Get the current scam keywords configuration
   */
  @Get('keywords')
  async getKeywordsConfig() {
    const config = this.scamDetectionService.getKeywordsConfig();

    return {
      success: true,
      data: config,
    };
  }

  @Get('dashboard')
  async getDashboardData(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string
  ) {
    let dateRange: DateRange;
    let daysNum: number;

    if (startDate && endDate) {
      dateRange = { startDate, endDate };
      // Calculate days from date range
      const start = new Date(startDate);
      const end = new Date(endDate);
      daysNum = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    } else {
      daysNum = days
        ? parseInt(days, 10)
        : environment.scamDetection.defaultDateRangeDays;
      dateRange = SearchConsoleService.getDateRange(daysNum);
    }

    // Calculate previous period for comparison
    const prevEnd = new Date(dateRange.startDate);
    prevEnd.setDate(prevEnd.getDate() - 1);
    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - daysNum + 1);
    const previousPeriod: DateRange = {
      startDate: prevStart.toISOString().split('T')[0],
      endDate: prevEnd.toISOString().split('T')[0],
    };

    // Get detection results and comparison data in parallel
    const [detection, comparison] = await Promise.all([
      this.scamDetectionService.detectScams(dateRange),
      this.comparisonService.comparePeriods({
        currentPeriod: dateRange,
        previousPeriod,
      }),
    ]);

    const criticalAlerts = detection.flaggedTerms
      .filter((t) => t.severity === 'critical')
      .slice(0, 10);

    const newTerms = detection.flaggedTerms
      .filter((t) => t.status === 'new')
      .slice(0, 10);

    // Build trending terms with actual comparison data
    // Map comparison data by query for quick lookup
    const comparisonMap = new Map(
      comparison.terms.map((t) => [t.query.toLowerCase(), t])
    );

    // Get trending flagged terms with real delta values
    const trendingTerms: TrendingTermData[] = detection.flaggedTerms
      .map((term) => {
        const comp = comparisonMap.get(term.query.toLowerCase());
        return {
          query: term.query,
          severity: term.severity,
          matchedCategory: term.matchedCategory,
          currentImpressions: term.impressions,
          previousImpressions: comp?.previous.impressions || 0,
          changeAmount: comp?.change.impressions || term.impressions,
          changePercent: comp?.change.impressionsPercent || 100,
        };
      })
      .filter((t) => t.changeAmount > 0) // Only show terms with positive growth
      .sort((a, b) => b.changeAmount - a.changeAmount)
      .slice(0, 10);

    return {
      success: true,
      data: {
        summary: detection.summary,
        flaggedTerms: detection.flaggedTerms,
        criticalAlerts,
        newTerms,
        trendingTerms,
        totalQueriesAnalyzed: detection.totalQueriesAnalyzed,
        period: dateRange,
        comparisonPeriod: previousPeriod,
      },
    };
  }

  @Get('emerging')
  async getEmergingThreats(
    @Query('days') days?: string,
    @Query('page') page?: string
  ) {
    const daysNum = days ? parseInt(days, 10) : 7;
    const pageNum = page ? parseInt(page, 10) : 1;
    const result = await this.emergingThreatService.getEmergingThreats(daysNum, pageNum);
    return { success: true, data: result };
  }

  @Post('keywords')
  async addKeyword(@Body() request: AddKeywordRequest) {
    this.logger.log(`Adding keyword "${request.term}" to category "${request.category}"`);
    await this.scamDetectionService.addKeyword(request.term, request.category);
    return { success: true, message: `Added "${request.term}" to ${request.category}` };
  }

  @Post('emerging/:id/dismiss')
  async dismissThreat(@Param('id') id: string) {
    this.logger.log(`Dismissing threat: ${id}`);
    return { success: true, message: `Dismissed threat ${id}` };
  }

  /**
   * GET /api/scams/benchmarks
   * Get the current CTR benchmarks (dynamically calculated from your data)
   */
  @Get('benchmarks')
  async getCTRBenchmarks() {
    const benchmarks = await this.emergingThreatService.getCTRBenchmarks();
    return { success: true, data: benchmarks };
  }

}
