import { Controller, Get, Post, Delete, Query, Body, Param, Logger, HttpException, HttpStatus, UseGuards } from '@nestjs/common';
import { ScamDetectionService } from '../services/scam-detection.service';
import { SearchConsoleService } from '../services/search-console.service';
import { EmergingThreatService } from '../services/emerging-threat.service';
import { ComparisonService } from '../services/comparison.service';
import { AuthService } from '../services/auth.service';
import { TermService } from '../services/term.service';
import { AdminAuthGuard } from '../guards/admin-auth.guard';
import {
  DateRange,
  AddKeywordRequest,
  AddTermRequest,
  FlaggedTerm,
  FlaggedTermWithComparison,
  TermComparison,
} from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';

/**
 * Parse and validate a numeric query parameter
 */
function parseIntParam(value: string | undefined, defaultValue: number, paramName: string): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed < 1) {
    throw new HttpException(
      `Invalid ${paramName}: must be a positive integer`,
      HttpStatus.BAD_REQUEST
    );
  }
  return parsed;
}

@Controller('scams')
export class ScamsController {
  private readonly logger = new Logger(ScamsController.name);

  constructor(
    private readonly scamDetectionService: ScamDetectionService,
    private readonly emergingThreatService: EmergingThreatService,
    private readonly comparisonService: ComparisonService,
    private readonly authService: AuthService,
    private readonly termService: TermService,
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
    try {
      let dateRange: DateRange;

      if (startDate && endDate) {
        dateRange = { startDate, endDate };
      } else {
        const daysNum = parseIntParam(days, environment.scamDetection.defaultDateRangeDays, 'days');
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
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to detect scams: ${error}`);
      throw new HttpException('Failed to run scam detection', HttpStatus.INTERNAL_SERVER_ERROR);
    }
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
    try {
      let dateRange: DateRange;

      if (startDate && endDate) {
        dateRange = { startDate, endDate };
      } else {
        const daysNum = parseIntParam(days, environment.scamDetection.defaultDateRangeDays, 'days');
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
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get flagged terms: ${error}`);
      throw new HttpException('Failed to get flagged terms', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * GET /api/scams/keywords
   * Get the current scam keywords configuration
   */
  @Get('keywords')
  async getKeywordsConfig() {
    try {
      const config = this.scamDetectionService.getKeywordsConfig();

      return {
        success: true,
        data: config,
      };
    } catch (error) {
      this.logger.error(`Failed to get keywords config: ${error}`);
      throw new HttpException('Failed to get keywords configuration', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('dashboard')
  async getDashboardData(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string
  ) {
    try {
      let dateRange: DateRange;

      if (startDate && endDate) {
        dateRange = { startDate, endDate };
      } else {
        const daysNum = parseIntParam(days, environment.scamDetection.defaultDateRangeDays, 'days');
        dateRange = SearchConsoleService.getDateRange(daysNum);
      }

      // Calculate previous period
      const daysInPeriod = this.getDaysBetween(dateRange.startDate, dateRange.endDate);
      const previousPeriod = this.getPreviousPeriod(dateRange, daysInPeriod);

      // Fetch detection and comparison data in parallel
      const [detection, comparison] = await Promise.all([
        this.scamDetectionService.detectScams(dateRange),
        this.comparisonService.comparePeriods({
          currentPeriod: dateRange,
          previousPeriod,
        }),
      ]);

      // Create lookup map from comparison data by query (lowercase)
      const comparisonMap = new Map(
        comparison.terms.map((t) => [t.query.toLowerCase(), t])
      );

      // Filter and enrich critical alerts
      const criticalAlerts = detection.flaggedTerms
        .filter((t) => t.severity === 'critical')
        .slice(0, 20)
        .map((term) => this.enrichWithComparison(term, comparisonMap));

      // Filter and enrich high alerts
      const highAlerts = detection.flaggedTerms
        .filter((t) => t.severity === 'high')
        .slice(0, 20)
        .map((term) => this.enrichWithComparison(term, comparisonMap));

      // Get top 10 new terms (terms that appeared this period but not previous)
      const newTerms = comparison.terms
        .filter((t) => t.isNew && t.current.impressions >= 100)
        .sort((a, b) => b.current.impressions - a.current.impressions)
        .slice(0, 10);

      return {
        success: true,
        data: {
          summary: detection.summary,
          criticalAlerts,
          highAlerts,
          newTerms,
          totalQueriesAnalyzed: detection.totalQueriesAnalyzed,
          period: dateRange,
          previousPeriod,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get dashboard data: ${error}`);
      throw new HttpException('Failed to get dashboard data', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Enrich a flagged term with comparison data from previous period
   */
  private enrichWithComparison(
    term: FlaggedTerm,
    comparisonMap: Map<string, TermComparison>
  ): FlaggedTermWithComparison {
    const comparison = comparisonMap.get(term.query.toLowerCase());

    if (!comparison || comparison.isNew) {
      return {
        ...term,
        previous: null,
        isNew: true,
        change: undefined,
      };
    }

    return {
      ...term,
      previous: comparison.previous,
      isNew: false,
      change: {
        impressions: comparison.change.impressions,
        impressionsPercent: comparison.change.impressionsPercent,
        position: comparison.change.position,
      },
    };
  }

  /**
   * Calculate the number of days between two dates
   */
  private getDaysBetween(startDate: string, endDate: string): number {
    const start = new Date(startDate);
    const end = new Date(endDate);
    return Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24)) + 1;
  }

  /**
   * Get previous period based on current period and duration
   */
  private getPreviousPeriod(currentPeriod: DateRange, days: number): DateRange {
    const prevEnd = new Date(currentPeriod.startDate);
    prevEnd.setDate(prevEnd.getDate() - 1);

    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - days + 1);

    return {
      startDate: prevStart.toISOString().split('T')[0],
      endDate: prevEnd.toISOString().split('T')[0],
    };
  }

  @Get('emerging')
  async getEmergingThreats(
    @Query('days') days?: string,
    @Query('page') page?: string
  ) {
    try {
      const daysNum = parseIntParam(days, 7, 'days');
      const pageNum = parseIntParam(page, 1, 'page');
      const result = await this.emergingThreatService.getEmergingThreats(daysNum, pageNum);
      return { success: true, data: result };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get emerging threats: ${error}`);
      throw new HttpException('Failed to get emerging threats', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('keywords')
  async addKeyword(@Body() request: AddKeywordRequest) {
    try {
      if (!request.term || typeof request.term !== 'string' || request.term.trim().length === 0) {
        throw new HttpException('Invalid term: must be a non-empty string', HttpStatus.BAD_REQUEST);
      }
      if (!request.category || typeof request.category !== 'string') {
        throw new HttpException('Invalid category: must be a valid category name', HttpStatus.BAD_REQUEST);
      }

      this.logger.log(`Adding keyword "${request.term}" to category "${request.category}"`);
      await this.scamDetectionService.addKeyword(request.term, request.category);
      return { success: true, message: `Added "${request.term}" to ${request.category}` };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to add keyword: ${error}`);
      throw new HttpException('Failed to add keyword', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('emerging/:id/dismiss')
  async dismissThreat(@Param('id') id: string) {
    try {
      this.logger.log(`Dismissing threat: ${id}`);
      return { success: true, message: `Dismissed threat ${id}` };
    } catch (error) {
      this.logger.error(`Failed to dismiss threat: ${error}`);
      throw new HttpException('Failed to dismiss threat', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * GET /api/scams/benchmarks
   * Get the current CTR benchmarks (dynamically calculated from your data)
   */
  @Get('benchmarks')
  async getCTRBenchmarks() {
    try {
      const benchmarks = await this.emergingThreatService.getCTRBenchmarks();
      return { success: true, data: benchmarks };
    } catch (error) {
      this.logger.error(`Failed to get CTR benchmarks: ${error}`);
      throw new HttpException('Failed to get CTR benchmarks', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * GET /api/scams/seed-phrases
   * Get all seed phrases from DynamoDB for UI dropdowns
   */
  @Get('seed-phrases')
  getSeedPhrases() {
    try {
      const phrases = this.scamDetectionService.getSeedPhrases();
      return { success: true, data: phrases };
    } catch (error) {
      this.logger.error(`Failed to get seed phrases: ${error}`);
      throw new HttpException('Failed to get seed phrases', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  // ==================== AUTH ENDPOINTS ====================

  /**
   * POST /api/scams/auth/validate
   * Validate admin password
   */
  @Post('auth/validate')
  async validateAdmin(@Body() body: { password: string }) {
    try {
      if (!body.password) {
        throw new HttpException('Password required', HttpStatus.BAD_REQUEST);
      }

      const isValid = await this.authService.validatePassword(body.password);
      return { success: true, data: { valid: isValid } };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Auth validation error: ${error}`);
      throw new HttpException('Authentication failed', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * GET /api/scams/auth/status
   * Check if auth is configured
   */
  @Get('auth/status')
  getAuthStatus() {
    return {
      success: true,
      data: {
        configured: this.authService.isAuthConfigured(),
      },
    };
  }

  // ==================== UNIFIED TERM ENDPOINTS ====================

  /**
   * GET /api/scams/terms
   * Get all unified terms (protected)
   */
  @Get('terms')
  @UseGuards(AdminAuthGuard)
  getAllTerms() {
    try {
      const response = this.termService.getUnifiedTermsResponse();
      return { success: true, data: response };
    } catch (error) {
      this.logger.error(`Failed to get terms: ${error}`);
      throw new HttpException('Failed to get terms', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * POST /api/scams/terms
   * Add a new unified term (protected)
   */
  @Post('terms')
  @UseGuards(AdminAuthGuard)
  async addTerm(@Body() request: AddTermRequest) {
    try {
      if (!request.term || typeof request.term !== 'string' || request.term.trim().length === 0) {
        throw new HttpException('Invalid term: must be a non-empty string', HttpStatus.BAD_REQUEST);
      }
      if (!request.category || typeof request.category !== 'string') {
        throw new HttpException('Invalid category: must be a valid category name', HttpStatus.BAD_REQUEST);
      }

      this.logger.log(`Adding unified term "${request.term}" to category "${request.category}"`);
      const success = await this.termService.addTerm(request);

      if (!success) {
        throw new HttpException('Term already exists or could not be added', HttpStatus.CONFLICT);
      }

      return { success: true, message: `Added "${request.term}" to ${request.category}` };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to add term: ${error}`);
      throw new HttpException('Failed to add term', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * DELETE /api/scams/terms/:category/:term
   * Remove a unified term (protected)
   */
  @Delete('terms/:category/:term')
  @UseGuards(AdminAuthGuard)
  async removeTerm(
    @Param('category') category: string,
    @Param('term') term: string
  ) {
    try {
      this.logger.log(`Removing term "${term}" from category "${category}"`);
      const success = await this.termService.removeTerm(decodeURIComponent(term), category);

      if (!success) {
        throw new HttpException('Term not found', HttpStatus.NOT_FOUND);
      }

      return { success: true, message: `Removed "${term}" from ${category}` };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to remove term: ${error}`);
      throw new HttpException('Failed to remove term', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * POST /api/scams/terms/:category/:term/restore
   * Restore a removed unified term (protected)
   */
  @Post('terms/:category/:term/restore')
  @UseGuards(AdminAuthGuard)
  async restoreTerm(
    @Param('category') category: string,
    @Param('term') term: string
  ) {
    try {
      this.logger.log(`Restoring term "${term}" in category "${category}"`);
      const success = await this.termService.restoreTerm(decodeURIComponent(term), category);

      if (!success) {
        throw new HttpException('Term not found or not removed', HttpStatus.NOT_FOUND);
      }

      return { success: true, message: `Restored "${term}" in ${category}` };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to restore term: ${error}`);
      throw new HttpException('Failed to restore term', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}
