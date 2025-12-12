import { Injectable, Logger } from '@nestjs/common';
import { CacheService } from './cache.service';
import { SearchConsoleService } from './search-console.service';
import {
  DateRange,
  ComparisonRequest,
  ComparisonResponse,
  TermComparison,
  SearchAnalyticsRow,
} from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';

@Injectable()
export class ComparisonService {
  private readonly logger = new Logger(ComparisonService.name);

  constructor(
    private readonly cacheService: CacheService,
    private readonly searchConsoleService: SearchConsoleService
  ) {}

  /**
   * Compare search analytics between two periods
   */
  async comparePeriods(request: ComparisonRequest): Promise<ComparisonResponse> {
    const cacheKey = `comparison:${JSON.stringify(request)}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        this.logger.log(
          `Comparing periods: ${request.currentPeriod.startDate}-${request.currentPeriod.endDate} ` +
            `vs ${request.previousPeriod.startDate}-${request.previousPeriod.endDate}`
        );

        // Fetch data for both periods in parallel
        const [currentData, previousData] = await Promise.all([
          this.searchConsoleService.getAnalyticsForDateRange(
            request.currentPeriod
          ),
          this.searchConsoleService.getAnalyticsForDateRange(
            request.previousPeriod
          ),
        ]);

        // Create maps for quick lookup
        const currentMap = new Map<string, SearchAnalyticsRow>();
        const previousMap = new Map<string, SearchAnalyticsRow>();

        for (const row of currentData) {
          currentMap.set(row.keys[0]?.toLowerCase() || '', row);
        }
        for (const row of previousData) {
          previousMap.set(row.keys[0]?.toLowerCase() || '', row);
        }

        // Get all unique queries
        const allQueries = new Set([
          ...currentMap.keys(),
          ...previousMap.keys(),
        ]);

        // Build comparison for each query
        const termComparisons: TermComparison[] = [];
        let totalCurrentImpressions = 0;
        let totalPreviousImpressions = 0;
        let newTerms = 0;
        let goneTerms = 0;

        for (const query of allQueries) {
          if (!query) continue;

          const current = currentMap.get(query);
          const previous = previousMap.get(query);

          const isNew = !previous && !!current;
          const isGone = !!previous && !current;

          if (isNew) newTerms++;
          if (isGone) goneTerms++;

          const currentMetrics = current || {
            impressions: 0,
            clicks: 0,
            ctr: 0,
            position: 0,
          };
          const previousMetrics = previous || {
            impressions: 0,
            clicks: 0,
            ctr: 0,
            position: 0,
          };

          totalCurrentImpressions += currentMetrics.impressions;
          totalPreviousImpressions += previousMetrics.impressions;

          termComparisons.push({
            query,
            current: {
              impressions: currentMetrics.impressions,
              clicks: currentMetrics.clicks,
              ctr: currentMetrics.ctr,
              position: currentMetrics.position,
            },
            previous: {
              impressions: previousMetrics.impressions,
              clicks: previousMetrics.clicks,
              ctr: previousMetrics.ctr,
              position: previousMetrics.position,
            },
            change: {
              impressions:
                currentMetrics.impressions - previousMetrics.impressions,
              impressionsPercent: this.calculatePercentChange(
                previousMetrics.impressions,
                currentMetrics.impressions
              ),
              clicks: currentMetrics.clicks - previousMetrics.clicks,
              clicksPercent: this.calculatePercentChange(
                previousMetrics.clicks,
                currentMetrics.clicks
              ),
              ctr: currentMetrics.ctr - previousMetrics.ctr,
              position: currentMetrics.position - previousMetrics.position,
            },
            isNew,
            isGone,
          });
        }

        // Sort by impression change (descending)
        termComparisons.sort(
          (a, b) => b.change.impressions - a.change.impressions
        );

        const response: ComparisonResponse = {
          currentPeriod: request.currentPeriod,
          previousPeriod: request.previousPeriod,
          summary: {
            totalTerms: allQueries.size,
            newTerms,
            goneTerms,
            totalImpressions: {
              current: totalCurrentImpressions,
              previous: totalPreviousImpressions,
              change: totalCurrentImpressions - totalPreviousImpressions,
              changePercent: this.calculatePercentChange(
                totalPreviousImpressions,
                totalCurrentImpressions
              ),
            },
          },
          terms: termComparisons,
        };

        this.logger.log(
          `Comparison complete: ${response.summary.totalTerms} terms, ` +
            `${newTerms} new, ${goneTerms} gone`
        );

        return response;
      },
      environment.cache.analyticsTtl
    );
  }

  /**
   * Week-over-week comparison (convenience method)
   */
  async compareWeekOverWeek(): Promise<ComparisonResponse> {
    const currentPeriod = SearchConsoleService.getDateRange(7);
    const previousPeriod = this.getPreviousPeriod(currentPeriod, 7);

    return this.comparePeriods({
      currentPeriod,
      previousPeriod,
    });
  }

  /**
   * Month-over-month comparison (convenience method)
   */
  async compareMonthOverMonth(): Promise<ComparisonResponse> {
    const currentPeriod = SearchConsoleService.getDateRange(28);
    const previousPeriod = this.getPreviousPeriod(currentPeriod, 28);

    return this.comparePeriods({
      currentPeriod,
      previousPeriod,
    });
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

  /**
   * Calculate percent change between two values
   */
  private calculatePercentChange(previous: number, current: number): number {
    if (previous === 0) {
      return current > 0 ? 100 : 0;
    }
    return ((current - previous) / previous) * 100;
  }

  /**
   * Get top gainers (terms with biggest impression increase)
   */
  async getTopGainers(
    request: ComparisonRequest,
    limit = 20
  ): Promise<TermComparison[]> {
    const comparison = await this.comparePeriods(request);
    return comparison.terms
      .filter((t) => t.change.impressions > 0 && !t.isNew)
      .slice(0, limit);
  }

  /**
   * Get new terms in current period
   */
  async getNewTerms(
    request: ComparisonRequest,
    minImpressions: number = environment.scamDetection.impressionThreshold
  ): Promise<TermComparison[]> {
    const comparison = await this.comparePeriods(request);
    return comparison.terms.filter(
      (t) => t.isNew && t.current.impressions >= minImpressions
    );
  }
}
