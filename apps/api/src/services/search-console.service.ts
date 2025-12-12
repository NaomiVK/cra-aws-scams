import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { google, searchconsole_v1 } from 'googleapis';
import { CacheService } from './cache.service';
import { environment } from '../environments/environment';
import {
  SearchAnalyticsRow,
  SearchAnalyticsQuery,
  DateRange,
  CTRBenchmarks,
} from '@cra-scam-detection/shared-types';
import * as path from 'path';

@Injectable()
export class SearchConsoleService implements OnModuleInit {
  private readonly logger = new Logger(SearchConsoleService.name);
  private searchConsole: searchconsole_v1.Searchconsole;
  private readonly siteUrl: string;
  private readonly craUrlFilters: string[];

  constructor(private readonly cacheService: CacheService) {
    this.siteUrl = environment.google.siteUrl;
    this.craUrlFilters = environment.google.craUrlFilters;
  }

  async onModuleInit() {
    await this.initializeClient();
  }

  /**
   * Initialize Google Search Console API client
   */
  private async initializeClient(): Promise<void> {
    try {
      const credentialsPath = path.resolve(
        process.cwd(),
        'service-account-credentials.json'
      );

      this.logger.log(`Loading credentials from: ${credentialsPath}`);

      const auth = new google.auth.GoogleAuth({
        keyFile: credentialsPath,
        scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
      });

      const authClient = await auth.getClient();
      this.searchConsole = google.searchconsole({
        version: 'v1',
        auth: authClient as Parameters<typeof google.searchconsole>[0]['auth'],
      });

      this.logger.log('Google Search Console client initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize Search Console client:', error);
      throw error;
    }
  }

  /**
   * Fetch search analytics data from Google Search Console
   */
  async getSearchAnalytics(
    query: SearchAnalyticsQuery
  ): Promise<SearchAnalyticsRow[]> {
    const cacheKey = `analytics:${JSON.stringify(query)}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const allRows: SearchAnalyticsRow[] = [];

        // Fetch data for each CRA URL filter
        for (const urlFilter of this.craUrlFilters) {
          try {
            const rows = await this.fetchWithPagination(query, urlFilter);
            allRows.push(...rows);
          } catch (error) {
            this.logger.warn(
              `Error fetching data for filter ${urlFilter}:`,
              error
            );
          }
        }

        // Deduplicate by query (aggregate impressions/clicks for same query)
        return this.aggregateByQuery(allRows);
      },
      environment.cache.analyticsTtl
    );
  }

  /**
   * Fetch data with pagination support
   * Respects maxRows limit from environment config
   */
  private async fetchWithPagination(
    query: SearchAnalyticsQuery,
    urlFilter: string
  ): Promise<SearchAnalyticsRow[]> {
    const allRows: SearchAnalyticsRow[] = [];
    const maxRows = environment.searchConsole?.maxRows || 5000;
    const rowLimit = Math.min(query.rowLimit || maxRows, maxRows);
    let startRow = 0;

    while (allRows.length < rowLimit) {
      const batchSize = Math.min(25000, rowLimit - allRows.length);

      const response = await this.searchConsole.searchanalytics.query({
        siteUrl: this.siteUrl,
        requestBody: {
          startDate: query.startDate,
          endDate: query.endDate,
          dimensions: query.dimensions || ['query'],
          dimensionFilterGroups: [
            {
              groupType: 'and',
              filters: [
                {
                  dimension: 'page',
                  operator: 'contains',
                  expression: urlFilter,
                },
              ],
            },
          ],
          rowLimit: batchSize,
          startRow,
        },
      });

      const rows = response.data.rows || [];
      if (rows.length === 0) break;

      allRows.push(
        ...rows.map((row) => ({
          keys: row.keys || [],
          clicks: row.clicks || 0,
          impressions: row.impressions || 0,
          ctr: row.ctr || 0,
          position: row.position || 0,
        }))
      );

      if (rows.length < batchSize) break;
      startRow += batchSize;
    }

    this.logger.debug(`Fetched ${allRows.length} rows for filter ${urlFilter} (max: ${rowLimit})`);
    return allRows;
  }

  /**
   * Aggregate rows by query (combine data from multiple URL filters)
   */
  private aggregateByQuery(rows: SearchAnalyticsRow[]): SearchAnalyticsRow[] {
    const queryMap = new Map<string, SearchAnalyticsRow>();

    for (const row of rows) {
      const query = row.keys[0]?.toLowerCase() || '';
      const existing = queryMap.get(query);

      if (existing) {
        // Aggregate metrics
        const totalImpressions = existing.impressions + row.impressions;
        const totalClicks = existing.clicks + row.clicks;

        existing.impressions = totalImpressions;
        existing.clicks = totalClicks;
        existing.ctr = totalImpressions > 0 ? totalClicks / totalImpressions : 0;
        // Weighted average position
        existing.position =
          (existing.position * existing.impressions +
            row.position * row.impressions) /
          totalImpressions;
      } else {
        queryMap.set(query, { ...row, keys: [query] });
      }
    }

    return Array.from(queryMap.values());
  }

  /**
   * Get search analytics for a specific date range (convenience method)
   */
  async getAnalyticsForDateRange(
    dateRange: DateRange
  ): Promise<SearchAnalyticsRow[]> {
    return this.getSearchAnalytics({
      startDate: dateRange.startDate,
      endDate: dateRange.endDate,
      dimensions: ['query'],
      rowLimit: 25000,
    });
  }

  /**
   * Get queries with minimum impression threshold
   * Uses searchConsole.minImpressions from config as default
   */
  async getQueriesAboveThreshold(
    dateRange: DateRange,
    minImpressions?: number
  ): Promise<SearchAnalyticsRow[]> {
    const threshold = minImpressions ??
      environment.searchConsole?.minImpressions ??
      environment.scamDetection.impressionThreshold;

    const allData = await this.getAnalyticsForDateRange(dateRange);
    return allData.filter((row) => row.impressions >= threshold);
  }

  /**
   * Get date range for last N days
   */
  static getDateRange(days: number): DateRange {
    const endDate = new Date();
    endDate.setDate(endDate.getDate() - 2); // GSC data has 2-day lag

    const startDate = new Date(endDate);
    startDate.setDate(startDate.getDate() - days);

    return {
      startDate: startDate.toISOString().split('T')[0],
      endDate: endDate.toISOString().split('T')[0],
    };
  }

  /**
   * Calculate dynamic CTR benchmarks from actual Search Console data
   * Uses percentile analysis of queries grouped by position ranges
   *
   * @param days Number of days of historical data to analyze (default 90)
   * @param minImpressions Minimum impressions for a query to be included (default 10)
   */
  async calculateCTRBenchmarks(
    days = 90,
    minImpressions = 10
  ): Promise<CTRBenchmarks> {
    const cacheKey = `ctr-benchmarks:${days}:${minImpressions}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        this.logger.log(`Calculating dynamic CTR benchmarks from ${days} days of data`);

        const dateRange = SearchConsoleService.getDateRange(days);
        const allData = await this.getAnalyticsForDateRange(dateRange);

        // Filter to queries with meaningful impressions
        const significantQueries = allData.filter(
          (row) => row.impressions >= minImpressions
        );

        this.logger.log(
          `Analyzing ${significantQueries.length} queries with ${minImpressions}+ impressions`
        );

        // Group queries by position ranges
        const positionGroups: Record<string, number[]> = {
          '1-3': [],
          '4-8': [],
          '9-15': [],
          '16+': [],
        };

        for (const query of significantQueries) {
          const position = query.position;
          const ctr = query.ctr;

          if (position <= 3) {
            positionGroups['1-3'].push(ctr);
          } else if (position <= 8) {
            positionGroups['4-8'].push(ctr);
          } else if (position <= 15) {
            positionGroups['9-15'].push(ctr);
          } else {
            positionGroups['16+'].push(ctr);
          }
        }

        // Calculate percentiles for each group
        const calculateBenchmark = (
          positionRange: string,
          ctrs: number[]
        ): { positionRange: string; min: number; expected: number; max: number; sampleSize: number } => {
          if (ctrs.length === 0) {
            // Fallback to industry defaults if no data
            const defaults: Record<string, { min: number; expected: number }> = {
              '1-3': { min: 0.03, expected: 0.20 },
              '4-8': { min: 0.02, expected: 0.10 },
              '9-15': { min: 0.01, expected: 0.05 },
              '16+': { min: 0.005, expected: 0.02 },
            };
            return {
              positionRange,
              min: defaults[positionRange].min,
              expected: defaults[positionRange].expected,
              max: defaults[positionRange].expected * 1.5,
              sampleSize: 0,
            };
          }

          // Sort CTRs for percentile calculation
          const sorted = [...ctrs].sort((a, b) => a - b);

          const percentile = (p: number): number => {
            const index = (p / 100) * (sorted.length - 1);
            const lower = Math.floor(index);
            const upper = Math.ceil(index);
            if (lower === upper) return sorted[lower];
            return sorted[lower] + (index - lower) * (sorted[upper] - sorted[lower]);
          };

          return {
            positionRange,
            min: percentile(10),      // 10th percentile - below this is anomalous
            expected: percentile(50), // Median CTR
            max: percentile(90),      // 90th percentile
            sampleSize: ctrs.length,
          };
        };

        const benchmarks: CTRBenchmarks = {
          '1-3': calculateBenchmark('1-3', positionGroups['1-3']),
          '4-8': calculateBenchmark('4-8', positionGroups['4-8']),
          '9-15': calculateBenchmark('9-15', positionGroups['9-15']),
          '16+': calculateBenchmark('16+', positionGroups['16+']),
          calculatedAt: new Date().toISOString(),
          dataRange: dateRange,
          totalQueriesAnalyzed: significantQueries.length,
        };

        this.logger.log(
          `CTR benchmarks calculated: ` +
          `1-3: ${(benchmarks['1-3'].expected * 100).toFixed(1)}% expected (n=${benchmarks['1-3'].sampleSize}), ` +
          `4-8: ${(benchmarks['4-8'].expected * 100).toFixed(1)}% expected (n=${benchmarks['4-8'].sampleSize})`
        );

        return benchmarks;
      },
      // Use benchmarksTtl from config (default 1 hour)
      environment.cache.benchmarksTtl || 3600
    );
  }
}
