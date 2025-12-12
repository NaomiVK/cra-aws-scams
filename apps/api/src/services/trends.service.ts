import { Injectable, Logger } from '@nestjs/common';
import { CacheService } from './cache.service';
import { ScamDetectionService } from './scam-detection.service';
import {
  TrendDataPoint,
  InterestOverTime,
  TrendExploration,
  TrendsPanelData,
  TrendsResult,
  InterestByRegionResponse,
  RegionInterest,
} from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';

// Using require for google-trends-api as it doesn't have proper TS types
const googleTrends = require('google-trends-api');

@Injectable()
export class TrendsService {
  private readonly logger = new Logger(TrendsService.name);

  constructor(
    private readonly cacheService: CacheService,
    private readonly scamDetectionService: ScamDetectionService
  ) {}

  /**
   * Convert time range string to startTime/endTime Date objects
   */
  private getTimeRangeDates(timeRange: string): { startTime: Date; endTime: Date } {
    const endTime = new Date();
    let startTime = new Date();

    switch (timeRange) {
      case 'now 1-H':
        startTime.setHours(startTime.getHours() - 1);
        break;
      case 'now 4-H':
        startTime.setHours(startTime.getHours() - 4);
        break;
      case 'now 1-d':
        startTime.setDate(startTime.getDate() - 1);
        break;
      case 'now 7-d':
        startTime.setDate(startTime.getDate() - 7);
        break;
      case 'today 1-m':
        startTime.setMonth(startTime.getMonth() - 1);
        break;
      case 'today 3-m':
        startTime.setMonth(startTime.getMonth() - 3);
        break;
      case 'today 12-m':
        startTime.setFullYear(startTime.getFullYear() - 1);
        break;
      case 'today 5-y':
        startTime.setFullYear(startTime.getFullYear() - 5);
        break;
      default:
        // Default to 3 months
        startTime.setMonth(startTime.getMonth() - 3);
    }

    return { startTime, endTime };
  }

  /**
   * Get interest over time for a keyword
   */
  async getInterestOverTime(
    keyword: string,
    timeRange = 'today 3-m'
  ): Promise<InterestOverTime | null> {
    const cacheKey = `trends:interest:${keyword}:${timeRange}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        try {
          const { startTime, endTime } = this.getTimeRangeDates(timeRange);

          this.logger.log(`Fetching trends for "${keyword}" from ${startTime.toISOString()} to ${endTime.toISOString()} (timeRange: ${timeRange})`);

          const result = await googleTrends.interestOverTime({
            keyword,
            geo: 'CA',
            startTime,
            endTime,
          });

          const parsed = JSON.parse(result);
          const timelineData = parsed.default?.timelineData || [];

          this.logger.log(`Received ${timelineData.length} data points for "${keyword}"`);

          const data: TrendDataPoint[] = timelineData.map(
            (point: { formattedTime: string; value: number[] }) => ({
              date: point.formattedTime,
              value: point.value[0] || 0,
            })
          );

          const averageInterest =
            data.length > 0
              ? data.reduce((sum, p) => sum + p.value, 0) / data.length
              : 0;

          return {
            keyword,
            data,
            averageInterest,
          };
        } catch (error) {
          this.logger.error(
            `Failed to fetch trends for "${keyword}" (timeRange: ${timeRange}): ${error.message}`,
            error.stack
          );
          return null;
        }
      },
      environment.cache.trendsTtl
    );
  }

  /**
   * Get related queries for a keyword
   */
  async getRelatedQueries(
    keyword: string
  ): Promise<{ rising: string[]; top: string[] } | null> {
    const cacheKey = `trends:related:${keyword}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        try {
          const result = await googleTrends.relatedQueries({
            keyword,
            geo: 'CA',
          });

          const parsed = JSON.parse(result);
          const defaultData = parsed.default || {};

          const rising =
            defaultData.rankedList?.[0]?.rankedKeyword?.map(
              (item: { query: string }) => item.query
            ) || [];

          const top =
            defaultData.rankedList?.[1]?.rankedKeyword?.map(
              (item: { query: string }) => item.query
            ) || [];

          return { rising, top };
        } catch (error) {
          this.logger.warn(
            `Failed to fetch related queries for "${keyword}": ${error.message}`
          );
          return null;
        }
      },
      environment.cache.trendsTtl
    );
  }

  /**
   * Explore multiple keywords and return combined TrendsResult
   */
  async exploreKeywords(keywords: string[], timeRange = 'today 3-m'): Promise<TrendsResult | null> {
    const cacheKey = `trends:explore-multi:${keywords.sort().join(',')}:${timeRange}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        try {
          const interestResults: Map<string, InterestOverTime> = new Map();
          const relatedResults: Map<string, { rising: string[]; top: string[] }> = new Map();

          // Fetch data for each keyword with rate limiting
          for (const keyword of keywords.slice(0, 5)) { // Limit to 5 to avoid rate limits
            const [interest, related] = await Promise.all([
              this.getInterestOverTime(keyword, timeRange),
              this.getRelatedQueries(keyword),
            ]);

            if (interest) {
              interestResults.set(keyword, interest);
            }
            if (related) {
              relatedResults.set(keyword, related);
            }

            // Small delay between keywords
            await this.delay(300);
          }

          if (interestResults.size === 0) return null;

          // Combine interest over time data - use the order from the first keyword's results
          // Google Trends returns data in chronological order, so we preserve that order
          const firstKeyword = keywords[0];
          const firstInterest = interestResults.get(firstKeyword);

          if (!firstInterest) return null;

          // Use the dates from the first result in their original order (already chronological)
          const interestOverTime = firstInterest.data.map((point) => {
            const values: Record<string, number> = {};
            interestResults.forEach((interest, kw) => {
              const matchingPoint = interest.data.find((p) => p.date === point.date);
              values[kw] = matchingPoint?.value || 0;
            });
            return { date: point.date, values };
          });

          // Build related queries
          const relatedQueries = keywords.map((keyword) => {
            const related = relatedResults.get(keyword);
            const queries = [
              ...(related?.rising || []).map((q) => ({ query: q, value: 0 })),
              ...(related?.top || []).map((q) => ({ query: q, value: 0 })),
            ].slice(0, 10);
            return { keyword, queries };
          });

          return {
            keywords,
            interestOverTime,
            relatedQueries,
            interestByRegion: [], // Not implemented yet
          };
        } catch (error) {
          this.logger.error(`Failed to explore keywords:`, error);
          return null;
        }
      },
      environment.cache.trendsTtl
    );
  }

  /**
   * Explore a keyword (combined interest + related)
   */
  async exploreKeyword(keyword: string): Promise<TrendExploration | null> {
    const cacheKey = `trends:explore:${keyword}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        try {
          const [interest, related] = await Promise.all([
            this.getInterestOverTime(keyword),
            this.getRelatedQueries(keyword),
          ]);

          if (!interest) return null;

          return {
            keyword,
            geo: 'CA',
            timeRange: 'today 3-m',
            interestOverTime: interest.data,
            relatedQueries: {
              rising: (related?.rising || []).map((q) => ({
                query: q,
                value: 0,
                isBreakout: false,
              })),
              top: (related?.top || []).map((q) => ({
                query: q,
                value: 0,
                isBreakout: false,
              })),
            },
          };
        } catch (error) {
          this.logger.error(`Failed to explore keyword "${keyword}":`, error);
          return null;
        }
      },
      environment.cache.trendsTtl
    );
  }

  /**
   * Get trends data for all monitored scam keywords
   */
  async getScamKeywordsTrends(): Promise<TrendsPanelData> {
    const cacheKey = 'trends:scam-panel';

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const keywords = this.scamDetectionService.getTrendsKeywords();
        const monitoredKeywords: TrendsPanelData['monitoredKeywords'] = [];

        // Fetch trends for each keyword (with rate limiting)
        for (const keyword of keywords.slice(0, 10)) {
          // Limit to 10 to avoid rate limits
          try {
            const interest = await this.getInterestOverTime(keyword);
            if (interest && interest.data.length > 0) {
              const recent = interest.data.slice(-7); // Last 7 data points
              const older = interest.data.slice(-14, -7);

              const recentAvg =
                recent.reduce((sum, p) => sum + p.value, 0) / recent.length;
              const olderAvg =
                older.length > 0
                  ? older.reduce((sum, p) => sum + p.value, 0) / older.length
                  : recentAvg;

              const changePercent =
                olderAvg > 0 ? ((recentAvg - olderAvg) / olderAvg) * 100 : 0;

              monitoredKeywords.push({
                keyword,
                currentInterest: Math.round(recentAvg),
                trend:
                  changePercent > 10
                    ? 'up'
                    : changePercent < -10
                      ? 'down'
                      : 'stable',
                changePercent: Math.round(changePercent),
              });
            }

            // Small delay to avoid rate limiting
            await this.delay(500);
          } catch (error) {
            this.logger.warn(`Skipping trend for "${keyword}": ${error.message}`);
          }
        }

        return {
          lastUpdated: new Date().toISOString(),
          monitoredKeywords,
          risingQueries: [], // Could be populated from related queries
          correlationAlerts: [], // Would need Search Console data to correlate
        };
      },
      environment.cache.trendsTtl
    );
  }

  async getInterestByRegion(
    keyword: string,
    geo = 'CA',
    resolution = 'REGION'
  ): Promise<InterestByRegionResponse | null> {
    const cacheKey = `trends:region:${keyword}:${geo}:${resolution}`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        try {
          this.logger.log(`Fetching interest by region for "${keyword}" in ${geo}`);

          const result = await googleTrends.interestByRegion({
            keyword,
            geo,
            resolution,
          });

          const parsed = JSON.parse(result);
          const geoMapData = parsed.default?.geoMapData || [];

          const regions: RegionInterest[] = geoMapData.map(
            (item: { geoCode: string; geoName: string; value: number[]; hasData: boolean[] }) => ({
              geoCode: item.geoCode,
              geoName: item.geoName,
              value: item.value[0] || 0,
              hasData: item.hasData[0] || false,
            })
          );

          this.logger.log(`Received ${regions.length} regions for "${keyword}"`);

          return {
            keyword,
            geo,
            resolution,
            regions,
          };
        } catch (error) {
          this.logger.error(`Failed to fetch interest by region for "${keyword}": ${error.message}`);
          return null;
        }
      },
      environment.cache.trendsTtl
    );
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
