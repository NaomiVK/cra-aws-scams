import { Injectable, Logger, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { SearchConsoleService } from './search-console.service';
import { ScamDetectionService } from './scam-detection.service';
import { ComparisonService } from './comparison.service';
import { EmergingThreatService } from './emerging-threat.service';
import { environment } from '../environments/environment';

/**
 * Pre-fetches common data at startup and refreshes on a schedule.
 * GSC data is 2 days behind and updates once daily, so a 4-hour
 * cache + periodic refresh keeps the UI snappy without stale data.
 */
@Injectable()
export class CacheWarmingService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(CacheWarmingService.name);
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly scamDetectionService: ScamDetectionService,
    private readonly comparisonService: ComparisonService,
    private readonly emergingThreatService: EmergingThreatService,
  ) {}

  /**
   * Runs after all modules are initialized and all onModuleInit hooks have completed.
   * This guarantees TermService, EmbeddingService, etc. are ready.
   */
  async onApplicationBootstrap(): Promise<void> {
    // Small delay to let the HTTP server start before warming
    setTimeout(() => this.warmCache(), 2000);

    // Schedule periodic refresh matching the analytics TTL
    const refreshInterval = environment.cache.analyticsTtl * 1000;
    this.refreshTimer = setInterval(() => this.warmCache(), refreshInterval);
    this.logger.log(`Scheduled cache refresh every ${environment.cache.analyticsTtl / 3600} hours`);
  }

  onModuleDestroy(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  private async warmCache(): Promise<void> {
    const start = Date.now();
    this.logger.log('Warming cache...');

    const results = { success: 0, failed: 0 };

    // Dashboard: scam detection for 7 days (default view)
    await this.warm('Dashboard (7d)', results, () => {
      const dateRange = SearchConsoleService.getDateRange(7);
      return this.scamDetectionService.detectScams(dateRange);
    });

    // Comparison: week-over-week (default view)
    await this.warm('Week-over-week comparison', results, () =>
      this.comparisonService.compareWeekOverWeek(),
    );

    // Comparison: month-over-month
    await this.warm('Month-over-month comparison', results, () =>
      this.comparisonService.compareMonthOverMonth(),
    );

    // Admin: emerging threats 7 days (default view)
    await this.warm('Emerging threats (7d)', results, () =>
      this.emergingThreatService.getEmergingThreats(7, 1),
    );

    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    this.logger.log(
      `Cache warming complete: ${results.success} succeeded, ${results.failed} failed (${elapsed}s)`,
    );
  }

  private async warm(
    label: string,
    results: { success: number; failed: number },
    fn: () => Promise<unknown>,
  ): Promise<void> {
    try {
      await fn();
      results.success++;
      this.logger.log(`  ✓ ${label}`);
    } catch (error) {
      results.failed++;
      this.logger.warn(`  ✗ ${label}: ${error.message}`);
    }
  }
}
