import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  DashboardData,
  ScamDetectionResult,
  ComparisonResponse,
  TrendsResult,
  FlaggedTerm,
  DateRange,
  ExportData,
  EmergingThreatsResponse,
  ScamKeywordsConfig,
  InterestByRegionResponse,
  ExcludedTermsResponse,
  RedditPostsResponse,
  RedditStatsResponse,
  RedditPost,
} from '@cra-scam-detection/shared-types';
import { environment } from '../../environments/environment';

export type ApiResponse<T> = {
  success: boolean;
  data: T;
  error?: string;
};

@Injectable({
  providedIn: 'root',
})
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = environment.apiUrl;

  /**
   * Fetch dashboard data
   */
  getDashboard(dateRange?: DateRange): Observable<ApiResponse<DashboardData>> {
    let params = new HttpParams();
    if (dateRange) {
      params = params
        .set('startDate', dateRange.startDate)
        .set('endDate', dateRange.endDate);
    }
    return this.http.get<ApiResponse<DashboardData>>(
      `${this.baseUrl}/scams/dashboard`,
      { params }
    );
  }

  /**
   * Detect scams
   */
  detectScams(dateRange?: DateRange): Observable<ApiResponse<ScamDetectionResult>> {
    let params = new HttpParams();
    if (dateRange) {
      params = params
        .set('startDate', dateRange.startDate)
        .set('endDate', dateRange.endDate);
    }
    return this.http.get<ApiResponse<ScamDetectionResult>>(
      `${this.baseUrl}/scams/detect`,
      { params }
    );
  }

  /**
   * Get flagged terms with filtering
   */
  getFlaggedTerms(options?: {
    severity?: string;
    status?: string;
    startDate?: string;
    endDate?: string;
  }): Observable<ApiResponse<FlaggedTerm[]>> {
    let params = new HttpParams();
    if (options?.severity) params = params.set('severity', options.severity);
    if (options?.status) params = params.set('status', options.status);
    if (options?.startDate) params = params.set('startDate', options.startDate);
    if (options?.endDate) params = params.set('endDate', options.endDate);

    return this.http.get<ApiResponse<FlaggedTerm[]>>(
      `${this.baseUrl}/scams/flagged`,
      { params }
    );
  }

  /**
   * Get comparison data between two periods
   * Backend expects: currentStart, currentEnd, previousStart, previousEnd
   */
  getComparison(
    currentPeriod: DateRange,
    previousPeriod: DateRange
  ): Observable<ApiResponse<ComparisonResponse>> {
    const params = new HttpParams()
      .set('currentStart', currentPeriod.startDate)
      .set('currentEnd', currentPeriod.endDate)
      .set('previousStart', previousPeriod.startDate)
      .set('previousEnd', previousPeriod.endDate);

    return this.http.get<ApiResponse<ComparisonResponse>>(
      `${this.baseUrl}/comparison/period`,
      { params }
    );
  }

  /**
   * Get week-over-week comparison
   */
  getWeekOverWeek(): Observable<ApiResponse<ComparisonResponse>> {
    return this.http.get<ApiResponse<ComparisonResponse>>(
      `${this.baseUrl}/comparison/week-over-week`
    );
  }

  /**
   * Get trends data
   */
  getTrends(keywords: string[], timeRange?: string): Observable<ApiResponse<TrendsResult>> {
    let params = new HttpParams().set('keywords', keywords.join(','));
    if (timeRange) {
      params = params.set('timeRange', timeRange);
    }
    return this.http.get<ApiResponse<TrendsResult>>(
      `${this.baseUrl}/trends/explore`,
      { params }
    );
  }

  /**
   * Get seed phrases from DynamoDB for dropdown
   */
  getSeedPhrases(): Observable<ApiResponse<{ term: string; category: string }[]>> {
    return this.http.get<ApiResponse<{ term: string; category: string }[]>>(
      `${this.baseUrl}/scams/seed-phrases`
    );
  }

  /**
   * Export data as JSON
   */
  exportJson(dateRange?: DateRange): Observable<ApiResponse<ExportData>> {
    let params = new HttpParams();
    if (dateRange) {
      params = params
        .set('startDate', dateRange.startDate)
        .set('endDate', dateRange.endDate);
    }
    return this.http.get<ApiResponse<ExportData>>(
      `${this.baseUrl}/export/json`,
      { params }
    );
  }

  /**
   * Download CSV export
   */
  downloadCsv(dateRange?: DateRange): void {
    let url = `${this.baseUrl}/export/csv`;
    if (dateRange) {
      url += `?startDate=${encodeURIComponent(dateRange.startDate)}&endDate=${encodeURIComponent(dateRange.endDate)}`;
    }
    window.open(url, '_blank');
  }

  downloadExcel(dateRange?: DateRange): void {
    let url = `${this.baseUrl}/export/excel`;
    if (dateRange) {
      url += `?startDate=${encodeURIComponent(dateRange.startDate)}&endDate=${encodeURIComponent(dateRange.endDate)}`;
    }
    window.open(url, '_blank');
  }

  getEmergingThreats(days = 7, page = 1): Observable<ApiResponse<EmergingThreatsResponse>> {
    const params = new HttpParams()
      .set('days', days.toString())
      .set('page', page.toString());
    return this.http.get<ApiResponse<EmergingThreatsResponse>>(
      `${this.baseUrl}/scams/emerging`,
      { params }
    );
  }

  getKeywordsConfig(): Observable<ApiResponse<ScamKeywordsConfig>> {
    return this.http.get<ApiResponse<ScamKeywordsConfig>>(
      `${this.baseUrl}/scams/keywords`
    );
  }

  addKeyword(term: string, category: string): Observable<ApiResponse<{ message: string }>> {
    return this.http.post<ApiResponse<{ message: string }>>(
      `${this.baseUrl}/scams/keywords`,
      { term, category }
    );
  }

  dismissThreat(id: string): Observable<ApiResponse<{ message: string }>> {
    return this.http.post<ApiResponse<{ message: string }>>(
      `${this.baseUrl}/scams/emerging/${id}/dismiss`,
      {}
    );
  }

  getInterestByRegion(keyword: string, geo = 'CA'): Observable<ApiResponse<InterestByRegionResponse>> {
    const params = new HttpParams().set('keyword', keyword).set('geo', geo);
    return this.http.get<ApiResponse<InterestByRegionResponse>>(
      `${this.baseUrl}/trends/region`,
      { params }
    );
  }

  /**
   * Get Google Maps API key from server
   */
  getMapsApiKey(): Observable<ApiResponse<{ apiKey: string }>> {
    return this.http.get<ApiResponse<{ apiKey: string }>>(
      `${this.baseUrl}/config/maps-key`
    );
  }

  /**
   * Get excluded/legitimate terms configuration
   */
  getExcludedTerms(): Observable<ApiResponse<ExcludedTermsResponse>> {
    return this.http.get<ApiResponse<ExcludedTermsResponse>>(
      `${this.baseUrl}/scams/excluded`
    );
  }

  /**
   * Add a term to excluded/legitimate terms
   */
  addExcludedTerm(term: string, category?: string): Observable<ApiResponse<{ message: string }>> {
    return this.http.post<ApiResponse<{ message: string }>>(
      `${this.baseUrl}/scams/excluded`,
      { term, category }
    );
  }

  // ==================== REDDIT ====================

  /**
   * Get Reddit posts with optional filters
   */
  getRedditPosts(options?: {
    days?: number;
    limit?: number;
    source?: 'live' | 'db';
  }): Observable<ApiResponse<RedditPostsResponse>> {
    let params = new HttpParams();
    if (options?.days) params = params.set('days', options.days.toString());
    if (options?.limit) params = params.set('limit', options.limit.toString());
    if (options?.source) params = params.set('source', options.source);

    return this.http.get<ApiResponse<RedditPostsResponse>>(
      `${this.baseUrl}/reddit/posts`,
      { params }
    );
  }

  /**
   * Get posts for a specific subreddit
   */
  getRedditPostsBySubreddit(
    subreddit: string,
    limit?: number
  ): Observable<ApiResponse<RedditPost[]>> {
    let params = new HttpParams();
    if (limit) params = params.set('limit', limit.toString());

    return this.http.get<ApiResponse<RedditPost[]>>(
      `${this.baseUrl}/reddit/posts/${subreddit}`,
      { params }
    );
  }

  /**
   * Fetch fresh Reddit data and save to database
   */
  fetchRedditData(limit?: number): Observable<ApiResponse<{ posts: number; saved: number }>> {
    let params = new HttpParams();
    if (limit) params = params.set('limit', limit.toString());

    return this.http.post<ApiResponse<{ posts: number; saved: number }>>(
      `${this.baseUrl}/reddit/fetch`,
      {},
      { params }
    );
  }

  /**
   * Get Reddit statistics and sentiment summary
   */
  getRedditStats(days?: number): Observable<ApiResponse<RedditStatsResponse>> {
    let params = new HttpParams();
    if (days) params = params.set('days', days.toString());

    return this.http.get<ApiResponse<RedditStatsResponse>>(
      `${this.baseUrl}/reddit/stats`,
      { params }
    );
  }

  /**
   * Search Reddit posts by keywords
   */
  searchRedditPosts(
    keywords: string[],
    limit?: number
  ): Observable<ApiResponse<RedditPost[]>> {
    let params = new HttpParams().set('keywords', keywords.join(','));
    if (limit) params = params.set('limit', limit.toString());

    return this.http.get<ApiResponse<RedditPost[]>>(
      `${this.baseUrl}/reddit/search`,
      { params }
    );
  }

  /**
   * Get Reddit service status
   */
  getRedditStatus(): Observable<ApiResponse<{ redditReady: boolean; subreddits: string[] }>> {
    return this.http.get<ApiResponse<{ redditReady: boolean; subreddits: string[] }>>(
      `${this.baseUrl}/reddit/status`
    );
  }
}
