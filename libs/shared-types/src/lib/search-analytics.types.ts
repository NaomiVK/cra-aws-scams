/**
 * Google Search Console Analytics Types
 */

export type SearchAnalyticsQuery = {
  startDate: string; // YYYY-MM-DD
  endDate: string; // YYYY-MM-DD
  dimensions?: SearchDimension[];
  rowLimit?: number;
  startRow?: number;
};

export type SearchDimension = 'query' | 'page' | 'country' | 'device' | 'date';

export type SearchAnalyticsRow = {
  keys: string[]; // Values for each dimension
  clicks: number;
  impressions: number;
  ctr: number;
  position: number;
};

export type SearchAnalyticsResponse = {
  rows: SearchAnalyticsRow[];
  responseAggregationType?: string;
};

/**
 * Processed search term with metadata
 */
export type SearchTerm = {
  query: string;
  impressions: number;
  clicks: number;
  ctr: number;
  position: number;
  pages?: string[]; // Associated CRA pages
};

/**
 * Date range for comparisons
 */
export type DateRange = {
  startDate: string;
  endDate: string;
};

/**
 * Period comparison request
 */
export type ComparisonRequest = {
  currentPeriod: DateRange;
  previousPeriod: DateRange;
};

/**
 * Comparison metrics for a single term
 */
export type TermComparison = {
  query: string;
  current: {
    impressions: number;
    clicks: number;
    ctr: number;
    position: number;
  };
  previous: {
    impressions: number;
    clicks: number;
    ctr: number;
    position: number;
  };
  change: {
    impressions: number;
    impressionsPercent: number;
    clicks: number;
    clicksPercent: number;
    ctr: number;
    position: number;
  };
  isNew: boolean; // New term not in previous period
  isGone: boolean; // Term disappeared from current period
};

/**
 * Full comparison response
 */
export type ComparisonResponse = {
  currentPeriod: DateRange;
  previousPeriod: DateRange;
  summary: {
    totalTerms: number;
    newTerms: number;
    goneTerms: number;
    totalImpressions: {
      current: number;
      previous: number;
      change: number;
      changePercent: number;
    };
  };
  terms: TermComparison[];
};
