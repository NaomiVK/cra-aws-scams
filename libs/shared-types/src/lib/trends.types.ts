/**
 * Google Trends Types
 */

/**
 * Interest over time data point
 */
export type TrendDataPoint = {
  date: string; // YYYY-MM-DD
  value: number; // 0-100 relative interest
};

/**
 * Interest over time response
 */
export type InterestOverTime = {
  keyword: string;
  data: TrendDataPoint[];
  averageInterest: number;
};

/**
 * Related query from Google Trends
 */
export type RelatedQuery = {
  query: string;
  value: number; // Relative interest or "Breakout"
  isBreakout: boolean;
};

/**
 * Trends exploration result for a keyword
 */
export type TrendExploration = {
  keyword: string;
  geo: string;
  timeRange: string;
  interestOverTime: TrendDataPoint[];
  relatedQueries: {
    rising: RelatedQuery[];
    top: RelatedQuery[];
  };
  relatedTopics?: {
    rising: RelatedQuery[];
    top: RelatedQuery[];
  };
};

/**
 * Correlation between Trends and Search Console data
 */
export type TrendCorrelation = {
  keyword: string;
  trends: {
    direction: 'rising' | 'stable' | 'falling';
    changePercent: number;
    currentInterest: number;
  };
  searchConsole: {
    impressions: number;
    changePercent: number;
  };
  confidence: 'high' | 'medium' | 'low';
  alert: boolean;
  alertReason?: string;
};

/**
 * Trends panel data for dashboard
 */
export type TrendsPanelData = {
  lastUpdated: string;
  monitoredKeywords: {
    keyword: string;
    currentInterest: number;
    trend: 'up' | 'down' | 'stable';
    changePercent: number;
  }[];
  risingQueries: RelatedQuery[];
  correlationAlerts: TrendCorrelation[];
};

/**
 * Interest by region data point
 */
export type RegionInterest = {
  geoCode: string;
  geoName: string;
  value: number;
  hasData: boolean;
};

/**
 * Interest by region response
 */
export type InterestByRegionResponse = {
  keyword: string;
  geo: string;
  resolution: string;
  regions: RegionInterest[];
};

/**
 * Trends API result
 */
export type TrendsResult = {
  keywords: string[];
  interestOverTime: Array<{
    date: string;
    values: Record<string, number>;
  }>;
  relatedQueries: Array<{
    keyword: string;
    queries: Array<{
      query: string;
      value: number;
    }>;
  }>;
  interestByRegion: Array<{
    geoName: string;
    values: Record<string, number>;
  }>;
};
