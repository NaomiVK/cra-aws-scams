/**
 * Reddit Social Listening Types
 */

export type SentimentLabel = 'positive' | 'negative' | 'neutral';

/**
 * Reddit post from the API
 */
export type RedditPost = {
  id: string;
  reddit_id: string;
  title: string;
  content: string | null;
  author: string;
  subreddit: string;
  score: number;
  upvote_ratio: number;
  num_comments: number;
  created_utc: string;
  url: string;
  permalink: string;
  is_self: boolean;
  flair_text: string | null;
  sentiment?: SentimentLabel;
  sentiment_confidence?: number;
  analyzed_at?: string;
};

/**
 * Sentiment analysis result
 */
export type SentimentResult = {
  label: SentimentLabel;
  score: number; // -1 to 1 (negative to positive)
  confidence: number; // 0 to 1
};

/**
 * Subreddit statistics
 */
export type SubredditStats = {
  subreddit: string;
  total_posts: number;
  total_comments: number;
  avg_score: number;
  sentiment_breakdown: {
    positive: number;
    negative: number;
    neutral: number;
  };
  avg_sentiment: SentimentLabel;
  engagement_rate: number; // comments per post ratio
};

/**
 * Overall sentiment summary across all subreddits
 */
export type SentimentSummary = {
  total_analyzed: number;
  positive_count: number;
  negative_count: number;
  neutral_count: number;
  positive_pct: number;
  negative_pct: number;
  neutral_pct: number;
  avg_confidence: number;
};

/**
 * Reddit fetch request parameters
 */
export type RedditFetchParams = {
  subreddits?: string[];
  keywords?: string[];
  days?: number;
  limit?: number;
};

/**
 * Reddit posts response with metadata
 */
export type RedditPostsResponse = {
  posts: RedditPost[];
  subreddits: string[];
  fetchedAt: string;
  totalPosts: number;
};

/**
 * Reddit stats response
 */
export type RedditStatsResponse = {
  subredditStats: SubredditStats[];
  sentimentSummary: SentimentSummary;
  totalPosts: number;
  lastUpdated: string;
};

/**
 * Monitored subreddits configuration
 */
export const MONITORED_SUBREDDITS = [
  'cantax',
  'canadarevenueagency',
] as const;

export type MonitoredSubreddit = (typeof MONITORED_SUBREDDITS)[number];
