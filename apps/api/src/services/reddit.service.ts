import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import Snoowrap from 'snoowrap';
import { CacheService } from './cache.service';
import { AwsConfigService } from './aws-config.service';
import { SentimentService } from './sentiment.service';
import { DynamoDbService } from './dynamodb.service';
import {
  RedditPost,
  SubredditStats,
  SentimentSummary,
  MONITORED_SUBREDDITS,
  SentimentLabel,
} from '@cra-scam-detection/shared-types';

/**
 * Default search terms if DynamoDB is empty
 */
const DEFAULT_SEARCH_TERMS = [
  'CRA',
  'Canada Revenue Agency',
  'tax refund',
  'cra scam',
  'cra rebate',
  'cra one time payment',
  'grocery rebate',
  'inflation relief',
  'cra rent relief',
  'TFSA',
  'RRSP',
];

/**
 * Reddit Service
 * Fetches and analyzes posts from CRA-related subreddits
 */
@Injectable()
export class RedditService implements OnModuleInit {
  private readonly logger = new Logger(RedditService.name);
  private reddit: Snoowrap | null = null;
  private initialized = false;
  private searchTerms: string[] = [];
  private readonly cacheTtl = 3600; // 1 hour

  constructor(
    private readonly cacheService: CacheService,
    private readonly awsConfigService: AwsConfigService,
    private readonly sentimentService: SentimentService,
    private readonly dynamoDbService: DynamoDbService,
  ) {}

  async onModuleInit() {
    await this.awsConfigService.ready;

    const clientId = this.awsConfigService.getRedditClientId();
    const clientSecret = this.awsConfigService.getRedditClientSecret();
    const username = this.awsConfigService.getRedditUsername();
    const password = this.awsConfigService.getRedditPassword();

    if (!clientId || !clientSecret) {
      this.logger.warn('Reddit credentials not configured - Reddit service disabled');
      return;
    }

    try {
      this.reddit = new Snoowrap({
        userAgent: 'CRA-Scam-Detection/1.0 (by /u/' + (username || 'unknown') + ')',
        clientId,
        clientSecret,
        username,
        password,
      });

      // Configure rate limiting
      this.reddit.config({
        requestDelay: 1000, // 1 second between requests
        continueAfterRatelimitError: true,
        retryErrorCodes: [502, 503, 504, 522],
        maxRetryAttempts: 3,
      });

      // Load search terms from DynamoDB seed phrases
      await this.loadSearchTerms();

      this.initialized = true;
      this.logger.log('Reddit service initialized successfully');
    } catch (error) {
      this.logger.error(`Failed to initialize Reddit client: ${error.message}`);
    }
  }

  /**
   * Load search terms from DynamoDB seed phrases + defaults
   */
  private async loadSearchTerms(): Promise<void> {
    try {
      const seedPhrases = await this.dynamoDbService.getAllSeedPhrases();
      const dynamoTerms = seedPhrases.map(p => p.term);

      // Combine defaults + DynamoDB terms, deduplicate
      const allTerms = [...DEFAULT_SEARCH_TERMS, ...dynamoTerms];
      this.searchTerms = [...new Set(allTerms.map(t => t.toLowerCase()))];

      this.logger.log(
        `Loaded ${this.searchTerms.length} search terms (${DEFAULT_SEARCH_TERMS.length} defaults + ${dynamoTerms.length} from DynamoDB)`,
      );
    } catch (error) {
      this.logger.warn(`Failed to load search terms from DynamoDB, using defaults: ${error.message}`);
      this.searchTerms = DEFAULT_SEARCH_TERMS;
    }
  }

  /**
   * Get current search terms
   */
  getSearchTerms(): string[] {
    return this.searchTerms;
  }

  /**
   * Check if service is ready
   */
  isReady(): boolean {
    return this.initialized;
  }

  /**
   * Get recent posts from a subreddit
   */
  async getSubredditPosts(
    subreddit: string,
    limit: number = 25,
    timeFilter: 'hour' | 'day' | 'week' | 'month' | 'year' | 'all' = 'week',
  ): Promise<RedditPost[]> {
    if (!this.reddit || !this.initialized) {
      this.logger.warn('Reddit service not initialized');
      return [];
    }

    const cacheKey = `reddit:${subreddit}:${limit}:${timeFilter}`;
    const cached = this.cacheService.get<RedditPost[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for r/${subreddit}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching posts from r/${subreddit}...`);

      const submissions = await this.reddit.getSubreddit(subreddit).getNew({ limit });

      const posts: RedditPost[] = submissions.map((post: Snoowrap.Submission) =>
        this.mapSubmissionToPost(post),
      );

      // Cache results
      this.cacheService.set(cacheKey, posts, this.cacheTtl);

      this.logger.log(`Fetched ${posts.length} posts from r/${subreddit}`);
      return posts;
    } catch (error) {
      this.logger.error(`Failed to fetch posts from r/${subreddit}: ${error.message}`);
      return [];
    }
  }

  /**
   * Get posts from all monitored subreddits using keyword search
   */
  async getAllMonitoredPosts(
    limit: number = 10,
    withSentiment: boolean = true,
  ): Promise<RedditPost[]> {
    if (!this.reddit || !this.initialized) {
      this.logger.warn('Reddit service not initialized');
      return [];
    }

    const cacheKey = `reddit:all:${limit}`;
    const cached = this.cacheService.get<RedditPost[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for all monitored posts');
      return cached;
    }

    const seenIds = new Set<string>();
    const allPosts: RedditPost[] = [];

    // Build all search tasks
    const searchTasks: Array<{ subreddit: string; term: string }> = [];
    for (const subreddit of MONITORED_SUBREDDITS) {
      for (const term of this.searchTerms) {
        searchTasks.push({ subreddit, term });
      }
    }

    this.logger.log(`Running ${searchTasks.length} searches in parallel...`);

    // Run searches in parallel (batches of 5 to respect rate limits)
    const batchSize = 5;
    for (let i = 0; i < searchTasks.length; i += batchSize) {
      const batch = searchTasks.slice(i, i + batchSize);

      const batchResults = await Promise.allSettled(
        batch.map(async ({ subreddit, term }) => {
          const submissions = await this.reddit!.getSubreddit(subreddit).search({
            query: term,
            sort: 'new',
            time: 'week',
            limit,
          } as Snoowrap.SearchOptions);

          return submissions.map((post: Snoowrap.Submission) => ({
            subreddit,
            term,
            post: this.mapSubmissionToPost(post),
          }));
        }),
      );

      // Collect results
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          for (const { post } of result.value) {
            if (!seenIds.has(post.id)) {
              seenIds.add(post.id);
              allPosts.push(post);
            }
          }
        }
      }

      // Small delay between batches
      if (i + batchSize < searchTasks.length) {
        await this.delay(300);
      }
    }

    this.logger.log(`Found ${allPosts.length} unique posts across all subreddits`);

    // Sort by created_utc descending (newest first)
    allPosts.sort(
      (a, b) => new Date(b.created_utc).getTime() - new Date(a.created_utc).getTime(),
    );

    // Analyze sentiment if requested
    if (withSentiment && this.sentimentService.isReady()) {
      await this.enrichWithSentiment(allPosts);
    }

    // Cache results
    this.cacheService.set(cacheKey, allPosts, this.cacheTtl);

    return allPosts;
  }

  /**
   * Helper to add delay for rate limiting
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Search for posts across subreddits
   */
  async searchPosts(
    keywords: string[],
    subreddits: string[] = [...MONITORED_SUBREDDITS],
    limit: number = 50,
  ): Promise<RedditPost[]> {
    if (!this.reddit || !this.initialized) {
      this.logger.warn('Reddit service not initialized');
      return [];
    }

    const query = keywords.join(' OR ');
    const subredditStr = subreddits.join('+');
    const cacheKey = `reddit:search:${subredditStr}:${query}:${limit}`;

    const cached = this.cacheService.get<RedditPost[]>(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      this.logger.log(`Searching for "${query}" in r/${subredditStr}...`);

      const submissions = await this.reddit.search({
        query,
        subreddit: subredditStr,
        sort: 'new',
        time: 'week',
        limit,
      });

      const posts: RedditPost[] = submissions.map((post: Snoowrap.Submission) =>
        this.mapSubmissionToPost(post),
      );

      this.cacheService.set(cacheKey, posts, this.cacheTtl);

      this.logger.log(`Found ${posts.length} posts matching "${query}"`);
      return posts;
    } catch (error) {
      this.logger.error(`Search failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Fetch fresh data from Reddit and save to DynamoDB
   */
  async fetchAndSaveData(
    limit: number = 25,
  ): Promise<{ posts: RedditPost[]; saved: number }> {
    const posts = await this.getAllMonitoredPosts(limit, true);

    let saved = 0;
    for (const post of posts) {
      const success = await this.dynamoDbService.saveRedditPost(post);
      if (success) saved++;
    }

    this.logger.log(`Saved ${saved}/${posts.length} posts to DynamoDB`);

    // Clear cache to force fresh data on next request
    this.cacheService.delByPattern('reddit:');

    return { posts, saved };
  }

  /**
   * Get subreddit statistics
   */
  async getSubredditStats(posts: RedditPost[]): Promise<SubredditStats[]> {
    const statsMap = new Map<
      string,
      {
        posts: number;
        comments: number;
        totalScore: number;
        sentiments: SentimentLabel[];
      }
    >();

    // Aggregate stats by subreddit
    for (const post of posts) {
      const existing = statsMap.get(post.subreddit) || {
        posts: 0,
        comments: 0,
        totalScore: 0,
        sentiments: [],
      };

      existing.posts++;
      existing.comments += post.num_comments;
      existing.totalScore += post.score;
      if (post.sentiment) {
        existing.sentiments.push(post.sentiment);
      }

      statsMap.set(post.subreddit, existing);
    }

    // Convert to stats array
    const stats: SubredditStats[] = [];
    for (const [subreddit, data] of statsMap.entries()) {
      const sentimentCounts = { positive: 0, negative: 0, neutral: 0 };
      for (const s of data.sentiments) {
        sentimentCounts[s]++;
      }

      // Determine average sentiment
      let avgSentiment: SentimentLabel = 'neutral';
      if (sentimentCounts.positive > sentimentCounts.negative) {
        avgSentiment = 'positive';
      } else if (sentimentCounts.negative > sentimentCounts.positive) {
        avgSentiment = 'negative';
      }

      stats.push({
        subreddit,
        total_posts: data.posts,
        total_comments: data.comments,
        avg_score: data.posts > 0 ? Math.round(data.totalScore / data.posts) : 0,
        sentiment_breakdown: sentimentCounts,
        avg_sentiment: avgSentiment,
        engagement_rate: data.posts > 0 ? Math.round((data.comments / data.posts) * 10) / 10 : 0,
      });
    }

    return stats.sort((a, b) => b.total_posts - a.total_posts);
  }

  /**
   * Get overall sentiment summary
   */
  getSentimentSummary(posts: RedditPost[]): SentimentSummary {
    const counts = { positive: 0, negative: 0, neutral: 0 };
    let totalConfidence = 0;
    let analyzedCount = 0;

    for (const post of posts) {
      if (post.sentiment) {
        counts[post.sentiment]++;
        totalConfidence += post.sentiment_confidence || 0;
        analyzedCount++;
      }
    }

    const total = analyzedCount || 1;

    return {
      total_analyzed: analyzedCount,
      positive_count: counts.positive,
      negative_count: counts.negative,
      neutral_count: counts.neutral,
      positive_pct: Math.round((counts.positive / total) * 100),
      negative_pct: Math.round((counts.negative / total) * 100),
      neutral_pct: Math.round((counts.neutral / total) * 100),
      avg_confidence: analyzedCount > 0 ? totalConfidence / analyzedCount : 0,
    };
  }

  /**
   * Enrich posts with sentiment analysis
   */
  private async enrichWithSentiment(posts: RedditPost[]): Promise<void> {
    const items = posts.map(post => ({
      id: post.id,
      text: `${post.title}\n\n${post.content || ''}`.trim(),
    }));

    const sentimentResults = await this.sentimentService.batchAnalyzeSentiment(items);

    for (const post of posts) {
      const result = sentimentResults.get(post.id);
      if (result) {
        post.sentiment = result.label;
        post.sentiment_confidence = result.confidence;
        post.analyzed_at = new Date().toISOString();
      }
    }
  }

  /**
   * Map snoowrap Submission to RedditPost
   */
  private mapSubmissionToPost(submission: Snoowrap.Submission): RedditPost {
    return {
      id: submission.id,
      reddit_id: submission.id,
      title: submission.title,
      content: submission.selftext || null,
      author: submission.author?.name || '[deleted]',
      subreddit: submission.subreddit?.display_name || 'unknown',
      score: submission.score,
      upvote_ratio: submission.upvote_ratio,
      num_comments: submission.num_comments,
      created_utc: new Date(submission.created_utc * 1000).toISOString(),
      url: `https://reddit.com${submission.permalink}`,
      permalink: submission.permalink,
      is_self: submission.is_self,
      flair_text: submission.link_flair_text || null,
    };
  }
}
