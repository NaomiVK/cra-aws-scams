import {
  Controller,
  Get,
  Post,
  Query,
  Param,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { RedditService } from '../services/reddit.service';
import { DynamoDbService } from '../services/dynamodb.service';
import {
  RedditPost,
  RedditPostsResponse,
  RedditStatsResponse,
  MONITORED_SUBREDDITS,
} from '@cra-scam-detection/shared-types';

/**
 * Parse and validate a numeric query parameter
 */
function parseIntParam(
  value: string | undefined,
  defaultValue: number,
  paramName: string,
): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed < 1) {
    throw new HttpException(
      `Invalid ${paramName}: must be a positive integer`,
      HttpStatus.BAD_REQUEST,
    );
  }
  return parsed;
}

@Controller('reddit')
export class RedditController {
  private readonly logger = new Logger(RedditController.name);

  constructor(
    private readonly redditService: RedditService,
    private readonly dynamoDbService: DynamoDbService,
  ) {}

  /**
   * GET /api/reddit/posts
   * Get recent Reddit posts with sentiment analysis
   */
  @Get('posts')
  async getPosts(
    @Query('days') days?: string,
    @Query('limit') limit?: string,
    @Query('source') source?: 'live' | 'db',
  ): Promise<{ success: boolean; data: RedditPostsResponse }> {
    try {
      const daysNum = parseIntParam(days, 7, 'days');
      const limitNum = parseIntParam(limit, 25, 'limit');
      const useDb = source === 'db';

      let posts: RedditPost[];

      if (useDb) {
        // Fetch from DynamoDB
        posts = await this.dynamoDbService.getRecentRedditPosts(daysNum);
        this.logger.log(`Fetched ${posts.length} posts from DynamoDB`);
      } else {
        // Fetch live from Reddit
        posts = await this.redditService.getAllMonitoredPosts(limitNum, true);
        this.logger.log(`Fetched ${posts.length} posts from Reddit API`);
      }

      return {
        success: true,
        data: {
          posts,
          subreddits: [...MONITORED_SUBREDDITS],
          fetchedAt: new Date().toISOString(),
          totalPosts: posts.length,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get Reddit posts: ${error.message}`);
      throw new HttpException(
        'Failed to get Reddit posts',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * GET /api/reddit/posts/:subreddit
   * Get posts for a specific subreddit
   */
  @Get('posts/:subreddit')
  async getPostsBySubreddit(
    @Param('subreddit') subreddit: string,
    @Query('limit') limit?: string,
  ): Promise<{ success: boolean; data: RedditPost[] }> {
    try {
      const limitNum = parseIntParam(limit, 25, 'limit');

      const posts = await this.redditService.getSubredditPosts(subreddit, limitNum);

      return {
        success: true,
        data: posts,
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get posts from r/${subreddit}: ${error.message}`);
      throw new HttpException(
        `Failed to get posts from r/${subreddit}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * POST /api/reddit/fetch
   * Fetch fresh data from Reddit and save to DynamoDB
   */
  @Post('fetch')
  async fetchData(
    @Query('limit') limit?: string,
  ): Promise<{ success: boolean; data: { posts: number; saved: number } }> {
    try {
      if (!this.redditService.isReady()) {
        throw new HttpException(
          'Reddit service not configured',
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }

      const limitNum = parseIntParam(limit, 25, 'limit');

      this.logger.log('Fetching fresh data from Reddit...');
      const result = await this.redditService.fetchAndSaveData(limitNum);

      return {
        success: true,
        data: {
          posts: result.posts.length,
          saved: result.saved,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to fetch Reddit data: ${error.message}`);
      throw new HttpException(
        'Failed to fetch Reddit data',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * GET /api/reddit/stats
   * Get subreddit statistics and sentiment summary
   */
  @Get('stats')
  async getStats(
    @Query('days') days?: string,
  ): Promise<{ success: boolean; data: RedditStatsResponse }> {
    try {
      const daysNum = parseIntParam(days, 7, 'days');

      // Try to get posts from DynamoDB first, fall back to live
      let posts = await this.dynamoDbService.getRecentRedditPosts(daysNum);

      if (posts.length === 0 && this.redditService.isReady()) {
        posts = await this.redditService.getAllMonitoredPosts(10, true);
      }

      const subredditStats = await this.redditService.getSubredditStats(posts);
      const sentimentSummary = this.redditService.getSentimentSummary(posts);

      return {
        success: true,
        data: {
          subredditStats,
          sentimentSummary,
          totalPosts: posts.length,
          lastUpdated: new Date().toISOString(),
        },
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to get Reddit stats: ${error.message}`);
      throw new HttpException(
        'Failed to get Reddit stats',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * GET /api/reddit/search
   * Search for posts matching keywords
   */
  @Get('search')
  async searchPosts(
    @Query('keywords') keywords: string,
    @Query('limit') limit?: string,
  ): Promise<{ success: boolean; data: RedditPost[] }> {
    try {
      if (!keywords) {
        throw new HttpException('Keywords parameter is required', HttpStatus.BAD_REQUEST);
      }

      if (!this.redditService.isReady()) {
        throw new HttpException(
          'Reddit service not configured',
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }

      const limitNum = parseIntParam(limit, 50, 'limit');
      const keywordList = keywords.split(',').map(k => k.trim());

      const posts = await this.redditService.searchPosts(keywordList, undefined, limitNum);

      return {
        success: true,
        data: posts,
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(`Failed to search Reddit: ${error.message}`);
      throw new HttpException(
        'Failed to search Reddit',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * GET /api/reddit/status
   * Get service status
   */
  @Get('status')
  getStatus(): {
    success: boolean;
    data: { redditReady: boolean; subreddits: readonly string[] };
  } {
    return {
      success: true,
      data: {
        redditReady: this.redditService.isReady(),
        subreddits: MONITORED_SUBREDDITS,
      },
    };
  }
}
