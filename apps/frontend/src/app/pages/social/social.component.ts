import { Component, OnInit, inject, signal, computed, DestroyRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgbTooltipModule, NgbModalModule, NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { firstValueFrom } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService } from '../../services/api.service';
import {
  RedditPost,
  RedditStatsResponse,
  SubredditStats,
  SentimentSummary,
  MONITORED_SUBREDDITS,
} from '@cra-scam-detection/shared-types';

@Component({
  selector: 'app-social',
  standalone: true,
  imports: [CommonModule, FormsModule, NgbTooltipModule, NgbModalModule],
  templateUrl: './social.component.html',
  styleUrl: './social.component.scss',
})
export class SocialComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly modalService = inject(NgbModal);

  // Loading states
  loading = signal(true);
  fetching = signal(false);
  error = signal<string | null>(null);

  // Data
  posts = signal<RedditPost[]>([]);
  stats = signal<RedditStatsResponse | null>(null);
  serviceReady = signal(false);
  lastFetched = signal<string | null>(null);

  // Filters
  selectedDays = signal(7);
  selectedSubreddit = signal<string | null>(null);

  // Selected post for modal
  selectedPost = signal<RedditPost | null>(null);

  // Computed values
  subredditStats = computed(() => this.stats()?.subredditStats || []);
  sentimentSummary = computed(() => this.stats()?.sentimentSummary);

  filteredPosts = computed(() => {
    const allPosts = this.posts();
    const subreddit = this.selectedSubreddit();
    if (!subreddit) return allPosts;
    return allPosts.filter(p => p.subreddit === subreddit);
  });

  // Stats for display
  totalPosts = computed(() => this.posts().length);
  negativePct = computed(() => {
    const summary = this.sentimentSummary();
    return summary ? summary.negative_pct : 0;
  });
  subredditCount = computed(() => MONITORED_SUBREDDITS.length);

  // Top issue (most negative posts)
  topIssue = computed(() => {
    const stats = this.subredditStats();
    if (stats.length === 0) return null;
    // Find subreddit with highest negative sentiment
    return stats.reduce((max, s) =>
      s.sentiment_breakdown.negative > (max?.sentiment_breakdown.negative || 0) ? s : max,
      stats[0]
    );
  });

  // Monitored subreddits for filter dropdown
  readonly monitoredSubreddits = MONITORED_SUBREDDITS;

  ngOnInit(): void {
    this.checkServiceStatus();
    this.loadData();
  }

  async checkServiceStatus(): Promise<void> {
    try {
      const response = await firstValueFrom(this.api.getRedditStatus());
      if (response?.success) {
        this.serviceReady.set(response.data.redditReady);
      }
    } catch (err) {
      console.error('Failed to check Reddit status:', err);
    }
  }

  async loadData(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);

    try {
      // Load posts and stats in parallel
      const [postsResponse, statsResponse] = await Promise.all([
        firstValueFrom(this.api.getRedditPosts({ days: this.selectedDays(), source: 'db' })),
        firstValueFrom(this.api.getRedditStats(this.selectedDays())),
      ]);

      if (postsResponse?.success && postsResponse.data) {
        this.posts.set(postsResponse.data.posts);
        this.lastFetched.set(postsResponse.data.fetchedAt);
      } else {
        this.error.set(postsResponse?.error || 'Failed to load Reddit posts');
      }

      if (statsResponse?.success && statsResponse.data) {
        this.stats.set(statsResponse.data);
      }
    } catch (err) {
      this.error.set('Failed to connect to Reddit API. Check your credentials.');
      console.error('Reddit load error:', err);
    } finally {
      this.loading.set(false);
    }
  }

  async fetchFreshData(): Promise<void> {
    if (!this.serviceReady()) {
      this.error.set('Reddit service not configured. Check your credentials.');
      return;
    }

    this.fetching.set(true);
    this.error.set(null);

    try {
      const response = await firstValueFrom(this.api.fetchRedditData(10));
      if (response?.success) {
        // Reload data after fetch
        await this.loadData();
      } else {
        this.error.set(response?.error || 'Failed to fetch Reddit data');
      }
    } catch (err) {
      this.error.set('Failed to fetch from Reddit. Please try again.');
      console.error('Reddit fetch error:', err);
    } finally {
      this.fetching.set(false);
    }
  }

  onDaysChange(days: number): void {
    this.selectedDays.set(days);
    this.loadData();
  }

  onSubredditFilter(subreddit: string | null): void {
    this.selectedSubreddit.set(subreddit);
  }

  openPostModal(post: RedditPost, content: unknown): void {
    this.selectedPost.set(post);
    this.modalService.open(content, { size: 'lg', centered: true });
  }

  getSentimentBadgeClass(sentiment?: string): string {
    switch (sentiment) {
      case 'positive':
        return 'bg-success';
      case 'negative':
        return 'bg-danger';
      case 'neutral':
      default:
        return 'bg-secondary';
    }
  }

  getSentimentIcon(sentiment?: string): string {
    switch (sentiment) {
      case 'positive':
        return 'bi-emoji-smile';
      case 'negative':
        return 'bi-emoji-frown';
      case 'neutral':
      default:
        return 'bi-emoji-neutral';
    }
  }

  formatDate(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-CA', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  getRelativeTime(dateString: string): string {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) {
      return `${diffDays}d ago`;
    } else if (diffHours > 0) {
      return `${diffHours}h ago`;
    } else {
      const diffMins = Math.floor(diffMs / (1000 * 60));
      return `${diffMins}m ago`;
    }
  }
}
