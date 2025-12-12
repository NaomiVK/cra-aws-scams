import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  NgbDatepickerModule,
  NgbDropdownModule,
  NgbPaginationModule,
  NgbTooltipModule,
} from '@ng-bootstrap/ng-bootstrap';
import { ApiService } from '../../services/api.service';
import {
  DashboardData,
  DateRange,
  Severity,
  EmergingThreatsResponse,
} from '@cra-scam-detection/shared-types';

type SortField = 'query' | 'severity' | 'impressions' | 'clicks' | 'ctr' | 'position';
type SortDirection = 'asc' | 'desc';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
    NgbDatepickerModule,
    NgbDropdownModule,
    NgbPaginationModule,
    NgbTooltipModule,
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit {
  private readonly api = inject(ApiService);

  // Loading state
  loading = signal(true);
  error = signal<string | null>(null);

  // Dashboard data
  dashboardData = signal<DashboardData | null>(null);
  emergingThreats = signal<EmergingThreatsResponse | null>(null);

  // Date range
  dateRange = signal<DateRange>({
    startDate: this.getDefaultStartDate(),
    endDate: this.getDefaultEndDate(),
  });

  // Filters
  severityFilter = signal<Severity | 'all'>('all');
  statusFilter = signal<string>('all');
  searchQuery = signal('');

  // Sorting
  sortField = signal<SortField>('impressions');
  sortDirection = signal<SortDirection>('desc');

  // Pagination
  page = signal(1);
  pageSize = signal(20);

  // Computed filtered and sorted terms
  filteredTerms = computed(() => {
    const data = this.dashboardData();
    if (!data) return [];

    let terms = [...data.flaggedTerms];

    // Apply severity filter
    const severity = this.severityFilter();
    if (severity !== 'all') {
      terms = terms.filter((t) => t.severity === severity);
    }

    // Apply status filter
    const status = this.statusFilter();
    if (status !== 'all') {
      terms = terms.filter((t) => t.status === status);
    }

    // Apply search filter
    const query = this.searchQuery().toLowerCase();
    if (query) {
      terms = terms.filter(
        (t) =>
          t.query.toLowerCase().includes(query) ||
          t.matchedPatterns.some((p: string) => p.toLowerCase().includes(query))
      );
    }

    // Apply sorting
    const field = this.sortField();
    const direction = this.sortDirection();
    terms.sort((a, b) => {
      let comparison = 0;
      switch (field) {
        case 'query':
          comparison = a.query.localeCompare(b.query);
          break;
        case 'severity':
          comparison = this.severityOrder(a.severity) - this.severityOrder(b.severity);
          break;
        case 'impressions':
          comparison = a.impressions - b.impressions;
          break;
        case 'clicks':
          comparison = a.clicks - b.clicks;
          break;
        case 'ctr':
          comparison = a.ctr - b.ctr;
          break;
        case 'position':
          comparison = a.position - b.position;
          break;
      }
      return direction === 'asc' ? comparison : -comparison;
    });

    return terms;
  });

  // Computed paginated terms
  paginatedTerms = computed(() => {
    const terms = this.filteredTerms();
    const start = (this.page() - 1) * this.pageSize();
    return terms.slice(start, start + this.pageSize());
  });

  ngOnInit(): void {
    this.loadDashboard();
    this.loadEmergingThreats();
  }

  loadEmergingThreats(): void {
    this.api.getEmergingThreats(7).subscribe({
      next: (res) => {
        if (res.success) {
          this.emergingThreats.set(res.data);
        }
      },
      error: (err) => console.error('Failed to load emerging threats', err),
    });
  }

  async loadDashboard(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);

    try {
      const response = await this.api.getDashboard(this.dateRange()).toPromise();
      if (response?.success && response.data) {
        this.dashboardData.set(response.data);
      } else {
        this.error.set(response?.error || 'Failed to load dashboard data');
      }
    } catch (err) {
      this.error.set('Failed to connect to API. Please ensure the server is running.');
      console.error('Dashboard load error:', err);
    } finally {
      this.loading.set(false);
    }
  }

  onDateRangeChange(startDate: string, endDate: string): void {
    this.dateRange.set({ startDate, endDate });
    this.page.set(1);
    this.loadDashboard();
  }

  onQuickDateRange(days: number): void {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    this.dateRange.set({
      startDate: this.formatDate(startDate),
      endDate: this.formatDate(endDate),
    });
    this.page.set(1);
    this.loadDashboard();
  }

  onSort(field: SortField): void {
    if (this.sortField() === field) {
      this.sortDirection.set(this.sortDirection() === 'asc' ? 'desc' : 'asc');
    } else {
      this.sortField.set(field);
      this.sortDirection.set('desc');
    }
  }

  onSeverityFilter(severity: Severity | 'all'): void {
    this.severityFilter.set(severity);
    this.page.set(1);
  }

  onStatusFilter(status: string): void {
    this.statusFilter.set(status);
    this.page.set(1);
  }

  onSearchChange(query: string): void {
    this.searchQuery.set(query);
    this.page.set(1);
  }

  exportCsv(): void {
    this.api.downloadCsv(this.dateRange());
  }

  exportExcel(): void {
    this.api.downloadExcel(this.dateRange());
  }

  getSeverityClass(severity: Severity): string {
    return `badge-${severity}`;
  }

  getSeverityIcon(severity: Severity): string {
    switch (severity) {
      case 'critical':
        return 'bi-exclamation-octagon-fill';
      case 'high':
        return 'bi-exclamation-triangle-fill';
      case 'medium':
        return 'bi-exclamation-circle-fill';
      case 'low':
        return 'bi-info-circle-fill';
      default:
        return 'bi-circle';
    }
  }

  // Expose Math for template
  protected Math = Math;

  private severityOrder(severity: Severity): number {
    const order: { [key: string]: number } = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    return order[severity] ?? 5;
  }

  private getDefaultStartDate(): string {
    const date = new Date();
    date.setDate(date.getDate() - 28);
    return this.formatDate(date);
  }

  private getDefaultEndDate(): string {
    return this.formatDate(new Date());
  }

  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
  }
}
