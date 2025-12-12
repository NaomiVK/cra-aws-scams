import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgbDatepickerModule, NgbDate, NgbCalendar } from '@ng-bootstrap/ng-bootstrap';
import { ApiService } from '../../services/api.service';
import { ComparisonResponse, DateRange, TermComparison } from '@cra-scam-detection/shared-types';

type SortColumn = 'query' | 'currentImpressions' | 'previousImpressions' | 'change';
type SortDirection = 'asc' | 'desc';

type ComparisonPreset = {
  label: string;
  value: string;
  days: number;
};

@Component({
  selector: 'app-comparison',
  standalone: true,
  imports: [CommonModule, FormsModule, NgbDatepickerModule],
  templateUrl: './comparison.component.html',
  styleUrl: './comparison.component.scss',
})
export class ComparisonComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly calendar = inject(NgbCalendar);

  loading = signal(true);
  error = signal<string | null>(null);
  comparisonData = signal<ComparisonResponse | null>(null);

  // Comparison presets
  comparisonPresets: ComparisonPreset[] = [
    { label: 'Week over Week', value: 'week', days: 7 },
    { label: '2 Weeks over 2 Weeks', value: '2weeks', days: 14 },
    { label: 'Month over Month', value: 'month', days: 30 },
    { label: 'Custom', value: 'custom', days: 0 },
  ];
  selectedPreset = signal<string>('week');

  // Custom date ranges
  period1Start = signal<NgbDate | null>(null);
  period1End = signal<NgbDate | null>(null);
  period2Start = signal<NgbDate | null>(null);
  period2End = signal<NgbDate | null>(null);

  // Table filtering and sorting
  queryFilter = signal<string>('');
  sortColumn = signal<SortColumn>('change');
  sortDirection = signal<SortDirection>('desc');
  minChangeFilter = signal<number>(0);

  // Computed filtered and sorted terms
  filteredTrendingTerms = computed(() => {
    const data = this.comparisonData();
    if (!data) return [];

    let terms = data.terms.filter(t => !t.isNew && !t.isGone);

    // Apply query filter
    const queryFilterValue = this.queryFilter().toLowerCase().trim();
    if (queryFilterValue) {
      terms = terms.filter(t => t.query.toLowerCase().includes(queryFilterValue));
    }

    // Apply minimum change filter
    const minChange = this.minChangeFilter();
    if (minChange > 0) {
      terms = terms.filter(t => Math.abs(t.change.impressionsPercent) >= minChange);
    }

    // Sort
    const column = this.sortColumn();
    const direction = this.sortDirection();
    terms.sort((a, b) => {
      let comparison = 0;
      switch (column) {
        case 'query':
          comparison = a.query.localeCompare(b.query);
          break;
        case 'currentImpressions':
          comparison = a.current.impressions - b.current.impressions;
          break;
        case 'previousImpressions':
          comparison = a.previous.impressions - b.previous.impressions;
          break;
        case 'change':
          comparison = a.change.impressionsPercent - b.change.impressionsPercent;
          break;
      }
      return direction === 'asc' ? comparison : -comparison;
    });

    return terms;
  });

  ngOnInit(): void {
    this.initializeDatePickers();
    this.loadComparison();
  }

  initializeDatePickers(): void {
    const today = this.calendar.getToday();

    // Period 1: Last 7 days
    this.period1End.set(today);
    this.period1Start.set(this.calendar.getPrev(today, 'd', 7));

    // Period 2: Previous 7 days
    const period1StartDate = this.calendar.getPrev(today, 'd', 7);
    this.period2End.set(this.calendar.getPrev(period1StartDate, 'd', 1));
    this.period2Start.set(this.calendar.getPrev(period1StartDate, 'd', 8));
  }

  async loadComparison(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);

    try {
      const preset = this.selectedPreset();

      if (preset === 'custom') {
        await this.loadCustomComparison();
      } else {
        const presetConfig = this.comparisonPresets.find(p => p.value === preset);
        const days = presetConfig?.days || 7;

        const period1 = this.getDateRangeFromToday(days);
        const period2 = this.getPreviousPeriod(period1, days);

        const response = await this.api.getComparison(period1, period2).toPromise();
        if (response?.success && response.data) {
          this.comparisonData.set(response.data);
        } else {
          this.error.set(response?.error || 'Failed to load comparison data');
        }
      }
    } catch (err) {
      this.error.set('Failed to connect to API');
      console.error('Comparison load error:', err);
    } finally {
      this.loading.set(false);
    }
  }

  async loadCustomComparison(): Promise<void> {
    const p1Start = this.period1Start();
    const p1End = this.period1End();
    const p2Start = this.period2Start();
    const p2End = this.period2End();

    if (!p1Start || !p1End || !p2Start || !p2End) {
      this.error.set('Please select all date ranges');
      this.loading.set(false);
      return;
    }

    const period1: DateRange = {
      startDate: this.ngbDateToString(p1Start),
      endDate: this.ngbDateToString(p1End),
    };
    const period2: DateRange = {
      startDate: this.ngbDateToString(p2Start),
      endDate: this.ngbDateToString(p2End),
    };

    const response = await this.api.getComparison(period1, period2).toPromise();
    if (response?.success && response.data) {
      this.comparisonData.set(response.data);
    } else {
      this.error.set(response?.error || 'Failed to load comparison data');
    }
  }

  onPresetChange(): void {
    const preset = this.selectedPreset();
    if (preset !== 'custom') {
      this.loadComparison();
    }
  }

  // Table sorting
  sort(column: SortColumn): void {
    if (this.sortColumn() === column) {
      this.sortDirection.set(this.sortDirection() === 'asc' ? 'desc' : 'asc');
    } else {
      this.sortColumn.set(column);
      this.sortDirection.set('desc');
    }
  }

  getSortIcon(column: SortColumn): string {
    if (this.sortColumn() !== column) return 'bi-chevron-expand';
    return this.sortDirection() === 'asc' ? 'bi-chevron-up' : 'bi-chevron-down';
  }

  getChangeClass(change: number): string {
    if (change > 0) return 'text-danger';
    if (change < 0) return 'text-success';
    return 'text-muted';
  }

  getChangeIcon(change: number): string {
    if (change > 0) return 'bi-arrow-up';
    if (change < 0) return 'bi-arrow-down';
    return 'bi-dash';
  }

  formatChange(change: number): string {
    const sign = change > 0 ? '+' : '';
    return `${sign}${change.toFixed(1)}%`;
  }

  getNewTerms(): TermComparison[] {
    const data = this.comparisonData();
    if (!data) return [];
    return data.terms.filter(t => t.isNew);
  }

  getRemovedTerms(): TermComparison[] {
    const data = this.comparisonData();
    if (!data) return [];
    return data.terms.filter(t => t.isGone);
  }

  getSelectedPresetLabel(): string {
    return this.comparisonPresets.find(p => p.value === this.selectedPreset())?.label || 'Week over Week';
  }

  private getDateRangeFromToday(days: number): DateRange {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);
    return {
      startDate: this.formatDate(start),
      endDate: this.formatDate(end),
    };
  }

  private getPreviousPeriod(currentPeriod: DateRange, days: number): DateRange {
    const prevEnd = new Date(currentPeriod.startDate);
    prevEnd.setDate(prevEnd.getDate() - 1);
    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - days + 1);
    return {
      startDate: this.formatDate(prevStart),
      endDate: this.formatDate(prevEnd),
    };
  }

  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
  }

  private ngbDateToString(date: NgbDate): string {
    const month = date.month.toString().padStart(2, '0');
    const day = date.day.toString().padStart(2, '0');
    return `${date.year}-${month}-${day}`;
  }
}
