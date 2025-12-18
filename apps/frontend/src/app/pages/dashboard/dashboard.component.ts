import { Component, OnInit, inject, signal, DestroyRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { NgbTooltipModule } from '@ng-bootstrap/ng-bootstrap';
import { firstValueFrom } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService } from '../../services/api.service';
import {
  DashboardData,
  DateRange,
  EmergingThreatsResponse,
} from '@cra-scam-detection/shared-types';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    NgbTooltipModule,
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);

  // Loading states
  loading = signal(true);
  loadingEmergingThreats = signal(false);
  error = signal<string | null>(null);
  emergingThreatsError = signal<string | null>(null);

  // Dashboard data
  dashboardData = signal<DashboardData | null>(null);
  emergingThreats = signal<EmergingThreatsResponse | null>(null);

  // Date range
  dateRange = signal<DateRange>({
    startDate: this.getDefaultStartDate(),
    endDate: this.getDefaultEndDate(),
  });

  // Track selected date range for button highlighting
  selectedDays = signal(7);

  ngOnInit(): void {
    this.loadDashboard();
    this.loadEmergingThreats();
  }

  loadEmergingThreats(): void {
    this.loadingEmergingThreats.set(true);
    this.emergingThreatsError.set(null);

    this.api.getEmergingThreats(this.selectedDays()).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.emergingThreats.set(res.data);
        } else {
          this.emergingThreatsError.set(res.error || 'Failed to load emerging threats');
        }
        this.loadingEmergingThreats.set(false);
      },
      error: () => {
        this.emergingThreatsError.set('Failed to connect to emerging threats API');
        this.loadingEmergingThreats.set(false);
      },
    });
  }

  async loadDashboard(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);

    try {
      const response = await firstValueFrom(this.api.getDashboard(this.dateRange()));
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

  onQuickDateRange(days: number): void {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    this.dateRange.set({
      startDate: this.formatDate(startDate),
      endDate: this.formatDate(endDate),
    });
    this.selectedDays.set(days);
    this.loadDashboard();
    this.loadEmergingThreats();
  }

  private getDefaultStartDate(): string {
    const date = new Date();
    date.setDate(date.getDate() - 7);
    return this.formatDate(date);
  }

  private getDefaultEndDate(): string {
    return this.formatDate(new Date());
  }

  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
  }
}
