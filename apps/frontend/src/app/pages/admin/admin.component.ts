import { Component, inject, signal, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgbNavModule, NgbTooltipModule, NgbPaginationModule, NgbModal, NgbModalModule } from '@ng-bootstrap/ng-bootstrap';
import { ApiService } from '../../services/api.service';
import {
  EmergingThreat,
  EmergingThreatsResponse,
  ScamKeywordsConfig,
  KeywordCategory,
  ExcludedTermsResponse,
} from '@cra-scam-detection/shared-types';

type CategoryKey = 'fakeExpiredBenefits' | 'illegitimatePaymentMethods' | 'threatLanguage' | 'suspiciousModifiers';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule, NgbNavModule, NgbTooltipModule, NgbPaginationModule, NgbModalModule],
  templateUrl: './admin.component.html',
  styleUrl: './admin.component.scss',
})
export class AdminComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly modalService = inject(NgbModal);

  @ViewChild('categoryModal') categoryModal!: TemplateRef<unknown>;

  // Expose Math for template
  Math = Math;

  activeTab = signal(1);
  loading = signal(false);
  error = signal<string | null>(null);

  emergingThreats = signal<EmergingThreatsResponse | null>(null);
  keywordsConfig = signal<ScamKeywordsConfig | null>(null);
  excludedTerms = signal<ExcludedTermsResponse | null>(null);
  selectedDays = signal(7);
  currentPage = signal(1);
  selectedCategory = signal<CategoryKey>('fakeExpiredBenefits');
  newKeyword = signal('');
  newWhitelistPattern = signal('');
  newExcludedTerm = signal('');
  selectedExcludedCategory = signal('generalInquiry');

  // Modal state
  pendingThreat = signal<EmergingThreat | null>(null);
  modalCategory = signal<CategoryKey>('fakeExpiredBenefits');

  // Bulk selection
  selectedThreats = signal<Set<string>>(new Set());
  bulkModalAction = signal<'keyword' | 'whitelist' | null>(null);

  ngOnInit(): void {
    this.loadEmergingThreats();
    this.loadKeywordsConfig();
    this.loadExcludedTerms();
  }

  loadEmergingThreats(): void {
    this.loading.set(true);
    this.api.getEmergingThreats(this.selectedDays(), this.currentPage()).subscribe({
      next: (res) => {
        if (res.success) {
          this.emergingThreats.set(res.data);
        }
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set('Failed to load emerging threats');
        this.loading.set(false);
        console.error(err);
      },
    });
  }

  onPageChange(page: number): void {
    this.currentPage.set(page);
    this.loadEmergingThreats();
  }

  loadKeywordsConfig(): void {
    this.api.getKeywordsConfig().subscribe({
      next: (res) => {
        if (res.success) {
          this.keywordsConfig.set(res.data);
        }
      },
      error: (err) => {
        console.error('Failed to load keywords config', err);
      },
    });
  }

  loadExcludedTerms(): void {
    this.api.getExcludedTerms().subscribe({
      next: (res) => {
        if (res.success) {
          this.excludedTerms.set(res.data);
        }
      },
      error: (err) => {
        console.error('Failed to load excluded terms', err);
      },
    });
  }

  addExcludedTerm(): void {
    const term = this.newExcludedTerm().trim();
    if (!term) return;

    this.api.addExcludedTerm(term, this.selectedExcludedCategory()).subscribe({
      next: () => {
        this.newExcludedTerm.set('');
        this.loadExcludedTerms();
      },
      error: (err) => console.error('Failed to add excluded term', err),
    });
  }

  onDaysChange(): void {
    this.currentPage.set(1); // Reset to first page when changing days
    this.loadEmergingThreats();
  }

  getRiskClass(level: string): string {
    switch (level) {
      case 'critical': return 'danger';
      case 'high': return 'warning';
      case 'medium': return 'info';
      default: return 'secondary';
    }
  }

  /**
   * Open modal to select category before adding keyword
   */
  addToKeywords(threat: EmergingThreat): void {
    this.pendingThreat.set(threat);
    this.modalCategory.set('fakeExpiredBenefits');
    this.modalService.open(this.categoryModal, { centered: true });
  }

  /**
   * Confirm adding keyword with selected category
   */
  confirmAddKeyword(): void {
    // Check if this is a bulk action
    if (this.bulkModalAction() === 'keyword') {
      this.confirmBulkAddKeyword();
      return;
    }

    const threat = this.pendingThreat();
    if (!threat) return;

    // Optimistic UI - remove immediately
    this.removeFromList(threat.id);

    this.api.addKeyword(threat.query, this.modalCategory()).subscribe({
      next: () => {
        this.loadKeywordsConfig();
        this.modalService.dismissAll();
        this.pendingThreat.set(null);
      },
      error: (err) => {
        console.error('Failed to add keyword', err);
        this.loadEmergingThreats(); // Reload on error
      },
    });
  }

  addToWhitelist(threat: EmergingThreat): void {
    // Optimistic UI - remove immediately
    this.removeFromList(threat.id);

    this.api.addWhitelist(threat.query).subscribe({
      next: () => {
        this.loadKeywordsConfig();
      },
      error: (err) => {
        console.error('Failed to add to whitelist', err);
        this.loadEmergingThreats(); // Reload on error
      },
    });
  }

  dismissThreat(threat: EmergingThreat): void {
    // Optimistic UI - remove immediately
    this.removeFromList(threat.id);

    this.api.dismissThreat(threat.id).subscribe({
      error: (err) => {
        console.error('Failed to dismiss', err);
        this.loadEmergingThreats(); // Reload on error
      },
    });
  }

  // Optimistic UI helper - remove threat from local list
  private removeFromList(threatId: string): void {
    const current = this.emergingThreats();
    if (!current) return;

    const updatedThreats = current.threats.filter(t => t.id !== threatId);
    this.emergingThreats.set({
      ...current,
      threats: updatedThreats,
      summary: {
        ...current.summary,
        total: current.summary.total - 1,
      },
    });

    // Remove from selection if selected
    const selected = new Set(this.selectedThreats());
    selected.delete(threatId);
    this.selectedThreats.set(selected);
  }

  // Bulk selection methods
  toggleSelect(threatId: string): void {
    const selected = new Set(this.selectedThreats());
    if (selected.has(threatId)) {
      selected.delete(threatId);
    } else {
      selected.add(threatId);
    }
    this.selectedThreats.set(selected);
  }

  isSelected(threatId: string): boolean {
    return this.selectedThreats().has(threatId);
  }

  toggleSelectAll(): void {
    const threats = this.emergingThreats()?.threats || [];
    const selected = this.selectedThreats();

    if (selected.size === threats.length) {
      // Deselect all
      this.selectedThreats.set(new Set());
    } else {
      // Select all
      this.selectedThreats.set(new Set(threats.map(t => t.id)));
    }
  }

  isAllSelected(): boolean {
    const threats = this.emergingThreats()?.threats || [];
    return threats.length > 0 && this.selectedThreats().size === threats.length;
  }

  getSelectedCount(): number {
    return this.selectedThreats().size;
  }

  // Bulk actions
  bulkAddToKeywords(): void {
    this.bulkModalAction.set('keyword');
    this.modalCategory.set('fakeExpiredBenefits');
    this.modalService.open(this.categoryModal, { centered: true });
  }

  bulkAddToWhitelist(): void {
    const selected = this.selectedThreats();
    const threats = this.emergingThreats()?.threats || [];
    const selectedThreats = threats.filter(t => selected.has(t.id));

    // Optimistic UI - remove all selected
    selectedThreats.forEach(t => this.removeFromList(t.id));

    // Add each to whitelist
    selectedThreats.forEach(threat => {
      this.api.addWhitelist(threat.query).subscribe({
        error: (err) => console.error('Failed to add to whitelist', err),
      });
    });

    this.selectedThreats.set(new Set());
    this.loadKeywordsConfig();
  }

  bulkDismiss(): void {
    const selected = this.selectedThreats();
    const threats = this.emergingThreats()?.threats || [];
    const selectedThreats = threats.filter(t => selected.has(t.id));

    // Optimistic UI - remove all selected
    selectedThreats.forEach(t => this.removeFromList(t.id));

    // Dismiss each
    selectedThreats.forEach(threat => {
      this.api.dismissThreat(threat.id).subscribe({
        error: (err) => console.error('Failed to dismiss', err),
      });
    });

    this.selectedThreats.set(new Set());
  }

  confirmBulkAddKeyword(): void {
    const selected = this.selectedThreats();
    const threats = this.emergingThreats()?.threats || [];
    const selectedThreats = threats.filter(t => selected.has(t.id));

    // Optimistic UI - remove all selected
    selectedThreats.forEach(t => this.removeFromList(t.id));

    // Add each as keyword
    selectedThreats.forEach(threat => {
      this.api.addKeyword(threat.query, this.modalCategory()).subscribe({
        error: (err) => console.error('Failed to add keyword', err),
      });
    });

    this.selectedThreats.set(new Set());
    this.modalService.dismissAll();
    this.bulkModalAction.set(null);
    this.loadKeywordsConfig();
  }

  addKeyword(): void {
    const term = this.newKeyword().trim();
    if (!term) return;

    this.api.addKeyword(term, this.selectedCategory()).subscribe({
      next: () => {
        this.newKeyword.set('');
        this.loadKeywordsConfig();
      },
      error: (err) => console.error('Failed to add keyword', err),
    });
  }

  addWhitelistPattern(): void {
    const pattern = this.newWhitelistPattern().trim();
    if (!pattern) return;

    this.api.addWhitelist(pattern).subscribe({
      next: () => {
        this.newWhitelistPattern.set('');
        this.loadKeywordsConfig();
      },
      error: (err) => console.error('Failed to add whitelist pattern', err),
    });
  }

  getCategoryDisplayName(key: string): string {
    const names: Record<string, string> = {
      fakeExpiredBenefits: 'Fake/Expired Benefits',
      illegitimatePaymentMethods: 'Illegitimate Payment Methods',
      threatLanguage: 'Threat Language',
      suspiciousModifiers: 'Suspicious Modifiers',
    };
    return names[key] || key;
  }

  getCategory(config: ScamKeywordsConfig, key: CategoryKey): KeywordCategory {
    return config.categories[key];
  }

  categoryKeys: CategoryKey[] = ['fakeExpiredBenefits', 'illegitimatePaymentMethods', 'threatLanguage', 'suspiciousModifiers'];

  exportConfig(): void {
    const config = this.keywordsConfig();
    if (!config) {
      console.error('No configuration loaded to export');
      return;
    }

    const exportData = {
      version: config.version || '1.0.0',
      lastUpdated: new Date().toISOString(),
      categories: config.categories,
      whitelist: config.whitelist,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'scam-keywords.json';
    a.click();
    URL.revokeObjectURL(url);
  }
}
