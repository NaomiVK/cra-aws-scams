import { Component, inject, signal, OnInit, TemplateRef, ViewChild, DestroyRef, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgbNavModule, NgbTooltipModule, NgbPaginationModule, NgbModal, NgbModalModule, NgbCollapseModule } from '@ng-bootstrap/ng-bootstrap';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService } from '../../services/api.service';
import { AuthService } from '../../services/auth.service';
import {
  EmergingThreat,
  EmergingThreatsResponse,
  ScamKeywordsConfig,
  KeywordCategory,
  UnifiedTerm,
  UnifiedTermsResponse,
  TermCategory,
  Severity,
} from '@cra-scam-detection/shared-types';

type CategoryKey = 'fakeExpiredBenefits' | 'illegitimatePaymentMethods' | 'threatLanguage' | 'suspiciousModifiers' | 'scamPatterns';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule, NgbNavModule, NgbTooltipModule, NgbPaginationModule, NgbModalModule, NgbCollapseModule],
  templateUrl: './admin.component.html',
  styleUrl: './admin.component.scss',
})
export class AdminComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly authService = inject(AuthService);
  private readonly modalService = inject(NgbModal);
  private readonly destroyRef = inject(DestroyRef);

  @ViewChild('categoryModal') categoryModal!: TemplateRef<unknown>;
  @ViewChild('loginModal') loginModal!: TemplateRef<unknown>;

  // Expose Math for template
  Math = Math;

  activeTab = signal(1);
  loading = signal(false);
  error = signal<string | null>(null);

  // Auth state
  isAuthenticated = this.authService.isAuthenticated;
  loginPassword = signal('');
  loginError = signal<string | null>(null);
  loginLoading = signal(false);
  authConfigured = signal(true); // Assume configured until we check

  emergingThreats = signal<EmergingThreatsResponse | null>(null);
  keywordsConfig = signal<ScamKeywordsConfig | null>(null);
  selectedDays = signal(7);
  currentPage = signal(1);
  selectedCategory = signal<CategoryKey>('fakeExpiredBenefits');
  newKeyword = signal('');

  // Unified terms state
  unifiedTermsResponse = signal<UnifiedTermsResponse | null>(null);
  termsLoading = signal(false);
  showRemovedTerms = signal(false);
  termSearchFilter = signal('');

  // New term form
  newTermText = signal('');
  newTermCategory = signal<TermCategory>('fakeExpiredBenefits');
  newTermSeverity = signal<Severity>('critical');
  newTermPatternMatch = signal(true);
  newTermEmbedding = signal(true);

  // Modal state
  pendingThreat = signal<EmergingThreat | null>(null);
  modalCategory = signal<CategoryKey>('fakeExpiredBenefits');

  // Bulk selection
  selectedThreats = signal<Set<string>>(new Set());
  bulkModalAction = signal<'keyword' | null>(null);

  // Computed: terms grouped by category (with search filter applied)
  termsByCategory = computed(() => {
    const response = this.unifiedTermsResponse();
    if (!response) return new Map<TermCategory, UnifiedTerm[]>();

    const searchFilter = this.termSearchFilter().toLowerCase().trim();
    const grouped = new Map<TermCategory, UnifiedTerm[]>();

    for (const term of response.terms) {
      // Apply search filter
      if (searchFilter && !term.term.toLowerCase().includes(searchFilter)) {
        continue;
      }

      const category = term.category;
      if (!grouped.has(category)) {
        grouped.set(category, []);
      }
      grouped.get(category)!.push(term);
    }
    return grouped;
  });

  // Computed: total filtered terms count
  filteredTermsCount = computed(() => {
    let count = 0;
    for (const terms of this.termsByCategory().values()) {
      count += terms.length;
    }
    return count;
  });

  ngOnInit(): void {
    this.checkAuthStatus();
    this.loadKeywordsConfig();

    // Try to validate stored password if any
    if (this.authService.hasStoredPassword()) {
      this.validateStoredPassword();
    }
  }

  private checkAuthStatus(): void {
    this.api.getAuthStatus().pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: (res) => {
        if (res.success) {
          this.authConfigured.set(res.data.configured);
        }
      },
      error: () => {
        // Assume configured if we can't check
        this.authConfigured.set(true);
      },
    });
  }

  private validateStoredPassword(): void {
    const password = this.authService.getPassword();
    if (!password) return;

    this.api.validateAdminPassword(password).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: (res) => {
        if (res.success && res.data.valid) {
          this.authService.markAuthenticated();
          this.loadEmergingThreats();
          this.loadUnifiedTerms();
        } else {
          this.authService.markUnauthenticated();
        }
      },
      error: () => {
        this.authService.markUnauthenticated();
      },
    });
  }

  // Auth methods
  submitLogin(): void {
    const password = this.loginPassword();
    if (!password) {
      this.loginError.set('Please enter a password');
      return;
    }

    this.loginLoading.set(true);
    this.loginError.set(null);

    this.api.validateAdminPassword(password).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: (res) => {
        this.loginLoading.set(false);
        if (res.success && res.data.valid) {
          this.authService.setPassword(password);
          this.loginPassword.set('');
          this.loadEmergingThreats();
          this.loadUnifiedTerms();
        } else {
          this.loginError.set('Invalid password');
        }
      },
      error: () => {
        this.loginLoading.set(false);
        this.loginError.set('Authentication failed');
      },
    });
  }

  logout(): void {
    this.authService.clearAuth();
    this.unifiedTermsResponse.set(null);
  }

  // Load unified terms
  loadUnifiedTerms(): void {
    this.termsLoading.set(true);

    this.api.getAllTerms().pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: (res) => {
        this.termsLoading.set(false);
        if (res.success) {
          this.unifiedTermsResponse.set(res.data);
        }
      },
      error: (err) => {
        this.termsLoading.set(false);
        if (err.status === 401) {
          this.authService.markUnauthenticated();
        }
        console.error('Failed to load unified terms', err);
      },
    });
  }

  // Add unified term
  addUnifiedTerm(): void {
    const term = this.newTermText().trim();
    if (!term) return;

    this.api.addUnifiedTerm({
      term,
      category: this.newTermCategory(),
      severity: this.newTermSeverity(),
      useForPatternMatch: this.newTermPatternMatch(),
      useForEmbedding: this.newTermEmbedding(),
    }).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: () => {
        this.newTermText.set('');
        this.loadUnifiedTerms();
      },
      error: (err) => {
        if (err.status === 401) {
          this.authService.markUnauthenticated();
        }
        console.error('Failed to add term', err);
      },
    });
  }

  // Remove unified term
  removeUnifiedTerm(term: UnifiedTerm): void {
    this.api.removeTerm(term.category, term.term).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: () => {
        this.loadUnifiedTerms();
      },
      error: (err) => {
        if (err.status === 401) {
          this.authService.markUnauthenticated();
        }
        console.error('Failed to remove term', err);
      },
    });
  }

  // Restore unified term
  restoreUnifiedTerm(term: UnifiedTerm): void {
    this.api.restoreTerm(term.category, term.term).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: () => {
        this.loadUnifiedTerms();
      },
      error: (err) => {
        if (err.status === 401) {
          this.authService.markUnauthenticated();
        }
        console.error('Failed to restore term', err);
      },
    });
  }

  loadEmergingThreats(): void {
    this.loading.set(true);
    this.api.getEmergingThreats(this.selectedDays(), this.currentPage()).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
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
    this.api.getKeywordsConfig().pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
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

    this.api.addKeyword(threat.query, this.modalCategory()).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: () => {
        this.loadKeywordsConfig();
        this.loadUnifiedTerms();
        this.modalService.dismissAll();
        this.pendingThreat.set(null);
      },
      error: (err) => {
        console.error('Failed to add keyword', err);
        this.loadEmergingThreats(); // Reload on error
      },
    });
  }

  dismissThreat(threat: EmergingThreat): void {
    // Optimistic UI - remove immediately
    this.removeFromList(threat.id);

    this.api.dismissThreat(threat.id).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
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

  bulkDismiss(): void {
    const selected = this.selectedThreats();
    const threats = this.emergingThreats()?.threats || [];
    const selectedThreats = threats.filter(t => selected.has(t.id));

    // Optimistic UI - remove all selected
    selectedThreats.forEach(t => this.removeFromList(t.id));

    // Dismiss each
    selectedThreats.forEach(threat => {
      this.api.dismissThreat(threat.id).pipe(
        takeUntilDestroyed(this.destroyRef)
      ).subscribe({
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
      this.api.addKeyword(threat.query, this.modalCategory()).pipe(
        takeUntilDestroyed(this.destroyRef)
      ).subscribe({
        error: (err) => console.error('Failed to add keyword', err),
      });
    });

    this.selectedThreats.set(new Set());
    this.modalService.dismissAll();
    this.bulkModalAction.set(null);
    this.loadKeywordsConfig();
    this.loadUnifiedTerms();
  }

  addKeyword(): void {
    const term = this.newKeyword().trim();
    if (!term) return;

    this.api.addKeyword(term, this.selectedCategory()).pipe(
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({
      next: () => {
        this.newKeyword.set('');
        this.loadKeywordsConfig();
        this.loadUnifiedTerms();
      },
      error: (err) => console.error('Failed to add keyword', err),
    });
  }

  getCategoryDisplayName(key: string): string {
    const names: Record<string, string> = {
      fakeExpiredBenefits: 'Fake/Expired Benefits',
      illegitimatePaymentMethods: 'Illegitimate Payment Methods',
      threatLanguage: 'Threat Language',
      suspiciousModifiers: 'Suspicious Modifiers',
      scamPatterns: 'Scam Patterns',
    };
    return names[key] || key;
  }

  getCategorySeverity(key: string): string {
    const severities: Record<string, string> = {
      fakeExpiredBenefits: 'critical',
      illegitimatePaymentMethods: 'critical',
      threatLanguage: 'high',
      suspiciousModifiers: 'medium',
      scamPatterns: 'high',
    };
    return severities[key] || 'medium';
  }

  getGoogleSearchUrl(query: string): string {
    return 'https://www.google.com/search?q=' + encodeURIComponent(query);
  }

  getCategory(config: ScamKeywordsConfig, key: CategoryKey): KeywordCategory {
    return config.categories[key as keyof typeof config.categories];
  }

  categoryKeys: CategoryKey[] = ['fakeExpiredBenefits', 'illegitimatePaymentMethods', 'threatLanguage', 'suspiciousModifiers'];
  allCategoryKeys: TermCategory[] = ['fakeExpiredBenefits', 'illegitimatePaymentMethods', 'threatLanguage', 'suspiciousModifiers', 'scamPatterns'];

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

  // When Keywords tab is activated, load unified terms if authenticated
  onTabChange(tabId: number): void {
    this.activeTab.set(tabId);
    if (tabId === 2 && this.isAuthenticated() && !this.unifiedTermsResponse()) {
      this.loadUnifiedTerms();
    }
  }
}
