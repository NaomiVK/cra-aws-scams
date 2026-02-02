import { Injectable, signal } from '@angular/core';

const STORAGE_KEY = 'admin_password';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  /** Whether the user is currently authenticated */
  isAuthenticated = signal(false);

  /** Password stored in memory (also in localStorage for persistence) */
  private password: string | null = null;

  constructor() {
    // Check localStorage on init
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      this.password = stored;
      // Don't set isAuthenticated yet - will be validated on first protected request
    }
  }

  /**
   * Get the stored password for API requests
   */
  getPassword(): string | null {
    return this.password;
  }

  /**
   * Set the password after successful validation
   */
  setPassword(password: string): void {
    this.password = password;
    localStorage.setItem(STORAGE_KEY, password);
    this.isAuthenticated.set(true);
  }

  /**
   * Clear authentication
   */
  clearAuth(): void {
    this.password = null;
    localStorage.removeItem(STORAGE_KEY);
    this.isAuthenticated.set(false);
  }

  /**
   * Check if we have a stored password (doesn't validate it)
   */
  hasStoredPassword(): boolean {
    return !!this.password;
  }

  /**
   * Mark as authenticated (after successful validation)
   */
  markAuthenticated(): void {
    this.isAuthenticated.set(true);
  }

  /**
   * Mark as unauthenticated (after failed validation)
   */
  markUnauthenticated(): void {
    this.isAuthenticated.set(false);
    // Don't clear the password - user might re-enter it
  }
}
