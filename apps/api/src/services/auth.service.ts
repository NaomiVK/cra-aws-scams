import { Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AwsConfigService } from './aws-config.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly awsConfigService: AwsConfigService) {}

  /**
   * Validate an admin password against the stored hash
   * @param password The plain text password to validate
   * @returns true if the password is valid, false otherwise
   */
  async validatePassword(password: string): Promise<boolean> {
    const hash = this.awsConfigService.getAdminPasswordHash();

    if (!hash) {
      this.logger.warn('ADMIN_PASSWORD_HASH not configured - admin auth disabled');
      return false;
    }

    if (!password) {
      return false;
    }

    try {
      const isValid = await bcrypt.compare(password, hash);
      if (!isValid) {
        this.logger.debug('Admin password validation failed');
      }
      return isValid;
    } catch (error) {
      this.logger.error(`Password validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if admin authentication is configured
   * @returns true if ADMIN_PASSWORD_HASH is set
   */
  isAuthConfigured(): boolean {
    const hash = this.awsConfigService.getAdminPasswordHash();
    return !!hash && hash.length > 0;
  }

  /**
   * Generate a password hash (utility for setup)
   * @param password The plain text password to hash
   * @returns The bcrypt hash
   */
  async generateHash(password: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }
}
