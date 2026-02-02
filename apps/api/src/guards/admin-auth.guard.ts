import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';

@Injectable()
export class AdminAuthGuard implements CanActivate {
  private readonly logger = new Logger(AdminAuthGuard.name);

  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const password = request.headers['x-admin-password'];

    if (!password) {
      this.logger.debug('Missing X-Admin-Password header');
      throw new UnauthorizedException('Admin authentication required');
    }

    const isValid = await this.authService.validatePassword(password);

    if (!isValid) {
      this.logger.debug('Invalid admin password');
      throw new UnauthorizedException('Invalid admin password');
    }

    return true;
  }
}
