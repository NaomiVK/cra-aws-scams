import { Controller, Get } from '@nestjs/common';
import { AwsConfigService } from '../services';

@Controller('config')
export class ConfigController {
  constructor(private readonly awsConfigService: AwsConfigService) {}

  /**
   * GET /api/config/maps-key
   * Returns the Google Maps API key for frontend use
   */
  @Get('maps-key')
  getMapsApiKey() {
    return {
      success: true,
      data: {
        apiKey: this.awsConfigService.getGoogleMapsApiKey(),
      },
    };
  }
}
