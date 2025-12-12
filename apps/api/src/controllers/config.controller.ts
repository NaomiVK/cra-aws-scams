import { Controller, Get } from '@nestjs/common';

@Controller('config')
export class ConfigController {
  /**
   * GET /api/config/maps-key
   * Returns the Google Maps API key for frontend use
   */
  @Get('maps-key')
  getMapsApiKey() {
    return {
      success: true,
      data: {
        apiKey: process.env.GOOGLE_MAPS_API_KEY || '',
      },
    };
  }
}
