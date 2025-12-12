export const environment = {
  production: true,
  port: process.env['PORT'] ? parseInt(process.env['PORT'], 10) : 3000,

  // Google Search Console Configuration
  google: {
    credentialsPath:
      process.env['GOOGLE_APPLICATION_CREDENTIALS'] ||
      '../../service-account-credentials.json',
    siteUrl: process.env['SEARCH_CONSOLE_SITE_URL'] || 'https://www.canada.ca/',
    craUrlFilters: [
      '/en/revenue-agency/',
      '/fr/agence-revenu/',
      '/en/services/taxes/',
      '/fr/services/impots/',
    ],
  },

  // Search Console Query Limits
  searchConsole: {
    maxRows: 5000,
    minImpressions: 100,
    maxDateRangeDays: 90,
  },

  // Scam Detection Settings
  scamDetection: {
    impressionThreshold: process.env['IMPRESSION_THRESHOLD']
      ? parseInt(process.env['IMPRESSION_THRESHOLD'], 10)
      : 500,
    defaultDateRangeDays: 28,
  },

  // Embedding Settings
  embedding: {
    similarityThreshold: 0.80,
    model: 'text-embedding-3-large',
  },

  // Cache Settings (in seconds)
  cache: {
    analyticsTtl: 3600,
    trendsTtl: 1800,
    keywordsTtl: 300,
    embeddingsTtl: 86400,
    benchmarksTtl: 3600,
  },

  // CORS - in production behind nginx, allow all origins
  // nginx handles the actual request proxying
  frontendUrl: process.env['FRONTEND_URL'] || '*',
};
