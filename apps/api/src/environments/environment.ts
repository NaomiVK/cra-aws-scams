export const environment = {
  production: false,
  port: 3000,

  // Google Search Console Configuration
  google: {
    credentialsPath: '../../service-account-credentials.json',
    // CRA-specific URLs on canada.ca
    siteUrl: 'https://www.canada.ca/',
    // URL filters for CRA pages only
    craUrlFilters: [
      '/en/revenue-agency/',
      '/fr/agence-revenu/',
      '/en/services/taxes/',
      '/fr/services/impots/',
    ],
  },

  // Search Console Query Limits
  searchConsole: {
    maxRows: 5000, // Maximum rows per query
    minImpressions: 100, // Minimum impressions filter
    maxDateRangeDays: 90, // Maximum date range
  },

  // Scam Detection Settings
  scamDetection: {
    impressionThreshold: 500, // Minimum impressions to flag
    defaultDateRangeDays: 28, // Default analysis period
  },

  // Embedding Settings
  embedding: {
    similarityThreshold: 0.80, // Minimum cosine similarity to flag
    model: 'text-embedding-3-large',
  },

  // Cache Settings (in seconds)
  cache: {
    analyticsTtl: 3600, // 1 hour
    trendsTtl: 1800, // 30 minutes
    keywordsTtl: 300, // 5 minutes
    embeddingsTtl: 86400, // 24 hours for seed phrase embeddings
    benchmarksTtl: 3600, // 1 hour for CTR benchmarks
  },

  // CORS
  frontendUrl: 'http://localhost:4200',
};
