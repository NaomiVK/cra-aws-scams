import { Controller, Get, Query, Res, Logger } from '@nestjs/common';
import { Response } from 'express';
import { ScamDetectionService } from '../services/scam-detection.service';
import { SearchConsoleService } from '../services/search-console.service';
import { DateRange, ExportData } from '@cra-scam-detection/shared-types';
import { environment } from '../environments/environment';
import * as XLSX from 'xlsx';

@Controller('export')
export class ExportController {
  private readonly logger = new Logger(ExportController.name);

  constructor(
    private readonly scamDetectionService: ScamDetectionService,
    private readonly searchConsoleService: SearchConsoleService
  ) {}

  /**
   * GET /api/export/csv
   * Export flagged terms as CSV
   */
  @Get('csv')
  async exportCsv(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string,
    @Res() res?: Response
  ) {
    const dateRange = this.getDateRange(startDate, endDate, days);

    this.logger.log(`Exporting CSV for ${dateRange.startDate} to ${dateRange.endDate}`);

    const detection = await this.scamDetectionService.detectScams(dateRange);

    // Build CSV content
    const headers = [
      'Query',
      'Severity',
      'Category',
      'Impressions',
      'Clicks',
      'CTR',
      'Position',
      'Matched Patterns',
      'Status',
      'First Detected',
    ];

    const rows = detection.flaggedTerms.map((term) => [
      term.query,
      term.severity,
      term.matchedCategory,
      term.impressions,
      term.clicks,
      (term.ctr * 100).toFixed(2) + '%',
      term.position.toFixed(1),
      term.matchedPatterns.join('; '),
      term.status,
      term.firstDetected,
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map((row) =>
        row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ),
    ].join('\n');

    const filename = `cra-scam-detection-${dateRange.startDate}-${dateRange.endDate}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  }

  /**
   * GET /api/export/excel
   * Export flagged terms as Excel file
   */
  @Get('excel')
  async exportExcel(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string,
    @Res() res?: Response
  ) {
    const dateRange = this.getDateRange(startDate, endDate, days);

    this.logger.log(`Exporting Excel for ${dateRange.startDate} to ${dateRange.endDate}`);

    const detection = await this.scamDetectionService.detectScams(dateRange);

    // Create workbook
    const wb = XLSX.utils.book_new();

    // Summary sheet
    const summaryData = [
      ['CRA Scam Detection Report'],
      [],
      ['Period', `${dateRange.startDate} to ${dateRange.endDate}`],
      ['Generated', new Date().toISOString()],
      [],
      ['Summary'],
      ['Total Flagged Terms', detection.summary.total],
      ['Critical', detection.summary.critical],
      ['High', detection.summary.high],
      ['Medium', detection.summary.medium],
      ['Low', detection.summary.low],
      [],
      ['Total Queries Analyzed', detection.totalQueriesAnalyzed],
      ['Impression Threshold', environment.scamDetection.impressionThreshold],
    ];
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(wb, summarySheet, 'Summary');

    // Flagged Terms sheet
    const termsHeaders = [
      'Query',
      'Severity',
      'Category',
      'Impressions',
      'Clicks',
      'CTR',
      'Position',
      'Matched Patterns',
      'Status',
      'First Detected',
    ];
    const termsData = [
      termsHeaders,
      ...detection.flaggedTerms.map((term) => [
        term.query,
        term.severity,
        term.matchedCategory,
        term.impressions,
        term.clicks,
        term.ctr,
        term.position,
        term.matchedPatterns.join('; '),
        term.status,
        term.firstDetected,
      ]),
    ];
    const termsSheet = XLSX.utils.aoa_to_sheet(termsData);
    XLSX.utils.book_append_sheet(wb, termsSheet, 'Flagged Terms');

    // Critical Terms sheet (filtered)
    const criticalTerms = detection.flaggedTerms.filter(
      (t) => t.severity === 'critical'
    );
    if (criticalTerms.length > 0) {
      const criticalData = [
        termsHeaders,
        ...criticalTerms.map((term) => [
          term.query,
          term.severity,
          term.matchedCategory,
          term.impressions,
          term.clicks,
          term.ctr,
          term.position,
          term.matchedPatterns.join('; '),
          term.status,
          term.firstDetected,
        ]),
      ];
      const criticalSheet = XLSX.utils.aoa_to_sheet(criticalData);
      XLSX.utils.book_append_sheet(wb, criticalSheet, 'Critical Terms');
    }

    // Generate buffer
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    const filename = `cra-scam-detection-${dateRange.startDate}-${dateRange.endDate}.xlsx`;

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  }

  /**
   * GET /api/export/json
   * Export flagged terms as JSON
   */
  @Get('json')
  async exportJson(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string
  ) {
    const dateRange = this.getDateRange(startDate, endDate, days);

    const detection = await this.scamDetectionService.detectScams(dateRange);

    const exportData: ExportData = {
      generatedAt: new Date().toISOString(),
      period: dateRange,
      summary: {
        period: dateRange,
        flaggedTermsCount: detection.summary.total,
        newTermsCount: detection.flaggedTerms.filter((t) => t.status === 'new')
          .length,
        totalSuspiciousImpressions: detection.flaggedTerms.reduce(
          (sum, t) => sum + t.impressions,
          0
        ),
        averagePosition:
          detection.flaggedTerms.length > 0
            ? detection.flaggedTerms.reduce((sum, t) => sum + t.position, 0) /
              detection.flaggedTerms.length
            : 0,
        severityBreakdown: {
          critical: detection.summary.critical,
          high: detection.summary.high,
          medium: detection.summary.medium,
          low: detection.summary.low,
        },
      },
      flaggedTerms: detection.flaggedTerms,
    };

    return {
      success: true,
      data: exportData,
    };
  }

  /**
   * Helper to get date range from query params
   */
  private getDateRange(
    startDate?: string,
    endDate?: string,
    days?: string
  ): DateRange {
    if (startDate && endDate) {
      return { startDate, endDate };
    }
    const daysNum = days
      ? parseInt(days, 10)
      : environment.scamDetection.defaultDateRangeDays;
    return SearchConsoleService.getDateRange(daysNum);
  }
}
