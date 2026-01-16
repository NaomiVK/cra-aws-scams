import { Component, OnInit, OnDestroy, inject, signal, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';
import { ApiService } from '../../services/api.service';
import { TrendsResult, InterestByRegionResponse, RegionInterest } from '@cra-scam-detection/shared-types';
import { NgApexchartsModule, ApexAxisChartSeries, ApexChart, ApexXAxis, ApexYAxis, ApexStroke, ApexTooltip, ApexDataLabels, ApexLegend, ApexFill, ApexGrid, ApexMarkers } from 'ng-apexcharts';

// Google Charts types - external library
type GoogleVisualization = {
  arrayToDataTable: (data: (string | number)[][]) => unknown;
  GeoChart: new (element: HTMLElement) => { draw: (data: unknown, options: unknown) => void };
};

type GoogleCharts = {
  load: (version: string, options: { packages: string[]; mapsApiKey: string }) => void;
  setOnLoadCallback: (callback: () => void) => void;
};

type GoogleGlobal = {
  visualization: GoogleVisualization;
  charts: GoogleCharts;
};

declare const google: GoogleGlobal;

export type ChartOptions = {
  series: ApexAxisChartSeries;
  chart: ApexChart;
  xaxis: ApexXAxis;
  yaxis: ApexYAxis;
  stroke: ApexStroke;
  tooltip: ApexTooltip;
  dataLabels: ApexDataLabels;
  legend: ApexLegend;
  fill: ApexFill;
  grid: ApexGrid;
  markers: ApexMarkers;
  colors: string[];
};

type TimePeriod = {
  label: string;
  value: string;
  description: string;
};

@Component({
  selector: 'app-trends',
  standalone: true,
  imports: [CommonModule, FormsModule, NgApexchartsModule],
  templateUrl: './trends.component.html',
  styleUrl: './trends.component.scss',
})
export class TrendsComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private googleChartsLoaded = false;
  private geoChart: { draw: (data: unknown, options: unknown) => void } | null = null;
  private googleChartsScriptLoaded = false;

  loading = signal(false);
  error = signal<string | null>(null);
  trendsData = signal<TrendsResult | null>(null);
  regionData = signal<InterestByRegionResponse | null>(null);
  loadingRegion = signal(false);
  googleChartsError = signal<string | null>(null);

  // Seed phrases from DynamoDB
  seedPhrases = signal<{ term: string; category: string }[]>([]);
  loadingSeedPhrases = signal(false);
  seedPhrasesError = signal<string | null>(null);

  constructor() {
    // Effect to redraw map when region data changes
    effect(() => {
      const data = this.regionData();
      if (data && this.googleChartsLoaded) {
        // Allow time for DOM to render after Angular change detection
        setTimeout(() => this.drawRegionsMap(), 100);
      }
    });
  }

  // Search term
  searchTerm = signal('');
  currentSearchTerm = signal('');
  
  // Time period selection
  selectedTimePeriod = signal<string>('today 3-m');
  timePeriods: TimePeriod[] = [
    { label: 'Past hour', value: 'now 1-H', description: 'Last 60 minutes' },
    { label: 'Past 4 hours', value: 'now 4-H', description: 'Last 4 hours' },
    { label: 'Past day', value: 'now 1-d', description: 'Last 24 hours' },
    { label: 'Past 7 days', value: 'now 7-d', description: 'Last week' },
    { label: 'Past 30 days', value: 'today 1-m', description: 'Last month' },
    { label: 'Past 90 days', value: 'today 3-m', description: 'Last 3 months' },
    { label: 'Past 12 months', value: 'today 12-m', description: 'Last year' },
    { label: 'Past 5 years', value: 'today 5-y', description: 'Last 5 years' },
  ];
  
  // Chart options
  chartOptions: Partial<ChartOptions> = {
    series: [],
    chart: {
      type: 'area',
      height: 350,
      fontFamily: 'inherit',
      toolbar: {
        show: true,
        tools: {
          download: true,
          selection: true,
          zoom: true,
          zoomin: true,
          zoomout: true,
          pan: true,
          reset: true,
        },
      },
      animations: {
        enabled: true,
        speed: 500,
      },
    },
    colors: ['#4285f4', '#ea4335', '#fbbc04', '#34a853', '#ff6d01'],
    stroke: {
      curve: 'smooth',
      width: 2,
    },
    fill: {
      type: 'gradient',
      gradient: {
        shadeIntensity: 1,
        opacityFrom: 0.4,
        opacityTo: 0.1,
        stops: [0, 90, 100],
      },
    },
    xaxis: {
      type: 'category',
      labels: {
        rotate: -45,
        style: {
          fontSize: '11px',
        },
      },
    },
    yaxis: {
      min: 0,
      max: 100,
      title: {
        text: 'Interest',
        style: {
          fontSize: '12px',
        },
      },
      labels: {
        formatter: (val: number) => val.toFixed(0),
      },
    },
    tooltip: {
      shared: true,
      intersect: false,
      y: {
        formatter: (val: number) => `${val} interest`,
      },
    },
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: 'top',
      horizontalAlign: 'left',
    },
    grid: {
      borderColor: '#e7e7e7',
      row: {
        colors: ['#f3f3f3', 'transparent'],
        opacity: 0.5,
      },
    },
    markers: {
      size: 0,
      hover: {
        size: 5,
      },
    },
  };

  ngOnInit(): void {
    this.loadGoogleCharts();
    this.loadSeedPhrases();
  }

  /**
   * Load seed phrases from DynamoDB for dropdown
   */
  async loadSeedPhrases(): Promise<void> {
    this.loadingSeedPhrases.set(true);
    this.seedPhrasesError.set(null);
    try {
      const response = await firstValueFrom(this.api.getSeedPhrases());
      if (response?.success && response.data) {
        this.seedPhrases.set(response.data);
      } else {
        this.seedPhrasesError.set(response?.error || 'Failed to load seed phrases');
      }
    } catch {
      this.seedPhrasesError.set('Failed to connect to seed phrases API');
    } finally {
      this.loadingSeedPhrases.set(false);
    }
  }

  /**
   * Search for a seed phrase from the dropdown
   */
  onSeedPhraseSelect(term: string): void {
    if (term) {
      this.searchTerm.set(term);
      this.searchTrends();
    }
  }

  ngOnDestroy(): void {
    this.geoChart = null;
  }

  private googleMapsApiKey = '';

  private async loadGoogleCharts(): Promise<void> {
    this.googleChartsError.set(null);

    // Fetch API key from server
    try {
      const response = await firstValueFrom(this.api.getMapsApiKey());
      if (response?.success && response.data?.apiKey) {
        this.googleMapsApiKey = response.data.apiKey;
      } else {
        this.googleChartsError.set('Google Maps API key not configured');
        return;
      }
    } catch {
      this.googleChartsError.set('Failed to fetch Maps API key');
      return;
    }

    // Check if already loaded
    if (typeof google !== 'undefined' && google.visualization) {
      this.googleChartsLoaded = true;
      return;
    }

    // Prevent loading script multiple times
    if (this.googleChartsScriptLoaded) {
      return;
    }
    this.googleChartsScriptLoaded = true;

    // Load Google Charts script
    const script = document.createElement('script');
    script.src = 'https://www.gstatic.com/charts/loader.js';
    script.onload = () => {
      if (typeof google === 'undefined' || !google.charts) {
        this.googleChartsError.set('Google Charts failed to load properly');
        return;
      }
      google.charts.load('current', {
        packages: ['geochart'],
        mapsApiKey: this.googleMapsApiKey
      });
      google.charts.setOnLoadCallback(() => {
        this.googleChartsLoaded = true;
        // Draw map if data is already available
        if (this.regionData()) {
          setTimeout(() => this.drawRegionsMap(), 100);
        }
      });
    };
    script.onerror = () => {
      this.googleChartsError.set('Failed to load Google Charts script');
    };
    document.head.appendChild(script);
  }

  private drawRegionsMap(): void {
    const regionData = this.regionData();
    if (!regionData?.regions || regionData.regions.length === 0) {
      return;
    }

    const chartElement = document.getElementById('canada-geochart');
    if (!chartElement) {
      return;
    }

    // Check Google Charts is available
    if (typeof google === 'undefined' || !google.visualization) {
      return;
    }

    // Build data table for GeoChart
    const dataArray: (string | number)[][] = [['Province', 'Interest']];

    // Map region names to format Google Charts expects
    for (const region of regionData.regions) {
      dataArray.push([region.geoName, region.value]);
    }

    const data = google.visualization.arrayToDataTable(dataArray);

    const options = {
      region: 'CA',
      resolution: 'provinces',
      colorAxis: {
        colors: ['#c6dafc', '#8ab4f8', '#4285f4', '#1a73e8'],
        minValue: 0,
        maxValue: 100
      },
      backgroundColor: '#fff',
      datalessRegionColor: '#f1f3f4',
      defaultColor: '#f1f3f4',
      legend: 'none',
      tooltip: {
        trigger: 'focus'
      }
    };

    this.geoChart = new google.visualization.GeoChart(chartElement);
    this.geoChart.draw(data, options);
  }

  async searchTrends(): Promise<void> {
    const term = this.searchTerm().trim();

    if (term.length === 0) {
      return;
    }

    this.loading.set(true);
    this.error.set(null);
    this.currentSearchTerm.set(term);
    this.regionData.set(null);

    try {
      const response = await firstValueFrom(this.api.getTrends([term], this.selectedTimePeriod()));
      if (response?.success && response.data) {
        this.trendsData.set(response.data);
        this.updateChart(response.data);
        // Delay region call to avoid Google rate limiting
        setTimeout(() => this.loadRegionData(term), 1500);
      } else {
        this.error.set(response?.error || 'Failed to load trends data');
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      this.error.set(`Failed to connect to API: ${errorMessage}`);
    } finally {
      this.loading.set(false);
    }
  }

  async loadRegionData(keyword: string): Promise<void> {
    this.loadingRegion.set(true);
    try {
      const response = await firstValueFrom(this.api.getInterestByRegion(keyword));
      if (response?.success && response.data) {
        this.regionData.set(response.data);
      }
    } catch {
      // Region data is optional, don't show error
    } finally {
      this.loadingRegion.set(false);
    }
  }

  onTimePeriodChange(): void {
    if (this.currentSearchTerm()) {
      this.searchTrends();
    }
  }

  updateChart(data: TrendsResult): void {
    if (!data.interestOverTime || data.interestOverTime.length === 0) {
      this.chartOptions.series = [];
      return;
    }

    const series = data.keywords.map((keyword) => ({
      name: keyword,
      data: data.interestOverTime.map((point) => point.values[keyword] || 0),
    }));

    const categories = data.interestOverTime.map((point) => point.date);

    this.chartOptions = {
      ...this.chartOptions,
      series,
      xaxis: {
        ...this.chartOptions.xaxis,
        categories,
      },
    };
  }

  getInterestLevel(value: number): { label: string; class: string } {
    if (value >= 75) return { label: 'Very High', class: 'bg-danger' };
    if (value >= 50) return { label: 'High', class: 'bg-warning' };
    if (value >= 25) return { label: 'Medium', class: 'bg-info' };
    return { label: 'Low', class: 'bg-secondary' };
  }

  getSelectedTimePeriodLabel(): string {
    return this.timePeriods.find(p => p.value === this.selectedTimePeriod())?.label || 'Past 90 days';
  }

  getPeakInterest(): number {
    const data = this.trendsData();
    if (!data?.interestOverTime) return 0;
    
    let peak = 0;
    data.interestOverTime.forEach(point => {
      Object.values(point.values).forEach(val => {
        if (val > peak) peak = val;
      });
    });
    return peak;
  }

  getAverageInterest(): number {
    const data = this.trendsData();
    if (!data?.interestOverTime || data.interestOverTime.length === 0) return 0;

    let sum = 0;
    let count = 0;
    data.interestOverTime.forEach(point => {
      Object.values(point.values).forEach(val => {
        sum += val;
        count++;
      });
    });
    return count > 0 ? Math.round(sum / count) : 0;
  }

  getTrendDirection(): { label: string; icon: string; class: string } {
    const data = this.trendsData();
    if (!data?.interestOverTime || data.interestOverTime.length < 2) {
      return { label: 'N/A', icon: 'bi-dash', class: 'text-muted' };
    }

    const points = data.interestOverTime;
    const midpoint = Math.floor(points.length / 2);

    let firstHalfSum = 0, firstHalfCount = 0;
    let secondHalfSum = 0, secondHalfCount = 0;

    points.forEach((point, index) => {
      Object.values(point.values).forEach(val => {
        if (index < midpoint) {
          firstHalfSum += val;
          firstHalfCount++;
        } else {
          secondHalfSum += val;
          secondHalfCount++;
        }
      });
    });

    const firstHalfAvg = firstHalfCount > 0 ? firstHalfSum / firstHalfCount : 0;
    const secondHalfAvg = secondHalfCount > 0 ? secondHalfSum / secondHalfCount : 0;
    const change = secondHalfAvg - firstHalfAvg;
    const percentChange = firstHalfAvg > 0 ? (change / firstHalfAvg) * 100 : 0;

    if (percentChange > 10) {
      return { label: 'Rising', icon: 'bi-arrow-up', class: 'text-danger' };
    } else if (percentChange < -10) {
      return { label: 'Falling', icon: 'bi-arrow-down', class: 'text-success' };
    } else {
      return { label: 'Stable', icon: 'bi-arrow-right', class: 'text-info' };
    }
  }

  getRegionColor(value: number): string {
    if (value >= 75) return '#1a73e8';
    if (value >= 50) return '#4285f4';
    if (value >= 25) return '#8ab4f8';
    if (value > 0) return '#c6dafc';
    return '#f1f3f4';
  }

  getSortedRegions(): RegionInterest[] {
    const data = this.regionData();
    if (!data?.regions) return [];
    return [...data.regions].sort((a, b) => b.value - a.value);
  }
}
