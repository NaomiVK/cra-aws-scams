import { Route } from '@angular/router';
import { DashboardComponent } from './pages/dashboard/dashboard.component';

export const appRoutes: Route[] = [
  {
    path: '',
    redirectTo: 'dashboard',
    pathMatch: 'full',
  },
  {
    path: 'dashboard',
    component: DashboardComponent,
  },
  {
    path: 'comparison',
    loadComponent: () =>
      import('./pages/comparison/comparison.component').then(
        (m) => m.ComparisonComponent
      ),
  },
  {
    path: 'trends',
    loadComponent: () =>
      import('./pages/trends/trends.component').then((m) => m.TrendsComponent),
  },
  {
    path: 'social',
    loadComponent: () =>
      import('./pages/social/social.component').then((m) => m.SocialComponent),
  },
  {
    path: 'admin',
    loadComponent: () =>
      import('./pages/admin/admin.component').then((m) => m.AdminComponent),
  },
  {
    path: '**',
    redirectTo: 'dashboard',
  },
];
