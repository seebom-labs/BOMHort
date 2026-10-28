import { createApplication } from '@angular/platform-browser';
import { createCustomElement } from '@angular/elements';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { LocationStrategy } from '@angular/common';

import { API_BASE_URL } from '../app/core/api.service';
import { routes } from '../app/app.routes';
import { MemoryLocationStrategy, PageComponent } from './page.component';
import { DonutChartComponent } from '../app/shared/charts/donut-chart.component';
import { HorizontalBarChartComponent } from '../app/shared/charts/horizontal-bar-chart.component';
import { ScopeBadgeComponent } from '../app/shared/scope-badge/scope-badge.component';
import { ScopeMatrixComponent } from '../app/shared/scope-matrix/scope-matrix.component';
import { VulnAliasesComponent } from '../app/shared/vuln-aliases/vuln-aliases.component';

declare global {
  interface Window {
    /** Set before loading the bundle; module scripts cannot read their own data attributes. */
    BOMHORT_API_URL?: string;
  }
}
const apiBase = window.BOMHORT_API_URL ?? '/api/v1';

const elements: [string, unknown][] = [
  ['bomhort-donut-chart', DonutChartComponent],
  ['bomhort-bar-chart', HorizontalBarChartComponent],
  ['bomhort-scope-badge', ScopeBadgeComponent],
  ['bomhort-scope-matrix', ScopeMatrixComponent],
  ['bomhort-vuln-aliases', VulnAliasesComponent],
  // Every app route (dashboard, projects, SBOMs, vulnerabilities, licenses, search …) via one element.
  ['bomhort-page', PageComponent],
];

createApplication({
  providers: [
    provideHttpClient(),
    provideRouter(routes),
    { provide: LocationStrategy, useClass: MemoryLocationStrategy },
    { provide: API_BASE_URL, useValue: apiBase },
  ],
}).then((app) => {
  for (const [tag, component] of elements) {
    if (!customElements.get(tag)) {
      customElements.define(
        tag,
        createCustomElement(component as never, { injector: app.injector }),
      );
    }
  }
});
