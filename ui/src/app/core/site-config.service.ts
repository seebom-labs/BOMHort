import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Title } from '@angular/platform-browser';

export interface SiteConfig {
  brandName: string;
  pageTitle: string;
  dashboard: {
    title: string;
    subtitle: string;
    description: string;
    disclaimer: string;
  };
  footer: {
    enabled: boolean;
    text: string;
  };
}

const DEFAULTS: SiteConfig = {
  brandName: 'BOMHort',
  pageTitle: 'BOMHort',
  dashboard: {
    title: 'Dashboard',
    subtitle: 'Software Bill of Materials — Governance Overview',
    description:
      '<strong>BOMHort</strong> autonomously ingests SPDX SBOMs from the CNCF ecosystem, cross-references known vulnerabilities via the <a href="https://osv.dev" target="_blank" rel="noopener">OSV database</a>, evaluates license compliance against a configurable policy, and applies <a href="https://openvex.dev" target="_blank" rel="noopener">OpenVEX</a> statements to suppress non-applicable findings — giving you a single pane of glass for software supply-chain governance.',
    disclaimer:
      '<strong>Disclaimer:</strong> The data shown on this dashboard is provided on an "as-is" basis for informational purposes only. Vulnerability and license information is sourced from third-party databases (OSV, GitHub) and may be incomplete or delayed. BOMHort does not guarantee the accuracy, completeness, or timeliness of any data and is not a substitute for professional security audits or legal advice. Use at your own risk.',
  },
  footer: { enabled: false, text: '' },
};

@Injectable({ providedIn: 'root' })
export class SiteConfigService {
  private config: SiteConfig = DEFAULTS;

  constructor(private readonly http: HttpClient, private readonly titleService: Title) {}

  /** Called once via APP_INITIALIZER before the app bootstraps. */
  load(): Promise<void> {
    return firstValueFrom(
      this.http.get<Partial<SiteConfig>>('/ui-config.json', { responseType: 'json' })
    )
      .then((json) => {
        this.config = {
          ...DEFAULTS,
          ...json,
          dashboard: { ...DEFAULTS.dashboard, ...(json.dashboard ?? {}) },
          footer: { ...DEFAULTS.footer, ...(json.footer ?? {}) },
        };
        this.titleService.setTitle(this.config.pageTitle);
      })
      .catch(() => {
        // Config file not mounted / not found → use built-in defaults silently
        this.config = DEFAULTS;
      });
  }

  get brandName(): string {
    return this.config.brandName;
  }

  get pageTitle(): string {
    return this.config.pageTitle;
  }

  get dashboard() {
    return this.config.dashboard;
  }

  get footer() {
    return this.config.footer;
  }
}

