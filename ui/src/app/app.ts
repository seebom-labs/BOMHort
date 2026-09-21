import { Component, OnInit } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { CommonModule } from '@angular/common';
import { SiteConfigService } from './core/site-config.service';
import { ApiService } from './core/api.service';
import { GlobalSearchComponent } from './shared/global-search/global-search.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive, GlobalSearchComponent],
  template: `
    <nav class="navbar">
      <a class="brand" routerLink="/">
        <img src="assets/bomhort-mascot.png" alt="BOMHort dragon mascot" class="brand-logo">
        {{ siteConfig.brandName }}
      </a>
      <div class="nav-links">
        <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{exact: true}">Dashboard</a>
        <a routerLink="/fleet" routerLinkActive="active" *ngIf="hasFleet">Fleet</a>
        <a routerLink="/projects" routerLinkActive="active">Projects</a>
        <a routerLink="/sboms" routerLinkActive="active">SBOMs</a>
        <a routerLink="/vulnerabilities" routerLinkActive="active">Vulnerabilities</a>
        <a routerLink="/cve-impact" routerLinkActive="active">CVE Impact</a>
        <a routerLink="/licenses" routerLinkActive="active">Licenses</a>
        <a routerLink="/license-compliance" routerLinkActive="active">Compliance</a>
        <a routerLink="/dependencies" routerLinkActive="active">Dependencies</a>
        <a routerLink="/package-search" routerLinkActive="active">Pkg Search</a>
        <a routerLink="/version-skew" routerLinkActive="active">Version Skew</a>
      </div>
      <app-global-search></app-global-search>
      <button class="theme-toggle" (click)="toggleTheme()" [title]="dark ? 'Light mode' : 'Dark mode'">
        {{ dark ? '☀' : '☾' }}
      </button>
    </nav>
    <main class="content">
      <router-outlet />
    </main>
  `,
  styles: [`
    :host { display: flex; flex-direction: column; height: 100vh; }
    .navbar {
      display: flex;
      align-items: center;
      padding: 0 20px;
      height: 48px;
      background: var(--nav-bg);
      color: #fff;
      gap: 28px;
      flex-shrink: 0;
    }
    .brand {
      color: var(--nav-brand);
      text-decoration: none;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .brand-logo {
      width: 28px;
      height: 28px;
      /* The mascot is portrait (381x427); contain keeps it from being
         squashed into the square box. */
      object-fit: contain;
    }
    .nav-links { display: flex; gap: 2px; flex: 1; }
    .nav-links a {
      color: var(--nav-link);
      text-decoration: none;
      padding: 6px 10px;
      border-radius: 3px;
      font-size: 0.8rem;
      font-weight: 500;
      transition: color 0.15s, background 0.15s;
    }
    .nav-links a:hover { color: var(--nav-link-hover); background: rgba(255,255,255,0.08); }
    .nav-links a.active { color: #fff; background: var(--nav-link-active-bg); }
    .theme-toggle {
      background: none;
      border: 1px solid rgba(255,255,255,0.15);
      color: #d0d0d0;
      width: 32px;
      height: 32px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s, color 0.15s;
      flex-shrink: 0;
    }
    .theme-toggle:hover { background: rgba(255,255,255,0.1); color: #fff; }
    .content { flex: 1; overflow: auto; background: var(--bg); }
    @media (max-width: 1000px) {
      app-global-search { display: none; }
    }
  `],
})
export class App implements OnInit {
  dark = false;

  /**
   * Whether this instance has any deployment (cluster) semantics at all.
   *
   * The Fleet view answers "where does this workload run?" — a question a
   * catalogue instance (a foundation publishing SBOMs for its projects) can
   * never answer, because nothing runs anywhere. Such an instance reports a
   * single cluster with an empty name, and the Fleet tab would be a dead link
   * onto an unnamed root node.
   *
   * Derived from the data rather than configured, so the same image serves
   * both modes and the tab appears by itself as soon as the first cluster
   * label is ingested. Defaults to hidden: showing it only once the data
   * justifies it is better than flashing a tab that then disappears.
   */
  hasFleet = false;

  constructor(
    readonly siteConfig: SiteConfigService,
    private readonly api: ApiService,
  ) {}

  ngOnInit(): void {
    const saved = localStorage.getItem('bomhort-theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      this.dark = true;
      document.documentElement.setAttribute('data-theme', 'dark');
    }

    // A named cluster is what makes the fleet hierarchy meaningful; the
    // unnamed '' bucket is where unassigned SBOMs land and does not count.
    // An API error leaves the tab hidden rather than showing a link that
    // cannot work.
    this.api.getClusters().subscribe({
      next: (clusters) => {
        this.hasFleet = clusters.some((c) => c.name !== '');
      },
      error: () => {
        this.hasFleet = false;
      },
    });
  }

  toggleTheme(): void {
    this.dark = !this.dark;
    if (this.dark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('bomhort-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('bomhort-theme', 'light');
    }
  }
}
