import { Component, OnInit } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { SiteConfigService } from './core/site-config.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <nav class="navbar">
      <a class="brand" routerLink="/">
        <img src="assets/logo.webp" alt="SeeBOM" class="brand-logo">
        {{ siteConfig.brandName }}
      </a>
      <div class="nav-links">
        <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{exact: true}">Dashboard</a>
        <a routerLink="/sboms" routerLinkActive="active">SBOMs</a>
        <a routerLink="/vulnerabilities" routerLinkActive="active">Vulnerabilities</a>
        <a routerLink="/cve-impact" routerLinkActive="active">CVE Impact</a>
        <a routerLink="/licenses" routerLinkActive="active">Licenses</a>
        <a routerLink="/license-compliance" routerLinkActive="active">Compliance</a>
        <a routerLink="/dependencies" routerLinkActive="active">Dependencies</a>
        <a routerLink="/package-search" routerLinkActive="active">Pkg Search</a>
        <a routerLink="/version-skew" routerLinkActive="active">Version Skew</a>
        <a routerLink="/vex" routerLinkActive="active">VEX</a>
      </div>
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
      border-radius: 4px;
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
  `],
})
export class App implements OnInit {
  dark = false;

  constructor(readonly siteConfig: SiteConfigService) {}

  ngOnInit(): void {
    const saved = localStorage.getItem('seebom-theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      this.dark = true;
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  }

  toggleTheme(): void {
    this.dark = !this.dark;
    if (this.dark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('seebom-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('seebom-theme', 'light');
    }
  }
}
