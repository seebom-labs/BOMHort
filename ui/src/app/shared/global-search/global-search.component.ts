import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, HostListener, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink, Router, Params } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { GlobalSearchResponse } from '../../core/api.models';

interface SearchResultItem {
  type: 'package' | 'project' | 'vulnerability' | 'license';
  label: string;
  sublabel: string;
  link: string[];
  queryParams?: Params;
  severity?: string;
  category?: string;
}

@Component({
  selector: 'app-global-search',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="search-container">
      <input
        type="text"
        [(ngModel)]="searchQuery"
        (ngModelChange)="onSearchChange($event)"
        (keydown)="onKeyDown($event)"
        (focus)="onFocus()"
        placeholder="Search packages, projects, CVEs..."
        class="search-input"
        autocomplete="off"
        spellcheck="false"
      />
      
      <div class="dropdown-panel" *ngIf="showDropdown">
        <div class="loading" *ngIf="loading">Searching...</div>
        
        <ng-container *ngIf="!loading && data">
          <div class="empty-state" *ngIf="flatItems.length === 0">
            No results found for "{{ searchQuery }}"
          </div>

          <div class="results-list" *ngIf="flatItems.length > 0">
            <!-- Packages -->
            <div class="section" *ngIf="data.packages.length > 0">
              <div class="section-header">
                Packages
                <span class="section-count" *ngIf="data.total_packages > data.packages.length">
                  {{ data.total_packages }} total
                </span>
              </div>
              <a class="result-item"
                 *ngFor="let pkg of data.packages"
                 [routerLink]="['/package-search', pkg.package_name]"
                 [class.active]="activeItem === pkg.package_name"
                 (click)="closeDropdown()">
                <span class="item-label">{{ pkg.package_name }}</span>
                <span class="item-sublabel">{{ pkg.project_count }} projects</span>
              </a>
            </div>

            <!-- Projects -->
            <div class="section" *ngIf="data.projects.length > 0">
              <div class="section-header">
                Projects
                <span class="section-count" *ngIf="data.total_projects > data.projects.length">
                  {{ data.total_projects }} total
                </span>
              </div>
              <a class="result-item"
                 *ngFor="let proj of data.projects"
                 [routerLink]="['/sboms', proj.latest_sbom_id]"
                 [class.active]="activeItem === proj.project_name"
                 (click)="closeDropdown()">
                <span class="item-label">{{ proj.project_name }}</span>
                <span class="item-sublabel">{{ proj.sbom_count }} sboms</span>
              </a>
            </div>

            <!-- Vulnerabilities -->
            <div class="section" *ngIf="data.vulnerabilities.length > 0">
              <div class="section-header">
                Vulnerabilities
                <span class="section-count" *ngIf="data.total_vulnerabilities > data.vulnerabilities.length">
                  {{ data.total_vulnerabilities }} total
                </span>
              </div>
              <a class="result-item"
                 *ngFor="let vuln of data.vulnerabilities"
                 [routerLink]="['/cve-impact']"
                 [queryParams]="{ cve: vuln.vuln_id }"
                 [class.active]="activeItem === vuln.vuln_id"
                 (click)="closeDropdown()">
                <div class="item-label">
                  <span class="severity-badge" [ngClass]="'severity-' + vuln.severity.toLowerCase()">
                    {{ vuln.severity }}
                  </span>
                  {{ vuln.vuln_id }}
                </div>
                <span class="item-sublabel">{{ vuln.affected_sboms }} sboms affected</span>
              </a>
            </div>

            <!-- Licenses -->
            <div class="section" *ngIf="data.licenses.length > 0">
              <div class="section-header">
                Licenses
                <span class="section-count" *ngIf="data.total_licenses > data.licenses.length">
                  {{ data.total_licenses }} total
                </span>
              </div>
              <a class="result-item"
                 *ngFor="let lic of data.licenses"
                 [routerLink]="['/licenses']"
                 [class.active]="activeItem === lic.license_id"
                 (click)="closeDropdown()">
                <div class="item-label">
                  <span class="license-cat" [ngClass]="'license-' + lic.category.toLowerCase()"></span>
                  {{ lic.license_id }}
                </div>
                <span class="item-sublabel">{{ lic.sbom_count }} sboms</span>
              </a>
            </div>
          </div>
          
          <div class="dropdown-footer" (click)="goToFullResults()">
            See all results for "{{ searchQuery }}" &rarr;
          </div>
        </ng-container>
      </div>
    </div>
  `,
  styles: [`
    .search-container {
      position: relative;
      width: 300px;
      max-width: 100%;
    }
    .search-input {
      width: 100%;
      padding: 6px 12px;
      font-size: 0.85rem;
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 4px;
      background: rgba(0,0,0,0.2);
      color: var(--nav-link-hover);
      outline: none;
      transition: all 0.2s;
    }
    .search-input:focus {
      border-color: var(--nav-link-hover);
      background: rgba(0,0,0,0.3);
    }
    .search-input::placeholder { color: var(--nav-link); }
    
    .dropdown-panel {
      position: absolute;
      top: 100%;
      left: 0;
      right: 0;
      margin-top: 4px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 1000;
      max-height: 400px;
      overflow-y: auto;
      color: var(--text);
    }
    
    .loading, .empty-state {
      padding: 16px;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    
    .section {
      padding-bottom: 4px;
    }
    .section-header {
      padding: 8px 12px 4px;
      font-size: 0.7rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .section-count {
      font-size: 0.65rem;
      font-weight: normal;
      text-transform: none;
      letter-spacing: normal;
    }
    
    .result-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 12px;
      text-decoration: none;
      color: var(--text);
      font-size: 0.85rem;
      transition: background 0.1s;
    }
    .result-item:hover, .result-item.active {
      background: var(--surface-alt);
    }
    .item-label {
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .item-sublabel {
      color: var(--text-muted);
      font-size: 0.75rem;
      flex-shrink: 0;
      margin-left: 8px;
    }
    
    .severity-badge {
      font-size: 0.65rem;
      font-weight: 700;
      padding: 1px 4px;
      border-radius: 2px;
      text-transform: uppercase;
    }
    .severity-critical { background: var(--severity-critical-bg); color: var(--severity-critical); border: 1px solid var(--severity-critical); }
    .severity-high { background: var(--severity-high-bg); color: var(--severity-high); border: 1px solid var(--severity-high); }
    .severity-medium { background: var(--severity-medium-bg); color: var(--severity-medium); border: 1px solid var(--severity-medium); }
    .severity-low { background: var(--severity-low-bg); color: var(--severity-low); border: 1px solid var(--severity-low); }
    
    .license-cat {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }
    .license-permissive { background: var(--license-permissive); }
    .license-copyleft { background: var(--license-copyleft); }
    .license-unknown { background: var(--license-unknown); }
    
    .dropdown-footer {
      padding: 8px 12px;
      border-top: 1px solid var(--border);
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--accent);
      text-align: center;
      cursor: pointer;
      background: var(--surface-alt);
      border-radius: 0 0 6px 6px;
    }
    .dropdown-footer:hover {
      text-decoration: underline;
    }
    
    @media (max-width: 600px) {
      .search-container { width: 200px; }
    }
    @media (max-width: 400px) {
      .search-container { width: 140px; }
    }
  `]
})
export class GlobalSearchComponent implements OnInit {
  searchQuery = '';
  data: GlobalSearchResponse | null = null;
  loading = false;
  showDropdown = false;
  
  flatItems: SearchResultItem[] = [];
  activeItem: string | null = null;
  activeIndex = -1;
  
  private searchSubject = new Subject<string>();

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
    private readonly eRef: ElementRef,
    private readonly router: Router
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged()
    ).subscribe(query => {
      this.doSearch(query);
    });
  }

  onSearchChange(value: string): void {
    this.searchSubject.next(value);
  }

  onFocus(): void {
    if (this.searchQuery.length >= 2) {
      this.showDropdown = true;
      if (!this.data && !this.loading) {
        this.searchSubject.next(this.searchQuery);
      }
    }
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: Event): void {
    if (!this.eRef.nativeElement.contains(event.target)) {
      this.showDropdown = false;
      this.cdr.markForCheck();
    }
  }

  closeDropdown(): void {
    this.showDropdown = false;
  }

  goToFullResults(): void {
    this.closeDropdown();
    this.router.navigate(['/search'], { queryParams: { q: this.searchQuery } });
  }

  onKeyDown(event: KeyboardEvent): void {
    if (!this.showDropdown && event.key !== 'Enter') return;

    if (event.key === 'ArrowDown') {
      event.preventDefault();
      this.moveSelection(1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      this.moveSelection(-1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (this.activeIndex >= 0 && this.activeIndex < this.flatItems.length) {
        const item = this.flatItems[this.activeIndex];
        this.closeDropdown();
        if (item.queryParams) {
          this.router.navigate(item.link, { queryParams: item.queryParams });
        } else {
          this.router.navigate(item.link);
        }
      } else if (this.searchQuery.length >= 2) {
        this.goToFullResults();
      }
    } else if (event.key === 'Escape') {
      this.closeDropdown();
      const input = this.eRef.nativeElement.querySelector('input');
      if (input) input.blur();
    }
  }

  private moveSelection(delta: number): void {
    if (this.flatItems.length === 0) return;
    this.activeIndex += delta;
    if (this.activeIndex < 0) this.activeIndex = this.flatItems.length - 1;
    if (this.activeIndex >= this.flatItems.length) this.activeIndex = 0;
    
    this.activeItem = this.flatItems[this.activeIndex].label;
  }

  private buildFlatItems(): void {
    this.flatItems = [];
    if (!this.data) return;
    
    for (const pkg of this.data.packages) {
      this.flatItems.push({ type: 'package', label: pkg.package_name, sublabel: '', link: ['/package-search', pkg.package_name] });
    }
    for (const proj of this.data.projects) {
      this.flatItems.push({ type: 'project', label: proj.project_name, sublabel: '', link: ['/sboms', proj.latest_sbom_id] });
    }
    for (const vuln of this.data.vulnerabilities) {
      this.flatItems.push({ type: 'vulnerability', label: vuln.vuln_id, sublabel: '', link: ['/cve-impact'], queryParams: { cve: vuln.vuln_id } });
    }
    for (const lic of this.data.licenses) {
      this.flatItems.push({ type: 'license', label: lic.license_id, sublabel: '', link: ['/licenses'] });
    }
    this.activeIndex = -1;
    this.activeItem = null;
  }

  private doSearch(query: string): void {
    if (!query || query.length < 2) {
      this.data = null;
      this.loading = false;
      this.showDropdown = false;
      this.flatItems = [];
      this.cdr.markForCheck();
      return;
    }
    this.loading = true;
    this.showDropdown = true;
    this.cdr.markForCheck();

    this.api.globalSearch(query, 5).subscribe({
      next: (resp) => {
        if (this.searchQuery === query) {
          this.data = resp;
          this.loading = false;
          this.buildFlatItems();
          this.cdr.markForCheck();
        }
      },
      error: () => {
        if (this.searchQuery === query) {
          this.data = null;
          this.loading = false;
          this.flatItems = [];
          this.cdr.markForCheck();
        }
      }
    });
  }
}
