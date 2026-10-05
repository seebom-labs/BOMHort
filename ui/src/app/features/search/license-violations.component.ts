import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import { ProjectLicenseViolation, LicenseExceptionsFile } from '../../core/api.models';
import { forkJoin } from 'rxjs';

type Tab = 'non-compliant' | 'exceptions';

@Component({
  selector: 'app-license-violations',
  standalone: true,
  imports: [CommonModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="violations-page">
      <h1>License Compliance</h1>
      <p class="subtitle">Non-compliant licenses filtered by configured exceptions. Exceptions are managed via <code>license-exceptions.json</code>.</p>
      <p *ngIf="loadError" role="alert" class="load-error">{{ loadError }}</p>

      <div class="tabs">
        <button [class.active]="activeTab === 'non-compliant'" (click)="activeTab = 'non-compliant'">
          Non-Compliant ({{ violations.length | number }})
        </button>
        <button [class.active]="activeTab === 'exceptions'" (click)="activeTab = 'exceptions'">
          Configured Exceptions ({{ totalExceptions | number }})
        </button>
      </div>

      <!-- Non-Compliant Tab -->
      <div *ngIf="activeTab === 'non-compliant'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="80" class="viewport">
          <div *cdkVirtualFor="let v of violations; trackBy: trackByViolation" class="violation-card">
            <div class="project-header">
              <a [routerLink]="['/sboms', v.sbom_id]" class="project-name">{{ v.document_name || v.source_file }}</a>
              <div class="counts">
                <span class="copyleft-badge" *ngIf="v.copyleft_count">{{ v.copyleft_count | number }} copyleft</span>
                <span class="unapproved-badge" *ngIf="v.unapproved_count">{{ v.unapproved_count | number }} not approved</span>
                <span class="unknown-badge" *ngIf="v.unknown_count">{{ v.unknown_count | number }} unknown</span>
              </div>
            </div>
            <div class="details">
              <span class="licenses">{{ v.violating_licenses.join(', ') }}</span>
              <span class="pkgs" *ngIf="v.non_compliant_packages.length">
                ({{ v.non_compliant_packages.length | number }} packages)
              </span>
            </div>
          </div>
        </cdk-virtual-scroll-viewport>
        <p *ngIf="loaded && violations.length === 0" class="empty">
          No non-compliant licenses found in the stored results.
        </p>
      </div>

      <!-- Exceptions Tab (read-only) -->
      <div *ngIf="activeTab === 'exceptions'" class="tab-content">
        <div class="config-hint">
          <span class="hint-icon">ℹ</span>
          Exceptions are loaded from <code>license-exceptions.json</code> in the config volume.
          No exceptions are enabled by default; only approved rules apply.
          Configure <code>licenseExceptions.custom</code> through Helm to roll out API and workers,
          then re-process existing SBOMs. Direct file edits require restarting both services.
        </div>

        <div class="exceptions-section" *ngIf="exceptionsFile.blanketExceptions.length > 0">
          <h2>Blanket Exceptions</h2>
          <p class="section-desc">Approved rules exempt entire licenses for all packages and projects. Pending and revoked rules are inactive.</p>
          <div *ngFor="let be of exceptionsFile.blanketExceptions" class="exception-card blanket">
            <div class="exc-row">
              <span class="exc-license">{{ be.license }}</span>
              <span class="exc-status" [class]="'status-' + be.status">{{ be.status }}</span>
              <span class="exc-date">{{ be.approvedDate }}</span>
            </div>
            <div class="exc-detail" *ngIf="be.scope">Scope: {{ be.scope }}</div>
            <div class="exc-comment" *ngIf="be.comment">{{ be.comment }}</div>
          </div>
        </div>

        <div class="exceptions-section" *ngIf="exceptionsFile.exceptions.length > 0">
          <h2>Package Exceptions</h2>
          <p class="section-desc">Approved package + license rules, optionally restricted to an exact SBOM document name. Scope descriptions are informational.</p>
          <div *ngFor="let exc of exceptionsFile.exceptions" class="exception-card">
            <div class="exc-row">
              <span class="exc-pkg">{{ exc.package }}</span>
              <span class="exc-license">{{ exc.license }}</span>
              <span class="exc-project" *ngIf="exc.project">{{ exc.project }}</span>
              <span class="exc-status" [class]="'status-' + exc.status">{{ exc.status }}</span>
              <span class="exc-date">{{ exc.approvedDate }}</span>
            </div>
            <div class="exc-detail" *ngIf="exc.scope">Scope: {{ exc.scope }}</div>
            <div class="exc-comment" *ngIf="exc.comment">{{ exc.comment }}</div>
          </div>
        </div>

        <p *ngIf="loaded && totalExceptions === 0" class="empty-hint">
          No exceptions configured. Add entries to <code>license-exceptions.json</code> to suppress known non-compliant licenses.
        </p>
      </div>
    </div>
  `,
  styles: [`
    .violations-page { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .subtitle { color: var(--text-secondary); margin: 4px 0 16px; font-size: 0.8rem; }
    .subtitle code { background: var(--bg); padding: 1px 4px; border-radius: 2px; font-size: 0.75rem; }
    .tabs { display: flex; gap: 2px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
    .tabs button {
      padding: 8px 18px; border: none; background: transparent; cursor: pointer;
      font-size: 0.8rem; border-radius: 0; transition: all 0.15s;
      font-family: inherit; color: var(--text-secondary); font-weight: 500;
      border-bottom: 2px solid transparent; margin-bottom: -1px;
    }
    .tabs button.active { color: var(--text); border-bottom-color: var(--accent); }
    .tab-content { flex: 1; min-height: 0; overflow-y: auto; }
    .viewport { height: 100%; min-height: 400px; }
    .violation-card {
      height: 72px; display: flex; flex-direction: column; justify-content: center;
      padding: 0 14px; border-bottom: 1px solid var(--border);
    }
    .project-header { display: flex; align-items: center; gap: 10px; }
    .project-name { font-weight: 600; font-size: 0.9rem; color: var(--accent); text-decoration: none; }
    .counts { display: flex; gap: 6px; }
    .copyleft-badge { background: var(--severity-critical-bg); color: var(--severity-critical); padding: 1px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 600; }
    .unapproved-badge { background: var(--severity-high-bg); color: var(--severity-high); padding: 1px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 600; }
    .unknown-badge { background: var(--bg); color: var(--text-secondary); padding: 1px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 600; }
    .details { margin-top: 3px; font-size: 0.75rem; color: var(--text-secondary); }
    .licenses { font-style: normal; }
    .pkgs { margin-left: 8px; }
    .empty { color: var(--status-success); font-size: 0.9rem; font-weight: 500; }
    .load-error { color: var(--severity-critical); font-size: 0.85rem; }

    .config-hint {
      display: flex; align-items: flex-start; gap: 8px; padding: 10px 14px;
      background: var(--status-info-bg); border: 1px solid #A8DCD8; border-radius: 2px;
      font-size: 0.8rem; color: var(--accent-hover); margin-bottom: 20px;
    }
    .config-hint code { background: #D4EDEB; padding: 1px 4px; border-radius: 2px; font-size: 0.75rem; }
    .hint-icon { font-size: 1rem; }

    .exceptions-section { margin-bottom: 24px; }
    h2 { font-size: 0.95rem; font-weight: 600; margin: 0 0 4px; }
    .section-desc { font-size: 0.75rem; color: var(--text-secondary); margin: 0 0 12px; }
    .empty-hint { font-size: 0.8rem; color: var(--text-muted); }
    .empty-hint code { background: var(--bg); padding: 1px 4px; border-radius: 2px; font-size: 0.75rem; }
    .exception-card {
      padding: 8px 12px; border: 1px solid var(--border); border-radius: 2px; margin-bottom: 6px;
    }
    .exception-card.blanket { border-left: 3px solid var(--accent); }
    .exc-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .exc-license { font-weight: 600; font-size: 0.85rem; }
    .exc-pkg { font-weight: 500; font-size: 0.85rem; color: var(--text); }
    .exc-project { font-size: 0.75rem; color: var(--text-secondary); background: var(--bg); padding: 1px 6px; border-radius: 2px; }
    .exc-status { font-size: 0.65rem; text-transform: uppercase; font-weight: 600; padding: 1px 5px; border-radius: 2px; }
    .status-approved { background: var(--status-success-bg); color: var(--status-success); }
    .status-revoked { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .exc-date { font-size: 0.7rem; color: var(--text-muted); }
    .exc-detail { font-size: 0.72rem; color: var(--text-secondary); margin-top: 3px; }
    .exc-comment { font-size: 0.75rem; color: var(--text-secondary); margin-top: 2px; font-style: italic; }
  `],
})
export class LicenseViolationsComponent implements OnInit {
  violations: ProjectLicenseViolation[] = [];
  exceptionsFile: LicenseExceptionsFile = {
    version: '1.0.0', lastUpdated: '', blanketExceptions: [], exceptions: [],
  };
  loaded = false;
  loadError = '';
  activeTab: Tab = 'non-compliant';

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    forkJoin({
      violations: this.api.getProjectsWithLicenseViolations(),
      exceptions: this.api.getLicenseExceptions(),
    }).subscribe({
      next: ({ violations, exceptions }) => {
        this.violations = violations;
        this.exceptionsFile = exceptions;
        this.loaded = true;
        this.cdr.markForCheck();
      },
      error: () => {
        this.loadError = 'Could not load license compliance. Check API availability and the license exceptions configuration; invalid files are rejected.';
        this.cdr.markForCheck();
      },
    });
  }

  get totalExceptions(): number {
    return this.exceptionsFile.blanketExceptions.length + this.exceptionsFile.exceptions.length;
  }

  trackByViolation(_i: number, v: ProjectLicenseViolation): string { return v.sbom_id; }
}

