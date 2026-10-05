import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { vi } from 'vitest';
import { CdkVirtualScrollViewport } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import { LicenseViolationsComponent } from './license-violations.component';

describe('LicenseViolationsComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LicenseViolationsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should have page title', () => {
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('License Compliance');
  });

  it('should default to non-compliant tab', () => {
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    const component = fixture.componentInstance;
    expect(component.activeTab).toBe('non-compliant');
  });

  it('should display empty defaults without claiming all packages are exempt', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getProjectsWithLicenseViolations').mockReturnValue(of([]));
    vi.spyOn(api, 'getLicenseExceptions').mockReturnValue(of({
      version: '1.0.0', lastUpdated: '', blanketExceptions: [], exceptions: [],
    }));
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    fixture.detectChanges();
    const element = fixture.nativeElement as HTMLElement;
    expect(element.textContent).toContain('Configured Exceptions (0)');
    expect(element.textContent).not.toContain('All items are covered by exceptions');
    const button = element.querySelectorAll('button')[1] as HTMLButtonElement;
    button.click();
    fixture.detectChanges();
    expect(element.textContent).toContain('No exceptions configured');
    expect(element.textContent).toContain('only approved rules apply');
    expect(element.textContent).toContain('re-process existing SBOMs');
  });

  it('should describe pending and revoked entries as configured, not active', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getProjectsWithLicenseViolations').mockReturnValue(of([]));
    vi.spyOn(api, 'getLicenseExceptions').mockReturnValue(of({
      version: '1.0.0', lastUpdated: '', blanketExceptions: [],
      exceptions: ['pending', 'revoked'].map(status => ({
        id: status, package: 'example.org/library', license: 'MPL-2.0',
        status, approvedDate: '',
      })),
    }));
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent;
    expect(text).toContain('Configured Exceptions (2)');
    expect(text).not.toContain('Active Exceptions');
  });

  it('should show configuration errors instead of an empty-success message', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getProjectsWithLicenseViolations').mockReturnValue(of([]));
    vi.spyOn(api, 'getLicenseExceptions').mockReturnValue(throwError(() => new Error('Invalid configuration')));
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    fixture.componentInstance.activeTab = 'exceptions';
    fixture.detectChanges();
    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('[role="alert"]')?.textContent).toContain('invalid files are rejected');
    expect(element.textContent).not.toContain('No exceptions configured');
    expect(fixture.componentInstance.loaded).toBe(false);
  });

  it('shows a not-approved badge next to copyleft and unknown counts', async () => {
    // jsdom has no layout, so the virtual viewport would render zero rows.
    vi.spyOn(CdkVirtualScrollViewport.prototype, 'getViewportSize').mockReturnValue(2000);
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getProjectsWithLicenseViolations').mockReturnValue(of([
      {
        sbom_id: '00000000-0000-0000-0000-000000000001', source_file: 'a.spdx.json', document_name: 'a',
        copyleft_count: 1, unapproved_count: 2, unknown_count: 0,
        violating_licenses: ['GPL-3.0-only', 'LicenseRef-Custom'], non_compliant_packages: ['x', 'y', 'z'],
      },
      {
        sbom_id: '00000000-0000-0000-0000-000000000002', source_file: 'b.spdx.json', document_name: 'b',
        copyleft_count: 1, unapproved_count: 0, unknown_count: 0,
        violating_licenses: ['GPL-3.0-only'], non_compliant_packages: ['x'],
      },
    ]));
    vi.spyOn(api, 'getLicenseExceptions').mockReturnValue(of({
      version: '1.0.0', lastUpdated: '', blanketExceptions: [], exceptions: [],
    }));
    const fixture = TestBed.createComponent(LicenseViolationsComponent);
    fixture.autoDetectChanges();
    await fixture.whenStable();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await fixture.whenStable();
    const element = fixture.nativeElement as HTMLElement;
    const badges = element.querySelectorAll('.unapproved-badge');
    expect(element.querySelectorAll('.violation-card').length).toBe(2);
    expect(badges.length).toBe(1);
    expect(badges[0].textContent).toContain('2 not approved');
  });
});
