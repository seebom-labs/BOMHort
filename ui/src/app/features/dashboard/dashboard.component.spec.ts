import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { vi } from 'vitest';
import { ApiService } from '../../core/api.service';
import { DashboardStats } from '../../core/api.models';
import { DashboardComponent } from './dashboard.component';

describe('DashboardComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(DashboardComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should show loading initially', () => {
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.loading-state')?.textContent).toContain('Loading');
  });

  it('shows not-approved licenses as their own chart segment', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getDashboardStats').mockReturnValue(of({
      critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0,
      exempted_packages: 1,
      license_breakdown: { permissive: 10, copyleft: 2, unapproved: 3, unknown: 4 },
    } as unknown as DashboardStats));
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    const segments = fixture.componentInstance.licenseSegments;
    expect(segments.map((x) => x.label)).toEqual(['Permissive', 'Copyleft', 'Not Approved', 'Exempted', 'Unknown']);
    expect(segments.find((x) => x.label === 'Not Approved')?.value).toBe(3);
    expect(segments.find((x) => x.label === 'Unknown')?.value).toBe(4);
  });
});
