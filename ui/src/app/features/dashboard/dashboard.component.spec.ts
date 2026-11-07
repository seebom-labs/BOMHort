import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of, Subject } from 'rxjs';
import { vi } from 'vitest';
import { ApiService } from '../../core/api.service';
import { ClusterListItem, DashboardStats } from '../../core/api.models';
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

  it('filters the stats by the selected cluster', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getClusters').mockReturnValue(of([{ name: '' }, { name: 'prod-eu' }] as unknown as ClusterListItem[]));
    const stats = vi.spyOn(api, 'getDashboardStats').mockReturnValue(of({ license_breakdown: {} } as unknown as DashboardStats));
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    const select = fixture.nativeElement.querySelector('.cluster-filter select') as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(['', 'prod-eu']);
    select.value = 'prod-eu';
    select.dispatchEvent(new Event('change'));
    expect(stats).toHaveBeenLastCalledWith({ cluster: 'prod-eu' });
  });

  it('drops a stale stats response when the cluster changes', () => {
    const api = TestBed.inject(ApiService);
    const slow = new Subject<DashboardStats>();
    vi.spyOn(api, 'getDashboardStats')
      .mockReturnValueOnce(slow)
      .mockReturnValue(of({ total_sboms: 2, license_breakdown: {} } as unknown as DashboardStats));
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    fixture.componentInstance.setCluster('prod-eu');
    slow.next({ total_sboms: 99, license_breakdown: {} } as unknown as DashboardStats);
    expect(fixture.componentInstance.stats?.total_sboms).toBe(2);
  });

  it('renders compromised packages count in kpi tile', () => {
    const api = TestBed.inject(ApiService);
    vi.spyOn(api, 'getDashboardStats').mockReturnValue(of({
      total_sboms: 1, total_packages: 10, total_vulnerabilities: 2,
      effective_vulnerabilities: 2, suppressed_by_vex: 0,
      critical_vulns: 1, high_vulns: 0, medium_vulns: 0, low_vulns: 0,
      exempted_packages: 0, total_vex_statements: 0,
      compromised_packages: 3,
      license_breakdown: {},
    } as unknown as DashboardStats));
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    const cards = fixture.nativeElement.querySelectorAll('.kpi-card');
    const lastCard = cards[cards.length - 1];
    expect(lastCard.textContent).toContain('3');
    expect(lastCard.textContent).toContain('Compromised Packages');
    expect(lastCard.classList.contains('warn')).toBe(true);
  });
});
