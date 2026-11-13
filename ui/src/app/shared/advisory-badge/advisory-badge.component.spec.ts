import { TestBed } from '@angular/core/testing';
import { describe, expect, it, beforeEach } from 'vitest';
import { AdvisoryBadgeComponent, advisoryStatusLabel } from './advisory-badge.component';

describe('AdvisoryBadgeComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [AdvisoryBadgeComponent] }).compileComponents();
  });

  function render(vuln: AdvisoryBadgeComponent['vuln']): HTMLElement | null {
    const fixture = TestBed.createComponent(AdvisoryBadgeComponent);
    fixture.componentInstance.vuln = vuln;
    fixture.detectChanges();
    return fixture.nativeElement.querySelector('.advisory-badge');
  }

  it('renders nothing for osv.dev findings and older servers', () => {
    expect(render({ advisory_source: 'osv' })).toBeNull();
    expect(render({})).toBeNull();
    expect(render(undefined)).toBeNull();
  });

  it('names the feed, its status and where the file sits', () => {
    const el = render({
      advisory_source: 'wolfi',
      advisory_status: 'pending_upstream_fix',
      advisory_components: [{ location: '/usr/lib/libxml2.so.2', architecture: 'x86_64' }],
    });
    expect(el?.textContent?.trim()).toBe('wolfi · Pending upstream fix');
    expect(el?.classList.contains('advisory-pending_upstream_fix')).toBe(true);
    expect(el?.title).toContain('/usr/lib/libxml2.so.2 (x86_64)');
  });

  it('labels every status of the vocabulary', () => {
    expect(advisoryStatusLabel('fix_not_planned')).toBe('Fix not planned');
    expect(advisoryStatusLabel('under_investigation')).toBe('Under investigation');
    expect(advisoryStatusLabel('not_affected')).toBe('Not affected');
    expect(advisoryStatusLabel('something_new')).toBe('something new');
    expect(advisoryStatusLabel(undefined)).toBe('');
  });
});
