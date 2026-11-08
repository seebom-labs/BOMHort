import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, it, expect, beforeEach } from 'vitest';
import { ExtraFieldsComponent, extraFieldList } from './extra-fields.component';

describe('ExtraFieldsComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ExtraFieldsComponent],
      providers: [provideRouter([])],
    }).compileComponents();
  });

  it('extraFieldList sorts by name and drops fields without values', () => {
    expect(extraFieldList(null)).toEqual([]);
    expect(extraFieldList({ b: ['2'], a: ['1'], none: [] })).toEqual([
      { name: 'a', values: ['1'] },
      { name: 'b', values: ['2'] },
    ]);
  });

  it('renders nothing for an empty list', () => {
    const fixture = TestBed.createComponent(ExtraFieldsComponent);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.extra-fields')).toBeNull();
  });

  it('keeps untrusted values as text and links out only http(s)', () => {
    const fixture = TestBed.createComponent(ExtraFieldsComponent);
    fixture.componentRef.setInput('fields', extraFieldList({
      owner_contact: ['<b>x</b>'],
      runbook: ['https://wiki.example.com', 'javascript:alert(1)'],
    }));
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.extra-fields b')).toBeNull();
    expect(el.querySelector('.extra-filter')?.textContent?.trim()).toBe('<b>x</b>');
    const out = [...el.querySelectorAll('.extra-out')].map((a) => a.getAttribute('href'));
    expect(out).toEqual(['https://wiki.example.com']);
  });
});
