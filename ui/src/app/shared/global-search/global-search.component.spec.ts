import { ComponentFixture, TestBed } from '@angular/core/testing';
import { GlobalSearchComponent } from './global-search.component';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

describe('GlobalSearchComponent', () => {
  let component: GlobalSearchComponent;
  let fixture: ComponentFixture<GlobalSearchComponent>;
  let httpMock: HttpTestingController;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GlobalSearchComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([])
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(GlobalSearchComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not search if query < 2 chars', async () => {
    component.searchQuery = 'a';
    component.onSearchChange('a');
    await new Promise((resolve) => setTimeout(resolve, 350));
    expect(component.data).toBeNull();
  });

  it('should call api after debounce and 2+ chars', async () => {
    component.searchQuery = 'gr';
    component.onSearchChange('gr');
    await new Promise((resolve) => setTimeout(resolve, 350));
    
    const req = httpMock.expectOne('/api/v1/search?q=gr&limit=5');
    expect(req.request.method).toBe('GET');
    req.flush({
      query: 'gr',
      packages: [],
      total_packages: 0,
      projects: [],
      total_projects: 0,
      vulnerabilities: [],
      total_vulnerabilities: 0,
      licenses: [],
      total_licenses: 0
    });
    
    fixture.detectChanges();
    expect(component.data).toBeTruthy();
  });

  it('should close dropdown on escape', () => {
    component.showDropdown = true;
    component.onKeyDown(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(component.showDropdown).toBe(false);
  });

  it('should navigate to search results on enter without active item', () => {
    const navigateSpy = vi.spyOn(router, 'navigate');
    component.searchQuery = 'grpc';
    component.showDropdown = true;
    component.activeIndex = -1;
    
    component.onKeyDown(new KeyboardEvent('keydown', { key: 'Enter' }));
    expect(navigateSpy).toHaveBeenCalledWith(['/search'], { queryParams: { q: 'grpc' } });
  });
});
