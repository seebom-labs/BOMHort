import { ComponentFixture, TestBed } from '@angular/core/testing';
import { GlobalSearchResultsComponent } from './global-search-results.component';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter, Router, ActivatedRoute } from '@angular/router';
import { BehaviorSubject } from 'rxjs';

describe('GlobalSearchResultsComponent', () => {
  let component: GlobalSearchResultsComponent;
  let fixture: ComponentFixture<GlobalSearchResultsComponent>;
  let httpMock: HttpTestingController;
  let queryParamsSubj: BehaviorSubject<any>;

  beforeEach(async () => {
    queryParamsSubj = new BehaviorSubject({ get: (k: string) => null });

    await TestBed.configureTestingModule({
      imports: [GlobalSearchResultsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            queryParamMap: queryParamsSubj.asObservable()
          }
        }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(GlobalSearchResultsComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create and handle empty query', () => {
    expect(component).toBeTruthy();
    expect(component.query).toBe('');
    expect(component.data).toBeNull();
  });

  it('should fetch results when queryParam changes', () => {
    queryParamsSubj.next({ get: (k: string) => k === 'q' ? 'grpc' : null });
    
    const req = httpMock.expectOne('/api/v1/search?q=grpc&limit=50');
    expect(req.request.method).toBe('GET');
    req.flush({
      query: 'grpc',
      packages: [{ package_name: 'grpc', purl: 'purl', project_count: 5 }],
      total_packages: 1,
      projects: [],
      total_projects: 0,
      vulnerabilities: [],
      total_vulnerabilities: 0,
      licenses: [],
      total_licenses: 0
    });
    
    fixture.detectChanges();
    expect(component.data).toBeTruthy();
    expect(component.data!.total_packages).toBe(1);
    expect(component.isAllEmpty()).toBe(false);
  });

  it('should return true for isAllEmpty when no results', () => {
    queryParamsSubj.next({ get: (k: string) => k === 'q' ? 'empty' : null });
    
    const req = httpMock.expectOne('/api/v1/search?q=empty&limit=50');
    req.flush({
      query: 'empty',
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
    expect(component.isAllEmpty()).toBe(true);
  });
});
