import {
  Component,
  EventEmitter,
  Injectable,
  Input,
  OnChanges,
  OnDestroy,
  OnInit,
  Output,
} from '@angular/core';
import { LocationStrategy } from '@angular/common';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { Subscription, filter } from 'rxjs';

/**
 * Keeps the router's URL in memory instead of the browser's address bar, so an
 * embedded BOMHort page never fights the host application's own routing.
 */
@Injectable()
export class MemoryLocationStrategy extends LocationStrategy {
  private url = '/';
  path(): string {
    return this.url;
  }
  prepareExternalUrl(internal: string): string {
    return internal;
  }
  getState(): unknown {
    return null;
  }
  pushState(_state: unknown, _title: string, url: string, queryParams: string): void {
    this.url = url + (queryParams && !queryParams.startsWith('?') ? '?' : '') + queryParams;
  }
  replaceState(state: unknown, title: string, url: string, queryParams: string): void {
    this.pushState(state, title, url, queryParams);
  }
  forward(): void {}
  back(): void {}
  onPopState(): void {}
  getBaseHref(): string {
    return '';
  }
}

/** `<bomhort-page route="/projects/foo">`: any BOMHort route, rendered through the app's own router. */
@Component({
  selector: 'bomhort-page',
  standalone: true,
  imports: [RouterOutlet],
  template: '<router-outlet />',
  styles: [':host { display: block; height: 100%; overflow: auto; background: var(--bg); }'],
})
export class PageComponent implements OnInit, OnChanges, OnDestroy {
  @Input() route = '/';
  @Output() navigate = new EventEmitter<string>();
  private sub?: Subscription;

  constructor(private readonly router: Router) {}

  ngOnInit(): void {
    // shortcut: all elements share one Router, so two pages would swap content together; one app per element when a host needs two
    if (document.querySelectorAll('bomhort-page').length > 1)
      throw new Error('bomhort-page: only one instance per document is supported');
    this.sub = this.router.events
      .pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd))
      .subscribe((e) => this.navigate.emit(e.urlAfterRedirects));
    void this.router.navigateByUrl(this.route || '/');
  }

  ngOnChanges(): void {
    void this.router.navigateByUrl(this.route || '/');
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }
}
