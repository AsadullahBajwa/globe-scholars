import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Menu } from './menu';
import { provideZonelessChangeDetection } from '@angular/core';
import { RouterTestingModule } from '@angular/router/testing';
import { LandingPage } from '../../external/landing-page/landing-page';
import { Login } from '../../external/login/login';
import { AboutComponent } from '../../external/about-component/about-component';
import { ScholarsComponent } from '../../internal/scholars-component/scholars-component';
import { RepositoryComponent } from '../../internal/repository-component/repository-component';
import { Register } from '../../external/register/register';
import { Router } from '@angular/router';

describe('Menu', () => {
  let component: Menu;
  let fixture: ComponentFixture<Menu>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Menu, RouterTestingModule.withRoutes([
        { path: '', component: LandingPage },
        { path: 'register', component: Register },
        { path: 'login', component: Login },
        { path: 'about', component: AboutComponent },
        { path: 'scholars', component: ScholarsComponent },
        { path: 'repository', component: RepositoryComponent },
      ]),
      ],
      providers: [provideZonelessChangeDetection()]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Menu);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should have a logo', () => {
    fixture.detectChanges();
    const logo = fixture.nativeElement.querySelector('.logo');
    expect(logo).toBeTruthy();
  });

  it('should have a menu', () => {
    fixture.detectChanges();
    const menu = fixture.nativeElement.querySelector('.menu');
    expect(menu).toBeTruthy();
  });

  it('Home link should navigate to landing page', async () => {
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    fixture.nativeElement.querySelector('a[routerLink="/"]').click();
    await fixture.whenStable();
    expect(router.url).toEqual('/');
  });

  it('About link should navigate to about page', async () => {
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    fixture.nativeElement.querySelector('a[routerLink="/about"]').click();
    await fixture.whenStable();
    expect(router.url).toEqual('/about');
  });

  it('Scholars link should navigate to scholars page', async () => {
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    fixture.nativeElement.querySelector('a[routerLink="/scholars"]').click();
    await fixture.whenStable();
    expect(router.url).toEqual('/scholars');
  });

  it('Repository link should navigate to repository page', async () => {
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    fixture.nativeElement.querySelector('a[routerLink="/repository"]').click();
    await fixture.whenStable();
    expect(router.url).toEqual('/repository');
  });

  it('Login link should navigate to login page', async () => {
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    fixture.nativeElement.querySelector('a[routerLink="/login"]').click();
    await fixture.whenStable();
    expect(router.url).toEqual('/login');
  });
});
