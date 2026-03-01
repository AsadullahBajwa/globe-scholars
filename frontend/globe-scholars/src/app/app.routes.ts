import { Routes } from '@angular/router';
import { LandingPage } from './external/landing-page/landing-page';
import { Register } from './external/register/register';
import { Login } from './external/login/login';
import { AboutComponent } from './external/about-component/about-component';
import { ScholarsComponent } from './internal/scholars-component/scholars-component';
import { RepositoryComponent } from './internal/repository-component/repository-component';

export const routes: Routes = [
    {
        path: '',
        component: LandingPage
    },
    {
        path: 'register',
        component: Register
    },
    {
        path: 'login',
        component: Login
    },
    {
        path: 'about',
        component: AboutComponent
    },
    {
        path: 'scholars',
        component: ScholarsComponent
    },
    {
        path: 'repository',
        component: RepositoryComponent,
    },
    {
        path: '**',
        redirectTo: ''
    }
];
