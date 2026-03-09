import {Routes} from '@angular/router';
import {authGuard} from './guards/auth.guard';
import {guestGuard} from './guards/guest.guard';
import {LandingPage} from './external/landing-page/landing-page';
import {Register} from './external/register/register';
import {Login} from './external/login/login';
import {AboutComponent} from './external/about-component/about-component';
import {ScholarsComponent} from './internal/scholars-component/scholars-component';
import {RepositoryComponent} from './internal/repository-component/repository-component';
import {UploadWorkComponent} from './internal/upload-work-component/upload-work-component';
import {ScholarProfileComponent} from './internal/scholar-profile-component/scholar-profile-component';
import {UserProfileComponent} from './internal/user-profile-component/user-profile-component';
import {FileViewComponent} from './internal/file-view-component/file-view-component';

export const routes: Routes = [
  {
    path: '',
    component: LandingPage
  },
  {
    path: 'register',
    component: Register,
    canActivate: [guestGuard]
  },
  {
    path: 'login',
    component: Login,
    canActivate: [guestGuard]
  },
  {
    path: 'about',
    component: AboutComponent
  },
  {
    path: 'scholars',
    component: ScholarsComponent,
  },
  {
    path: 'scholars/:id',
    component: ScholarProfileComponent
  },
  {
    path: 'repository',
    component: RepositoryComponent,
  },
  {
    path: 'repository/:id',
    component: FileViewComponent,
    canActivate: [authGuard]
  },
  {
    path: 'upload',
    component: UploadWorkComponent,
    canActivate: [authGuard],
  },
  {
    path: 'profile',
    component: UserProfileComponent,
    canActivate: [authGuard]
  },
  {
    path: '**',
    redirectTo: ''
  }
];
