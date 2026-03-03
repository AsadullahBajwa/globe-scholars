import { TestBed } from '@angular/core/testing';

import { AuthService } from './auth-service';
import { NewUser, UserAccount } from './interface';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideZonelessChangeDetection } from '@angular/core';

describe('AuthService', () => {
  let service: AuthService;
  const newUser: NewUser = {
    first_name: 'John',
    last_name: 'Doe',
    username: 'johnD',
    password: 'Password123',
    password2: 'Password123'
  };

  let httpTestingController: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideZonelessChangeDetection()
      ]
    });
    service = TestBed.inject(AuthService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should make an http request to the register endpoint', () => {
    service.register(newUser).subscribe();
    const req = httpTestingController.expectOne('http://localhost:8001/api/auth/signup/');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(newUser);
    httpTestingController.verify();
  });

  it('should register a new user', (done: DoneFn) => {
    const expectedResponse: UserAccount = {
      message: 'Account created successfully.',
      user: {
          id: 1,
          email: null,
          username: 'johnD',
          first_name: 'John',
          last_name: 'Doe',
          full_name: 'John Doe',
          bio: '',
          affiliation: '',
          country: '',
          website: '',
          created_at: new Date(),
          upload_count: 0,
          total_reactions: 0
      },
      tokens: {
        access: 'access_token',
        refresh: 'refresh_token'
      }
    };
    service.register(newUser).subscribe(res => {
      expect(res).toEqual(expectedResponse);
      done();
    });
    const req = httpTestingController.expectOne('http://localhost:8001/api/auth/signup/');
    expect(req.request.method).toBe('POST');
    req.flush(expectedResponse);
    httpTestingController.verify();
  });

  it('should return an error if the username is already taken', (done: DoneFn) => {
    service.register(newUser).subscribe({
      error: (error: any) => {
        expect(error.error.username[0]).toBe('user with this username already exists.');
        done();
      },
    });
    const req = httpTestingController.expectOne('http://localhost:8001/api/auth/signup/');
    expect(req.request.method).toBe('POST');
    req.flush({ username: ['user with this username already exists.'] }, { status: 400, statusText: 'Bad Request' });
    httpTestingController.verify();
  });

  it('should return an error if the password does not match', (done: DoneFn) => {
      service.register(newUser).subscribe({
        error: (error: any) => {
          expect(error.error.password[0]).toBe('Passwords do not match.');
          done();
        },
      });
      const req = httpTestingController.expectOne('http://localhost:8001/api/auth/signup/');
      expect(req.request.method).toBe('POST');
      req.flush({ password: ['Passwords do not match.'] }, { status: 400, statusText: 'Bad Request' });
      httpTestingController.verify();
    });
});
