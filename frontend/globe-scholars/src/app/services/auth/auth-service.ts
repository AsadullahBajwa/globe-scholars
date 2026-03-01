import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment.development'
import { NewUser, UserAccount } from './interface';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  public isLoggedIn:boolean = false

  constructor(private http: HttpClient){}
  protected authURL = `${environment.baseURL}/auth`
  public user: UserAccount | null = null;

  register(params:NewUser): Observable<UserAccount> {
    return this.http.post<UserAccount>(`${this.authURL}/signup/`, params)
  }
}