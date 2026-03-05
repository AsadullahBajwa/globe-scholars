import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {map, Observable} from 'rxjs';
import {UserProfile, UpdateProfileRequest} from './user-profile.model';
import {environment} from '../../../environments/environment.development';

@Injectable({providedIn: 'root'})
export class UserProfileService {
  private apiUrl = `${environment.baseURL}/auth/profile/`;

  constructor(private http: HttpClient) {
  }

  getProfile(): Observable<UserProfile> {
    return this.http.get<any>(this.apiUrl).pipe(
      map(s => this.mapProfile(s))
    );
  }

  updateProfile(data: UpdateProfileRequest): Observable<UserProfile> {
    return this.http.patch<any>(this.apiUrl, data).pipe(
      map(response => this.mapProfile(response.user))
    );
  }

  private mapProfile(s: any): UserProfile {
    return {
      id: s.id,
      email: s.email,
      username: s.username,
      firstName: s.first_name,
      lastName: s.last_name,
      fullName: s.full_name,
      bio: s.bio ?? '',
      affiliation: s.affiliation ?? '',
      country: s.country ?? '',
      website: s.website ?? '',
      createdAt: new Date(s.created_at),
      uploadCount: parseInt(s.upload_count) || 0,
      totalReactions: parseInt(s.total_reactions) || 0,
    };
  }
}
