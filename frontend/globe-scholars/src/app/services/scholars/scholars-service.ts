import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {map, Observable} from 'rxjs';
import {Scholar} from './scholar.model';
import {environment} from '../../../environments/environment.development';

@Injectable({providedIn: 'root'})
export class ScholarsService {
  protected apiUrl = `${environment.baseURL}/auth/scholars/`;

  constructor(private http: HttpClient) {
  }

  getScholars(): Observable<Scholar[]> {
    return this.http.get<any>(this.apiUrl).pipe(
      map(response => response.results.map((s: any): Scholar => this.mapScholar(s)))
    );
  }

  getScholarById(id: number): Observable<Scholar> {
    return this.http.get<any>(`${this.apiUrl}${id}/`).pipe(
      map(s => this.mapScholar(s))
    );
  }

  private mapScholar(s: any): Scholar {
    return {
      id: s.id,
      username: s.username,
      firstName: s.first_name,
      lastName: s.last_name,
      fullName: s.full_name,
      bio: s.bio,
      affiliation: s.affiliation,
      country: s.country,
      website: s.website,
      createdAt: new Date(s.created_at),
      uploadCount: s.upload_count
    };
  }

  exportScholar(id: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}${id}/export/`, {
      responseType: 'blob'
    });
  }
}
