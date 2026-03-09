import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { WorkSummary, WorkDetail, WorksResponse } from './work.model';
import { environment } from '../../../environments/environment.development';

@Injectable({ providedIn: 'root' })
export class RepositoryService {
  private apiUrl = `${environment.baseURL}/repository`;

  constructor(private http: HttpClient) {}

  getWorks(): Observable<WorkSummary[]> {
    return this.http.get<WorksResponse>(`${this.apiUrl}/`).pipe(
      map(res => res.results)
    );
  }

  getWorkDetail(id: number): Observable<WorkDetail> {
    return this.http.get<WorkDetail>(`${this.apiUrl}/${id}/`);
  }

  downloadWork(id: number): Observable<Blob> {
    const token = sessionStorage.getItem('access_token');
    const headers = new HttpHeaders({
      Authorization: `Bearer ${token}`
    });
    return this.http.get(`${this.apiUrl}/${id}/download/`, { headers, responseType: 'blob' });
  }

  addReaction(id: number): Observable<void> {
    const token = sessionStorage.getItem('access_token');
    const headers = new HttpHeaders({
      Authorization: `Bearer ${token}`
    });
    return this.http.post<void>(`${this.apiUrl}/${id}/react/`, {}, { headers });
  }
}
