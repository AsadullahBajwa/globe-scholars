import {Component, OnInit} from '@angular/core';
import {CommonModule, DatePipe} from '@angular/common';
import {RepositoryService} from '../../services/repository/repository-service';
import {WorkSummary} from '../../services/repository/work.model';
import {ScholarsService} from '../../services/scholars/scholars-service';
import {Scholar} from '../../services/scholars/scholar.model';
import {environment} from '../../../environments/environment.development';
import { AuthService } from '../../services/auth/auth-service';
import {RouterLink} from '@angular/router';
import {FormsModule} from '@angular/forms';

@Component({
  selector: 'app-repository-component',
  imports: [CommonModule, DatePipe, RouterLink, FormsModule],
  templateUrl: './repository-component.html',
  styleUrl: './repository-component.scss',
})
export class RepositoryComponent implements OnInit {
  works: WorkSummary[] = [];
  scholars: Scholar[] = [];
  isLoading = true;
  error: string | null = null;

  buttons = [
    {id: 'last-year', text: 'Last Year'},
    {id: 'last-5-years', text: 'Last 5 Years'},
    {id: 'last-10-years', text: 'Last 10 Years'},
    {id: 'all-time', text: 'All Time'},
  ];

  constructor(
    private repositoryService: RepositoryService,
    private scholarsService: ScholarsService,
    protected authService: AuthService,
  ) {
  }

  ngOnInit(): void {
    this.loadWorks();
    this.loadScholars();
  }

  loadWorks() {
    this.isLoading = true;
    this.repositoryService.getWorks().subscribe({
      next: (data) => {
        this.works = data;
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Failed to load works.';
        this.isLoading = false;
      }
    });
  }

  loadScholars() {
    this.scholarsService.getScholars().subscribe({
      next: (data) => {
        this.scholars = data.slice(0, 4);
      },
      error: () => {
      }
    });
  }

  downloadWork(work: WorkSummary) {
    const token = sessionStorage.getItem('access_token');
    if (!token) {
      alert('Please log in to download files.');
      return;
    }

    fetch(`${environment.baseURL}/repository/${work.id}/download/`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => {
        if (res.status === 401) {
          alert('Please log in to download files.');
          return null;
        }
        if (!res.ok) throw new Error('Download failed');
        return res.blob();
      })
      .then(blob => {
        if (!blob) return;
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = work.title;
        a.click();
        window.URL.revokeObjectURL(url);
      })
      .catch(() => alert('Download failed. Please try again.'));
  }

  activeFilter = 'all-time';

  searchQuery = '';

  get filteredWorks(): WorkSummary[] {
    const now = new Date().getFullYear();
    return this.works
      .filter(work => {
        const matchesSearch = !this.searchQuery ||
          work.title.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
          work.authors.toLowerCase().includes(this.searchQuery.toLowerCase());

        const matchesYear = (() => {
          switch (this.activeFilter) {
            case 'last-year': return work.publication_year >= now - 1;
            case 'last-5-years': return work.publication_year >= now - 5;
            case 'last-10-years': return work.publication_year >= now - 10;
            default: return true;
          }
        })();

        return matchesSearch && matchesYear;
      });
  }

  setFilter(id: string) {
    this.activeFilter = id;
  }
}
