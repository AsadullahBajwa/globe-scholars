import {Component, OnInit, PLATFORM_ID, Inject, ChangeDetectorRef} from '@angular/core';
import {CommonModule} from '@angular/common';
import {FormsModule} from '@angular/forms';
import {ScholarsService} from '../../services/scholars/scholars-service';
import {Scholar} from '../../services/scholars/scholar.model';
import {isPlatformBrowser} from '@angular/common';
import {Router} from '@angular/router';

@Component({
  selector: 'app-scholars',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scholars-component.html',
  styleUrl: './scholars-component.scss',
})
export class ScholarsComponent implements OnInit {
  searchQuery = '';
  sortAsc = true;

  scholars: Scholar[] = [];
  isLoading = false;
  error: string | null = null;

  constructor(
    private scholarsService: ScholarsService,
    private router: Router,
    @Inject(PLATFORM_ID) private platformId: Object,
    private cdr: ChangeDetectorRef
  ) {
  }

  ngOnInit() {
    if (isPlatformBrowser(this.platformId)) {
      this.loadScholars();
    }
  }

  loadScholars() {
    this.isLoading = true;
    this.error = null;

    this.scholarsService.getScholars().subscribe({
      next: (data: Scholar[]) => {
        this.scholars = data;
        this.isLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.error = 'Failed to load scholars. Please try again.';
        this.isLoading = false;
        this.cdr.detectChanges();
      }
    });
  }


  get filteredScholars(): Scholar[] {
    return [...this.scholars]
      .filter(s =>
        (s.fullName ?? '').toLowerCase().includes(this.searchQuery.toLowerCase())
      )
      .sort((a, b) => {
        const cmp = (a.fullName ?? '').localeCompare(b.fullName ?? '');
        return this.sortAsc ? cmp : -cmp;
      });
  }

  toggleSort() {
    this.sortAsc = !this.sortAsc;
  }

  getYear(date: Date): number {
    return date.getFullYear();
  }

  goToProfile(id: number) {
    this.router.navigate(['/scholars', id]);
  }
}
