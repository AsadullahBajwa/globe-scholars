import {Component, OnInit} from '@angular/core';
import {CommonModule} from '@angular/common';
import {ActivatedRoute, RouterModule} from '@angular/router';
import {ScholarsService} from '../../services/scholars/scholars-service';
import {Scholar} from '../../services/scholars/scholar.model';

@Component({
  selector: 'app-scholar-profile',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './scholar-profile-component.html',
  styleUrl: './scholar-profile-component.scss',
})
export class ScholarProfileComponent implements OnInit {
  scholar: Scholar | null = null;
  isLoading = true;
  error: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private scholarsService: ScholarsService
  ) {
  }

  ngOnInit() {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    this.scholarsService.getScholarById(id).subscribe({
      next: (data) => {
        this.scholar = data;
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Failed to load scholar profile.';
        this.isLoading = false;
      }
    });
  }

  getYear(date: Date): number {
    return new Date(date).getFullYear();
  }

  copied = false;

  copyProfileLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      this.copied = true;
      setTimeout(() => this.copied = false, 2000);
    });
  }

  downloadProfile() {
    if (!this.scholar) return;

    this.scholarsService.exportScholar(this.scholar.id).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${this.scholar!.fullName}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
      },
      error: () => {
        console.error('Failed to download profile');
      }
    });
  }
}
