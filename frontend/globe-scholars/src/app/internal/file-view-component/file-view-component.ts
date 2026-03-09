import {Component, OnDestroy, OnInit} from '@angular/core';
import {UpperCasePipe} from '@angular/common';
import {ActivatedRoute} from '@angular/router';
import {PdfViewerModule} from 'ng2-pdf-viewer';
import {RepositoryService} from '../../services/repository/repository-service';
import {WorkDetail} from '../../services/repository/work.model';

@Component({
  selector: 'app-file-view-component',
  imports: [PdfViewerModule, UpperCasePipe],
  templateUrl: './file-view-component.html',
  styleUrl: './file-view-component.scss',
})
export class FileViewComponent implements OnInit, OnDestroy {
  work: WorkDetail | null = null;
  downloadURL: string | null = null;
  isLoading = true;
  error: string | null = null;
  hasReacted = false;

  private objectUrl: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private repositoryService: RepositoryService,
  ) {}

  ngOnInit(): void {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    this.repositoryService.getWorkDetail(id).subscribe({
      next: (work) => {
        this.work = work;
        this.loadPdf(id);
      },
      error: () => {
        this.error = 'Failed to load work details.';
        this.isLoading = false;
      }
    });
  }

  private loadPdf(id: number): void {
    this.repositoryService.downloadWork(id).subscribe({
      next: (blob) => {
        this.objectUrl = URL.createObjectURL(blob);
        this.downloadURL = this.objectUrl;
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Failed to load file.';
        this.isLoading = false;
      }
    });
  }

  react(): void {
    if (!this.work || this.hasReacted) return;
    this.repositoryService.addReaction(this.work.id).subscribe({
      next: (res) => {
        console.log(res)
        this.hasReacted = true;
        if (this.work) {
          this.work.reaction_count = String(Number(this.work.reaction_count) + 1);
        }
      }
    });
  }

  ngOnDestroy(): void {
    if (this.objectUrl) {
      URL.revokeObjectURL(this.objectUrl);
    }
  }
}
