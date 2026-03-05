import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule, Router } from '@angular/router';
import { UserProfileService } from '../../services/user-profile/user-profile-service';
import { UserProfile, UpdateProfileRequest } from '../../services/user-profile/user-profile.model';

@Component({
  selector: 'app-user-profile',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './user-profile-component.html',
  styleUrl: './user-profile-component.scss',
})
export class UserProfileComponent implements OnInit {
  profile: UserProfile | null = null;
  isLoading = true;
  error: string | null = null;
  isEditing = false;
  isSaving = false;
  saveSuccess = false;

  form: UpdateProfileRequest = {};

  constructor(
    private profileService: UserProfileService,
    private router: Router
  ) {}

  ngOnInit() {
    this.profileService.getProfile().subscribe({
      next: (data: UserProfile | null) => {
        this.profile = data;
        this.resetForm();
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Failed to load profile.';
        this.isLoading = false;
      }
    });
  }

  resetForm() {
    if (!this.profile) return;
    this.form = {
      username: this.profile.username,
      first_name: this.profile.firstName,
      last_name: this.profile.lastName,
      email: this.profile.email,
      bio: this.profile.bio,
      affiliation: this.profile.affiliation,
      country: this.profile.country,
      website: this.profile.website,
    };
  }

  startEditing() {
    this.isEditing = true;
    this.saveSuccess = false;
  }

  cancelEditing() {
    this.isEditing = false;
    this.resetForm();
  }

  saveProfile() {
    this.isSaving = true;
    this.profileService.updateProfile(this.form).subscribe({
      next: (data) => {
        this.profile = data;
        this.resetForm();
        this.isEditing = false;
        this.isSaving = false;
        this.saveSuccess = true;
        setTimeout(() => this.saveSuccess = false, 3000);
      },
      error: () => {
        this.isSaving = false;
      }
    });
  }

  // TODO: change password

  copied = false;

  copyProfileLink() {
    if (!this.profile) return;
    const url = `${window.location.origin}/scholars/${this.profile.id}`;
    navigator.clipboard.writeText(url).then(() => {
      this.copied = true;
      setTimeout(() => this.copied = false, 2000);
    });
  }

  logout() {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('refresh_token');
    this.router.navigate(['/login']);
  }
}
