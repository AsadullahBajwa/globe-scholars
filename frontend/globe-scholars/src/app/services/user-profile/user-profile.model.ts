export interface UserProfile {
  id: number;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  fullName: string;
  bio: string;
  affiliation: string;
  country: string;
  website: string;
  createdAt: Date;
  uploadCount: number;
  totalReactions: number;
}

export interface UpdateProfileRequest {
  username?: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  bio?: string;
  affiliation?: string;
  country?: string;
  website?: string;
}
