export interface WorkSummary {
  id: number;
  title: string;
  authors: string;
  publication_year: number;
  file_type: string;
  file_size: number;
  uploaded_at: string;
  uploader: {
    id: number;
    username: string;
    full_name: string;
    affiliation: string;
  };
  reaction_count: string;
  user_has_reacted: string;
  conversion_status: string;
}

export interface WorkDetail extends WorkSummary {
  author_list: string;
  description: string;
  keywords: string;
  original_filename: string;
  updated_at: string;
  download_url: string;
  conversion_progress: number;
}

export interface WorksResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: WorkSummary[];
}
