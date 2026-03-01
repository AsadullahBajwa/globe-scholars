export interface User {
    id: number,
    email: string | null,
    username: string,
    first_name: string,
    last_name: string,
    full_name: string,
    bio: string,
    affiliation: string,
    country: string,
    website: string,
    created_at: Date,
    upload_count: number,
    total_reactions: number
  }

export interface Tokens {
    refresh: string,
    access: string
}
  
export interface UserAccount {
    message: string,
    user: User,
    tokens: Tokens
}

export interface NewUser {
    first_name: string | null,
    last_name: string | null,
    username: string | null,
    password: string | null,
    password2: string | null
}