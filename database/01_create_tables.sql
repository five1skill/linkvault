
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.folders (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now()
);

create table public.folder_access (
  folder_id uuid not null references public.folders(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (folder_id, user_id)
);

create table public.saved_links (
  id uuid primary key default gen_random_uuid(),
  folder_id uuid not null references public.folders(id) on delete cascade,
  url text not null,
  title text not null,
  description text not null default '',
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  unique (folder_id, url)
);

create table public.link_authors (
  link_id uuid not null references public.saved_links(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (link_id, user_id)
);

alter table public.profiles enable row level security;
alter table public.folders enable row level security;
alter table public.folder_access enable row level security;
alter table public.saved_links enable row level security;
alter table public.link_authors enable row level security;
