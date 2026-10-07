create table if not exists public.url_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid null references auth.users(id) on delete set null,
  url text not null,
  prediction text not null check (prediction in ('Safe', 'Phishing')),
  confidence numeric not null check (confidence >= 0 and confidence <= 1),
  risk_score integer not null check (risk_score >= 0 and risk_score <= 100),
  created_at timestamptz not null default now()
);

alter table public.url_scans enable row level security;

-- Keep service-role inserts on the backend. Add authenticated-user select policies
-- only after wiring Supabase Auth and a real user identity flow.
