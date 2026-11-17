create table if not exists public.url_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid null references auth.users(id) on delete set null,
  url text not null,
  prediction text not null check (prediction in ('Safe', 'Phishing', 'Needs review')),
  confidence numeric not null check (confidence >= 0 and confidence <= 1),
  risk_score integer not null check (risk_score >= 0 and risk_score <= 100),
  created_at timestamptz not null default now()
);

-- Keep existing deployments compatible with the explicit inconclusive outcome.
alter table public.url_scans drop constraint if exists url_scans_prediction_check;
alter table public.url_scans add constraint url_scans_prediction_check check (prediction in ('Safe', 'Phishing', 'Needs review'));

alter table public.url_scans enable row level security;

-- Keep service-role inserts on the backend. Add authenticated-user select policies
-- only after wiring Supabase Auth and a real user identity flow.
