-- ============================================================================
-- Stellaegis.Identity — the accounts schema on SQL Server, script 0001
-- ============================================================================
-- Applied by the installation of the application (DatabaseLifecycle.InstallAsync of
-- Stellaegis.Primitives.Data), under a login that owns the schema; the schema is created by the
-- installation before this script. The application connects as a member of the database role the
-- installation grants its data rights. The record of the scripts applied is the installation's,
-- ident._schema_migrations, not this script's.
--
-- The same tables as the PostgreSQL script of Stellaegis.Identity.PostgreSQL, the same names, the
-- same rules. What differs, and why:
--   * a key that is a uuid or a hash is nonclustered: a table is stored in the order of its
--     clustered key, and a random one would scatter every insertion;
--   * the hashes compared by the queries — of a token, of a recovery code — and the format checks
--     carry a binary collation. A database of SQL Server is usually case-insensitive: without it,
--     two hashes differing only by case would be one, and a check would accept a capital;
--   * no index on the accounts blocked: the filter of an index of SQL Server takes no "or". The
--     resource servers read that list now and then, from a table of accounts, and scan it.
--
-- No row-level security: the module has no compartment, every row belongs to the application.
-- No table of an issuer: the tokens are Stellaegis.Issuer's, in a schema of their own.
-- All constraints and defaults explicitly named.
-- ============================================================================

-- ── Accounts ─────────────────────────────────────────────────────────────────
-- The identity of an account is user_unique_id, which its sub claim carries; it is never reused:
-- a deleted account stays, marked, so that its id stays taken.
-- The audit columns carry an actor, as Stellaegis.Primitives writes one: at most 128 characters,
-- and never a default — an actor forgotten is an error, not "system".
-- email is lowercase and trimmed by the module before it reaches the store, unique among the
-- accounts, deleted ones included. email_verified says whether it was proven: a code, or a link
-- the system sent there; while it was not, no reset link is sent to it.

create table ident.users (
  user_unique_id       uniqueidentifier  not null,
  email                nvarchar(320)     not null,
  display_name         nvarchar(200)     not null,
  password_hash        nvarchar(2000)    null,     -- null while the account waits for its activation
  is_enabled           bit               not null,
  email_verified       bit               not null,

  -- Lockout after failed logins; not a block at the door.
  failed_login_count   int               not null constraint df_users_failed_login_count default 0,
  failed_login_last    datetimeoffset(3) null,
  blocked_until        datetimeoffset(3) null,

  -- Audit
  created_at           datetimeoffset(3) not null,
  created_by           nvarchar(128)     not null,
  modified_at          datetimeoffset(3) not null,
  modified_by          nvarchar(128)     not null,
  last_login           datetimeoffset(3) null,

  -- Soft delete
  is_deleted           bit               not null constraint df_users_is_deleted default 0,
  deleted_at           datetimeoffset(3) null,
  deleted_by           nvarchar(128)     null,

  constraint pk_users primary key nonclustered (user_unique_id),
  constraint ux_users_email unique (email),
  constraint ck_users_failed_login_count check (failed_login_count >= 0),
  constraint ck_users_deleted check (
    (is_deleted = 0 and deleted_at is null and deleted_by is null)
    or (is_deleted = 1 and deleted_at is not null and deleted_by is not null))
);

-- The lookups of the login and the registration, among the accounts not deleted.
create index ix_users_email_active on ident.users (email)
  where is_deleted = 0;

-- ── Account tokens ───────────────────────────────────────────────────────────
-- The tokens of the links an account receives — a password reset, an activation —, each good once,
-- for a while. Only the SHA-256 of a token is kept, in hexadecimal: the token is in the link, and
-- whoever reads this table holds nothing that works. consumed_at is set on use, atomically, and
-- prevents a replay; revoked_at, when a newer token of the same purpose replaces it. delivery says
-- how the link reached its holder: by e-mail from the system, which proves the address, or by hand.

create table ident.account_tokens (
  token_hash     nchar(64) collate Latin1_General_100_BIN2 not null,
  user_unique_id uniqueidentifier  not null,
  purpose        nvarchar(20)      not null,
  delivery       nvarchar(10)      not null,
  email          nvarchar(320)     not null,
  created_at     datetimeoffset(3) not null,
  created_by     nvarchar(128)     not null,
  expires_at     datetimeoffset(3) not null,
  consumed_at    datetimeoffset(3) null,
  revoked_at     datetimeoffset(3) null,
  ip_address     nvarchar(45)      null,

  constraint pk_account_tokens primary key nonclustered (token_hash),
  constraint fk_account_tokens_user
    foreign key (user_unique_id) references ident.users (user_unique_id) on delete cascade,
  constraint ck_account_tokens_token_hash check (token_hash not like N'%[^0-9a-f]%'),
  constraint ck_account_tokens_purpose check (purpose collate Latin1_General_100_BIN2 in (N'password_reset', N'activation')),
  constraint ck_account_tokens_delivery check (delivery collate Latin1_General_100_BIN2 in (N'email', N'hand'))
);

create index ix_account_tokens_user_purpose on ident.account_tokens (user_unique_id, purpose);

-- ── E-mail verifications ─────────────────────────────────────────────────────
-- The code sent to an e-mail before an account is created with it, or before an account takes
-- it. One per e-mail: a new request replaces the previous code. The code has as many digits as
-- the module is configured for, between 4 and 10.

create table ident.email_verifications (
  email        nvarchar(320)     not null,
  code         nvarchar(10)      not null,
  created_at   datetimeoffset(3) not null,
  expires_at   datetimeoffset(3) not null,
  attempts     int               not null constraint df_email_verifications_attempts default 0,
  is_verified  bit               not null constraint df_email_verifications_is_verified default 0,
  ip_address   nvarchar(45)      null,

  constraint pk_email_verifications primary key (email),
  constraint ck_email_verifications_code check (
    len(code) between 4 and 10 and code collate Latin1_General_100_BIN2 not like N'%[^0-9]%'),
  constraint ck_email_verifications_attempts check (attempts >= 0)
);

-- ── Login events ─────────────────────────────────────────────────────────────
-- One row per attempt, succeeded or failed, append only. The user_unique_id of an attempt whose
-- e-mail matched no account is the empty uuid.

create table ident.login_events (
  login_event_id  bigint            not null identity (1, 1),
  user_unique_id  uniqueidentifier  not null,
  email           nvarchar(320)     not null,
  success         bit               not null,
  fail_reason     nvarchar(50)      null,
  ip_address      nvarchar(45)      null,
  user_agent      nvarchar(500)     null,
  created_at      datetimeoffset(3) not null,

  constraint pk_login_events primary key (login_event_id)
);

-- The recent attempts of an account, newest first.
create index ix_login_events_user_date on ident.login_events (user_unique_id, created_at desc);

-- The purge of the attempts past their retention, every day.
create index ix_login_events_date on ident.login_events (created_at);

-- ── Second factor ────────────────────────────────────────────────────────────

create table ident.user_mfa (
  user_unique_id  uniqueidentifier  not null,
  pending_secret  nvarchar(200)     null,   -- protected secret during setup, until a first code confirms it
  totp_secret     nvarchar(200)     null,   -- protected active secret, set when enabled by authenticator
  last_used_step  bigint            null,   -- time step of the last code accepted: a code is good once
  is_enabled      bit               not null constraint df_user_mfa_is_enabled default 0,
  enabled_at      datetimeoffset(3) null,
  method          nvarchar(10)      not null constraint df_user_mfa_method default N'totp',

  constraint pk_user_mfa primary key nonclustered (user_unique_id),
  constraint ck_user_mfa_method check (method collate Latin1_General_100_BIN2 in (N'totp', N'email'))
);

-- ── Recovery codes ───────────────────────────────────────────────────────────
-- Single-use codes for when the authenticator is unavailable. Only their hashes are kept.

create table ident.recovery_codes (
  recovery_code_id  bigint            not null identity (1, 1),
  user_unique_id    uniqueidentifier  not null,
  code_hash         nvarchar(2000) collate Latin1_General_100_BIN2 not null,
  created_at        datetimeoffset(3) not null constraint df_recovery_codes_created_at default sysdatetimeoffset(),
  used_at           datetimeoffset(3) null,   -- null while unused; set when consumed

  constraint pk_recovery_codes primary key (recovery_code_id)
);

-- The codes of an account not used yet, read at the login challenge.
create index ix_recovery_codes_user_unused on ident.recovery_codes (user_unique_id)
  where used_at is null;
