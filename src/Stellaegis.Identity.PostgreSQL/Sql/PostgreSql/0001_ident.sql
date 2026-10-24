-- ============================================================================
-- Stellaegis.Identity — the accounts schema, script 0001
-- ============================================================================
-- Applied by the installation of the application (DatabaseLifecycle.InstallAsync of
-- Stellaegis.Primitives.Data), under the role that owns the schema; the schema is created by the
-- installation before this script. The application connects under an ordinary role, granted its
-- data rights by the installation. The record of the scripts applied is the installation's,
-- ident._schema_migrations, not this script's.
--
-- No row-level security: the module has no compartment, every row belongs to the application.
-- No table of an issuer: the tokens are Stellaegis.Issuer's, in a schema of its own.
-- All constraints explicitly named.
-- ============================================================================

-- ── Accounts ─────────────────────────────────────────────────────────────────
-- The identity of an account is user_unique_id, which its sub claim carries; it is never reused:
-- a deleted account stays, marked, so that its id stays taken.
-- The audit columns carry an actor, as Stellaegis.Primitives writes one: at most 128 characters,
-- and never a default — an actor forgotten is an error, not "system".

create table ident.users (
  user_unique_id       uuid          not null,
  email                varchar(320)  not null,
  display_name         varchar(200)  not null,
  password_hash        varchar(2000),          -- null while the account waits for its activation
  is_enabled           boolean       not null,
  email_verified       boolean       not null,

  -- What the person chose for themselves; null while they chose nothing.
  locale               varchar(35),            -- a culture name, such as fr or en-GB: the locale claim
  time_zone            varchar(64),            -- an IANA name, such as Europe/Paris: the zoneinfo claim

  -- Lockout after failed logins; not a block at the door.
  failed_login_count   integer       not null default 0,
  failed_login_last    timestamptz,
  blocked_until        timestamptz,

  -- Audit
  created_at           timestamptz   not null,
  created_by           varchar(128)  not null,
  modified_at          timestamptz   not null,
  modified_by          varchar(128)  not null,
  last_login           timestamptz,

  -- Soft delete
  is_deleted           boolean       not null default false,
  deleted_at           timestamptz,
  deleted_by           varchar(128),

  constraint pk_users primary key (user_unique_id),
  constraint ux_users_email unique (email),
  constraint ck_users_failed_login_count check (failed_login_count >= 0),
  constraint ck_users_locale check (char_length(locale) between 2 and 35),
  constraint ck_users_time_zone check (char_length(time_zone) between 1 and 64),
  constraint ck_users_deleted check (
    (is_deleted = false and deleted_at is null and deleted_by is null)
    or (is_deleted = true and deleted_at is not null and deleted_by is not null))
);

comment on table  ident.users                is 'The accounts: who can sign in, with which e-mail and which password. The second factor and the recovery codes are kept apart.';
comment on column ident.users.user_unique_id is 'The identity of the account, which its sub claim carries. Never reused: a deleted account stays, marked.';
comment on column ident.users.email          is 'Lowercase and trimmed by the module before it reaches the store. Unique among the accounts, deleted ones included.';
comment on column ident.users.locale         is 'The language the person chose, a culture name the module checks: the locale claim. Null while they chose none.';
comment on column ident.users.time_zone      is 'The time zone the person chose, an IANA name the module checks: the zoneinfo claim. Null while they chose none.';
comment on column ident.users.email_verified is 'Whether the e-mail was proven: a code, or a link the system sent there. While it was not, no reset link is sent to it.';
comment on column ident.users.created_by     is 'The actor who created the account: the person themselves, or an administrator. Never a default.';
comment on column ident.users.deleted_by     is 'The actor who deleted the account; null while it is not deleted.';

-- The lookups of the login and the registration, among the accounts not deleted.
create index ix_users_email_active on ident.users (email)
  where is_deleted = false;

-- The accounts a resource server refuses: disabled or deleted.
create index ix_users_blocked on ident.users (user_unique_id)
  where is_enabled = false or is_deleted = true;

-- ── Account tokens ───────────────────────────────────────────────────────────
-- The tokens of the links an account receives — a password reset, an activation —, each good once,
-- for a while. Only the SHA-256 of a token is kept, in hexadecimal: the token is in the link, and
-- whoever reads this table holds nothing that works. consumed_at is set on use, atomically, and
-- prevents a replay; revoked_at, when a newer token of the same purpose replaces it. delivery says
-- how the link reached its holder: by e-mail from the system, which proves the address, or by hand.

create table ident.account_tokens (
  token_hash     char(64)     not null,
  user_unique_id uuid         not null,
  purpose        varchar(20)  not null,
  delivery       varchar(10)  not null,
  email          varchar(320) not null,
  created_at     timestamptz  not null,
  created_by     varchar(128) not null,
  expires_at     timestamptz  not null,
  consumed_at    timestamptz,
  revoked_at     timestamptz,
  ip_address     varchar(45),

  constraint pk_account_tokens primary key (token_hash),
  constraint fk_account_tokens_user
    foreign key (user_unique_id) references ident.users (user_unique_id) on delete cascade,
  constraint ck_account_tokens_token_hash check (token_hash ~ '^[0-9a-f]{64}$'),
  constraint ck_account_tokens_purpose check (purpose in ('password_reset', 'activation')),
  constraint ck_account_tokens_delivery check (delivery in ('email', 'hand'))
);

create index ix_account_tokens_user_purpose on ident.account_tokens (user_unique_id, purpose);

-- ── E-mail verifications ─────────────────────────────────────────────────────
-- The code sent to an e-mail before an account is created with it, or before an account takes
-- it. One per e-mail: a new request replaces the previous code. The code has as many digits as
-- the module is configured for, between 4 and 10.

create table ident.email_verifications (
  email        varchar(320) not null,
  code         varchar(10)  not null,
  created_at   timestamptz  not null,
  expires_at   timestamptz  not null,
  attempts     integer      not null default 0,
  is_verified  boolean      not null default false,
  ip_address   varchar(45),

  constraint pk_email_verifications primary key (email),
  constraint ck_email_verifications_code check (code ~ '^[0-9]{4,10}$'),
  constraint ck_email_verifications_attempts check (attempts >= 0)
);

-- ── Login events ─────────────────────────────────────────────────────────────
-- One row per attempt, succeeded or failed, append only. The user_unique_id of an attempt whose
-- e-mail matched no account is the empty uuid.

create table ident.login_events (
  login_event_id  bigint generated always as identity,
  user_unique_id  uuid         not null,
  email           varchar(320) not null,
  success         boolean      not null,
  fail_reason     varchar(50),
  ip_address      varchar(45),
  user_agent      varchar(500),
  created_at      timestamptz  not null,

  constraint pk_login_events primary key (login_event_id)
);

-- The recent attempts of an account, newest first.
create index ix_login_events_user_date on ident.login_events (user_unique_id, created_at desc);

-- The purge of the attempts past their retention, every day.
create index ix_login_events_date on ident.login_events (created_at);

-- ── Avatars ──────────────────────────────────────────────────────────────────
-- The image an account shows: a PNG of 256 by 256 pixels, which the module checks and strips of every
-- chunk but the image's own before it reaches the store. One row per account that has one, apart
-- from the account so that reading an account never carries it, and so that removing it is deleting
-- a row: the image identifies the person.

create table ident.user_avatars (
  user_unique_id  uuid          not null,
  image           bytea         not null,
  modified_at     timestamptz   not null,
  modified_by     varchar(128)  not null,

  constraint pk_user_avatars primary key (user_unique_id),
  constraint fk_user_avatars_user
    foreign key (user_unique_id) references ident.users (user_unique_id) on delete cascade,
  constraint ck_user_avatars_image check (octet_length(image) between 8 and 262144)
);

-- ── Second factor ────────────────────────────────────────────────────────────

create table ident.user_mfa (
  user_unique_id  uuid         not null,
  pending_secret  varchar(200),           -- protected secret during setup, until a first code confirms it
  totp_secret     varchar(200),           -- protected active secret, set when enabled by authenticator
  last_used_step  bigint,                 -- time step of the last code accepted: a code is good once
  is_enabled      boolean      not null default false,
  enabled_at      timestamptz,
  method          varchar(10)  not null default 'totp',

  constraint pk_user_mfa primary key (user_unique_id),
  constraint ck_user_mfa_method check (method in ('totp', 'email'))
);

-- ── Recovery codes ───────────────────────────────────────────────────────────
-- Single-use codes for when the authenticator is unavailable. Only their hashes are kept.

create table ident.recovery_codes (
  recovery_code_id  bigint generated always as identity,
  user_unique_id    uuid         not null,
  code_hash         text         not null,
  created_at        timestamptz  not null default now(),
  used_at           timestamptz,           -- null while unused; set when consumed

  constraint pk_recovery_codes primary key (recovery_code_id)
);

-- The codes of an account not used yet, read at the login challenge.
create index ix_recovery_codes_user_unused on ident.recovery_codes (user_unique_id)
  where used_at is null;
