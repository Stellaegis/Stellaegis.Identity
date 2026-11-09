-- ============================================================================
-- Stellaegis.Identity — the accounts schema on SQL Server, script 0002 (Identity 8.0.0)
-- ============================================================================
-- Applied after 0001 by the installation, replayed as it was the first time: a database installed
-- by an earlier version takes it by running the installation again, and the application refuses to
-- start until it has. The same change as the PostgreSQL script 0002 of Stellaegis.Identity.PostgreSQL.

-- ── E-mail verifications: the code kept as its keyed hash ────────────────────
-- The code sent to an e-mail is kept as an HMAC-SHA256 under the pepper of the host, its e-mail and
-- purpose in the input, in lowercase hexadecimal under a binary collation, as the other hashes: a
-- row read from ident does not give the code without the pepper. The verifications pending hold
-- codes in clear, which no hash matches: they are removed, and the person asks a new code — they
-- live fifteen minutes unless set.

delete from ident.email_verifications;
go

alter table ident.email_verifications drop constraint ck_email_verifications_code;
go

exec sp_rename N'ident.email_verifications.code', N'code_hash', N'COLUMN';
go

alter table ident.email_verifications alter column code_hash nchar(64) collate Latin1_General_100_BIN2 not null;
go

alter table ident.email_verifications add constraint ck_email_verifications_code_hash check (code_hash not like N'%[^0-9a-f]%');
go

-- ── Login codes ──────────────────────────────────────────────────────────────
-- The code sent by e-mail during a login whose second step is the e-mail method, which the process
-- kept in memory before: a code issued by one instance of the host is checked by another. One per
-- account, replaced by the next, removed when spent; kept as an HMAC-SHA256 under the pepper, the
-- account in the input. An expired code stays until the purge, which reads expires_at.

create table ident.login_codes (
  user_unique_id  uniqueidentifier  not null,
  code_hash       nchar(64) collate Latin1_General_100_BIN2 not null,
  created_at      datetimeoffset(3) not null,
  expires_at      datetimeoffset(3) not null,

  constraint pk_login_codes primary key clustered (user_unique_id),
  constraint fk_login_codes_user
    foreign key (user_unique_id) references ident.users (user_unique_id) on delete cascade,
  constraint ck_login_codes_code_hash check (code_hash not like N'%[^0-9a-f]%')
);
go

create index ix_login_codes_expires on ident.login_codes (expires_at);
go
