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
