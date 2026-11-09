-- ============================================================================
-- Stellaegis.Identity — the accounts schema, script 0002 (Identity 8.0.0)
-- ============================================================================
-- Applied after 0001 by the installation, replayed as it was the first time: a database installed
-- by an earlier version takes it by running the installation again, and the application refuses to
-- start until it has.

-- ── E-mail verifications: the code kept as its keyed hash ────────────────────
-- The code sent to an e-mail is kept as an HMAC-SHA256 under the pepper of the host, its e-mail and
-- purpose in the input, in lowercase hexadecimal: a row read from ident does not give the code
-- without the pepper. The verifications pending hold codes in clear, which no hash matches: they
-- are removed, and the person asks a new code — they live fifteen minutes unless set.

delete from ident.email_verifications;

alter table ident.email_verifications drop constraint ck_email_verifications_code;
alter table ident.email_verifications rename column code to code_hash;
alter table ident.email_verifications alter column code_hash type char(64);
alter table ident.email_verifications add constraint ck_email_verifications_code_hash check (code_hash ~ '^[0-9a-f]{64}$');
