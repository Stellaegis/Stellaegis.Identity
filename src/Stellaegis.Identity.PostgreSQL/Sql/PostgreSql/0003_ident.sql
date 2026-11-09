-- ============================================================================
-- Stellaegis.Identity — the accounts schema, script 0003 (Identity 9.0.0)
-- ============================================================================
-- Applied after 0002 by the installation, replayed as it was the first time: a database installed
-- by an earlier version takes it by running the installation again.

-- ── Accounts: the security stamp ─────────────────────────────────────────────
-- A random value that changes with whatever must close the other sessions of the account — a new
-- password, a block, a change of the second factor or of the e-mail —, which a session carries and
-- is held against. Every account present gets one of its own; the sessions signed in before carry
-- none, and close at their next reading: every person signs in once more after the upgrade. The
-- module writes it with the account, and replaces it alone: an update of the account never does.

alter table ident.users add column security_stamp char(32) not null default replace(gen_random_uuid()::text, '-', '');
alter table ident.users alter column security_stamp drop default;
alter table ident.users add constraint ck_users_security_stamp check (security_stamp ~ '^[0-9a-f]{32}$');
