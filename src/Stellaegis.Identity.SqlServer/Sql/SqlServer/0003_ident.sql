-- ============================================================================
-- Stellaegis.Identity — the accounts schema on SQL Server, script 0003 (Identity 9.0.0)
-- ============================================================================
-- Applied after 0002 by the installation, replayed as it was the first time: a database installed
-- by an earlier version takes it by running the installation again. The same change as the
-- PostgreSQL script 0003 of Stellaegis.Identity.PostgreSQL.

-- ── Accounts: the security stamp ─────────────────────────────────────────────
-- A random value that changes with whatever must close the other sessions of the account — a new
-- password, a block, a change of the second factor or of the e-mail —, which a session carries and
-- is held against. Every account present gets one of its own — newid() is drawn for each row —; the
-- sessions signed in before carry none, and close at their next reading: every person signs in once
-- more after the upgrade. The module writes it with the account, and replaces it alone.

alter table ident.users add security_stamp nchar(32) collate Latin1_General_100_BIN2 not null
  constraint df_users_security_stamp default lower(replace(convert(nchar(36), newid()), N'-', N''));
go

alter table ident.users drop constraint df_users_security_stamp;
go

alter table ident.users add constraint ck_users_security_stamp check (security_stamp not like N'%[^0-9a-f]%');
go
