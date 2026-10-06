# Uninstalled isolation proposal

**Planning artefacts only. Nothing here is installed, enabled or activated.**
The existing endpoint checks cannot yet serve clients with different UIDs.
Required launch/preflight/provisioning adapters and actual-identity tests are absent.
Do not install these templates against the current source.

- [Plan and ownership matrix](../../stage2_authority_isolation_plan.md).
- [Activation, verification and rollback runbook](activation.md).
- [Accounts, permission bindings and placeholder policies](principals.json).
- [Account/group template](accounts.sysusers.conf.in).
- [New-directory ownership template](directories.tmpfiles.conf.in).
- [Aggregate resource slice](pqiso.slice.in).
- [Owner unit](pqiso-owner@.service.in) and [client unit](pqiso-client@.service.in).
- [Manager replacement test unit](pqiso-replacement-m.service.in).
- [Credential provisioning contract](credentials.json.in).
- [Protected runtime layout](runtime-layout.json).
- [22-case actual-identity acceptance plan](acceptance.json).

There are no live secrets, numeric account assignments or approved recovery tickets
in this directory. Placeholders are not defaults. Units have no install target and
require a future root-controlled `ACTIVATION-AUTHORISED` marker; that marker alone
does not satisfy the preflight gates. An authorised pilot must resolve and validate
every placeholder, implement the missing adapters, and pass actual-identity tests
before making an isolation claim. Existing databases are never migrated by this plan.
