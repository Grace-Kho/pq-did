"""Isolated v2 wiring; immutable v1 application and data remain intact."""

from dataclasses import replace

from experiments.kyc_issuer_incremental_storage_1.integration import upgrade as issuer_upgrade
from experiments.kyc_manager_incremental_storage_1.store import ManagerStore
from experiments.kyc_milestone_1.baseline.scenario import _MeasuredProvider
from experiments.kyc_testbed_execution_1.application import Application
from pqdid.bounded_manager import BoundedDurableManager


def upgrade(app):
    s = app.scenario
    old = s.manager_store
    plan = ManagerStore.migration_plan(old, b"admin", s.manager.ticket, s.manager_permit)
    new, permit, ticket = ManagerStore.migrate(old, b"admin", s.manager_permit, plan)
    s.manager_store, s.manager_permit = new, permit
    s.manager = BoundedDurableManager(new, permit, ticket, signing_key=s.trusted[b"M"])
    # Existing issuer service object pins the manager; refresh only its trusted dependency.
    s.issuer = s._issuer(s.issuer.journal)
    # Providers capture a manager object at construction. Rebind both trusted stores
    # AND the verifier's cached provider; old objects remain fenced by schema/generation.
    for name, verifier in s.verifiers.items():
        provider = _MeasuredProvider(s, s.trusted[name.encode()].service_id)
        verifier.store._deps = replace(verifier.store._deps, provider=provider)
        verifier.provider = provider
    return plan


def create(path):
    app = Application.create(path)
    issuer_upgrade(app)
    upgrade(app)
    return app
