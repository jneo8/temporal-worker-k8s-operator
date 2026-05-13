# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Temporal worker library unit tests."""

import unittest.mock

import ops.testing
import pytest
from charms.temporal_worker_k8s.v0.temporal_worker import (
    LIBAPI,
    LIBID,
    LIBPATCH,
    TemporalWorker,
)
from ops.charm import CharmBase

DEFAULT_META = {
    "name": "minimal-temporal-worker",
    "peers": {"peer": {"interface": "temporal"}},
    "containers": {"temporal-worker": {"resource": "temporal-worker-image"}},
    "resources": {"temporal-worker-image": {"type": "oci-image"}},
    "provides": {
        "metrics-endpoint": {"interface": "prometheus_scrape"},
        "grafana-dashboard": {"interface": "grafana_dashboard"},
        "temporal-worker-info": {"interface": "temporal-worker-info"},
    },
    "requires": {
        "database": {"interface": "postgresql_client"},
        "vault": {"interface": "vault-kv"},
        "logging": {"interface": "loki_push_api"},
        "temporal-host-info": {"interface": "temporal-host-info"},
    },
}

CUSTOM_META = {
    "name": "minimal-temporal-worker",
    "peers": {"cluster": {"interface": "temporal"}},
    "containers": {"worker": {"resource": "temporal-worker-image"}},
    "resources": {"temporal-worker-image": {"type": "oci-image"}},
    "provides": {
        "metrics": {"interface": "prometheus_scrape"},
        "workers": {"interface": "temporal-worker-info"},
    },
    "requires": {
        "pg": {"interface": "postgresql_client"},
        "secrets": {"interface": "vault-kv"},
        "logs": {"interface": "loki_push_api"},
        "temporal": {"interface": "temporal-host-info"},
    },
}

VAULT_ACTIONS = {
    "restart": {},
    "add-vault-secret": {
        "params": {
            "path": {"type": "string"},
            "key": {"type": "string"},
            "value": {"type": "string"},
        },
    },
    "get-vault-secret": {
        "params": {
            "path": {"type": "string"},
            "key": {"type": "string"},
        },
    },
}

CONFIG_SCHEMA = {
    "options": {
        "log-level": {"type": "string"},
        "host": {"type": "string"},
        "namespace": {"type": "string"},
        "queue": {"type": "string"},
        "sentry-dsn": {"type": "string"},
        "sentry-sample-rate": {"type": "float"},
        "auth-provider": {"type": "string"},
        "environment": {"type": "string"},
    }
}

REQUIRED_CONFIG = {
    "log-level": "info",
    "host": "temporal.example:7233",
    "namespace": "default",
    "queue": "worker",
    "sentry-dsn": "",
    "sentry-sample-rate": 1.0,
    "auth-provider": "",
    "environment": "",
}


class MinimalTemporalWorkerCharm(CharmBase):
    """Minimal charm using default TemporalWorker arguments."""

    def __init__(self, *args):
        """Initialize the test charm."""
        super().__init__(*args)
        self.worker = TemporalWorker(self)


class CustomTemporalWorkerCharm(CharmBase):
    """Minimal charm using custom TemporalWorker arguments."""

    def __init__(self, *args):
        """Initialize the test charm."""
        super().__init__(*args)
        self.worker = TemporalWorker(
            self,
            container_name="worker",
            service_name="worker-service",
            entrypoint="/bin/start-worker",
            prometheus_port=9100,
            peer_relation="cluster",
            database_relation="pg",
            vault_relation="secrets",
            host_info_relation="temporal",
            worker_info_relation="workers",
            metrics_relation="metrics",
            logging_relation="logs",
            dashboards_relation=None,
            extra_environment=lambda charm: {"CUSTOM_KEY": charm.app.name},
        )


def test_library_metadata_is_publishable():
    """The library exposes initial Charmhub metadata."""
    assert len(LIBID) == 32
    assert int(LIBID, 16) >= 0
    assert LIBAPI == 0
    assert LIBPATCH == 1


def test_default_constructor_values():
    """Default constructor values match the public API."""
    ctx = ops.testing.Context(
        charm_type=MinimalTemporalWorkerCharm,
        meta=DEFAULT_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )

    with ctx(ctx.on.update_status(), ops.testing.State()) as manager:
        worker = manager.charm.worker

        assert worker.container_name == "temporal-worker"
        assert worker.service_name == "temporal-worker"
        assert worker.entrypoint == "/app/scripts/start-worker.sh"
        assert worker.prometheus_port == 9000
        assert worker.peer_relation == "peer"
        assert worker.database_relation == "database"
        assert worker.vault_relation == "vault"
        assert worker.host_info_relation == "temporal-host-info"
        assert worker.worker_info_relation == "temporal-worker-info"
        assert worker.metrics_relation == "metrics-endpoint"
        assert worker.logging_relation == "logging"
        assert worker.dashboards_relation == "grafana-dashboard"


def test_constructor_overrides_and_extra_environment():
    """Constructor overrides are stored and extra environment overrides base keys."""
    ctx = ops.testing.Context(
        charm_type=CustomTemporalWorkerCharm,
        meta=CUSTOM_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    peer_relation = ops.testing.PeerRelation(endpoint="cluster")

    with ctx(
        ctx.on.start(),
        ops.testing.State(config=REQUIRED_CONFIG, relations=[peer_relation]),
    ) as manager:
        worker = manager.charm.worker

        assert worker.container_name == "worker"
        assert worker.service_name == "worker-service"
        assert worker.entrypoint == "/bin/start-worker"
        assert worker.prometheus_port == 9100
        assert worker.peer_relation == "cluster"
        assert worker.database_relation == "pg"
        assert worker.vault_relation == "secrets"
        assert worker.host_info_relation == "temporal"
        assert worker.worker_info_relation == "workers"
        assert worker.metrics_relation == "metrics"
        assert worker.logging_relation == "logs"
        assert worker.dashboards_relation is None
        assert worker.build_environment()["CUSTOM_KEY"] == "minimal-temporal-worker"


def test_is_ready_reflects_container_connectivity():
    """The readiness check reflects Pebble connectivity and validation."""
    ctx = ops.testing.Context(
        charm_type=MinimalTemporalWorkerCharm,
        meta=DEFAULT_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    container = ops.testing.Container("temporal-worker", can_connect=True)
    peer_relation = ops.testing.PeerRelation(endpoint="peer")

    with ctx(
        ctx.on.start(),
        ops.testing.State(config=REQUIRED_CONFIG, containers=[container], relations=[peer_relation]),
    ) as manager:
        assert manager.charm.worker.is_ready is True


def test_host_uses_deprecated_config_fallback():
    """The host property exposes the resolved Temporal address."""
    ctx = ops.testing.Context(
        charm_type=MinimalTemporalWorkerCharm,
        meta=DEFAULT_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )

    with ctx(ctx.on.update_status(), ops.testing.State(config=REQUIRED_CONFIG)) as manager:
        assert manager.charm.worker.host == "temporal.example:7233"


def test_update_blocks_without_host():
    """Update blocks when neither host-info nor deprecated host config is available."""
    ctx = ops.testing.Context(
        charm_type=MinimalTemporalWorkerCharm,
        meta=DEFAULT_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    container = ops.testing.Container("temporal-worker", can_connect=True)
    peer_relation = ops.testing.PeerRelation(endpoint="peer")

    with unittest.mock.patch("ops.Container.exists", return_value=True):
        state_out = ctx.run(
            ctx.on.config_changed(),
            ops.testing.State(
                config={**REQUIRED_CONFIG, "host": ""},
                containers=[container],
                relations=[peer_relation],
            ),
        )

    assert state_out.unit_status == ops.BlockedStatus(
        "temporal-host-info relation not established; set deprecated `host` config as fallback"
    )


def test_build_pebble_layer_uses_constructor_values():
    """The library can build a Pebble layer for custom container/service settings."""
    ctx = ops.testing.Context(
        charm_type=CustomTemporalWorkerCharm,
        meta=CUSTOM_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    peer_relation = ops.testing.PeerRelation(endpoint="cluster")

    with ctx(
        ctx.on.start(),
        ops.testing.State(config=REQUIRED_CONFIG, relations=[peer_relation]),
    ) as manager:
        layer = manager.charm.worker.build_pebble_layer({"A": "B"})

    assert layer == {
        "summary": "temporal worker layer",
        "services": {
            "worker-service": {
                "summary": "temporal worker",
                "command": "/bin/start-worker",
                "startup": "enabled",
                "override": "replace",
                "environment": {"A": "B"},
            }
        },
    }


def test_custom_vault_relation_name_used_for_environment():
    """Vault environment processing respects the constructor relation-name override."""
    ctx = ops.testing.Context(
        charm_type=CustomTemporalWorkerCharm,
        meta=CUSTOM_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    peer_relation = ops.testing.PeerRelation(endpoint="cluster")
    vault_relation = ops.testing.Relation("secrets")
    environment = """
vault:
  - path: app
    name: TOKEN
    key: token
"""

    with unittest.mock.patch(
        "charms.temporal_worker_k8s.v0.temporal_worker._VaultRelation.get_vault_client"
    ) as get_vault_client:
        mock_vault_client = unittest.mock.Mock()
        mock_vault_client.read_secret.return_value = "secret-token"
        get_vault_client.return_value = mock_vault_client

        with ctx(
            ctx.on.start(),
            ops.testing.State(
                config={**REQUIRED_CONFIG, "environment": environment},
                relations=[peer_relation, vault_relation],
            ),
        ) as manager:
            assert manager.charm.worker.create_env() == {"TOKEN": "secret-token"}


def test_validate_missing_required_config_blocks():
    """Missing required config surfaces through validation."""
    ctx = ops.testing.Context(
        charm_type=MinimalTemporalWorkerCharm,
        meta=DEFAULT_META,
        actions=VAULT_ACTIONS,
        config=CONFIG_SCHEMA,
    )
    peer_relation = ops.testing.PeerRelation(endpoint="peer")

    with ctx(
        ctx.on.start(),
        ops.testing.State(config={**REQUIRED_CONFIG, "namespace": ""}, relations=[peer_relation]),
    ) as manager:
        with pytest.raises(ValueError, match="Invalid config: namespace value missing"):
            manager.charm.worker._validate(None)
