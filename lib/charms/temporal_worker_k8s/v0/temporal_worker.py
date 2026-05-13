# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Reusable Temporal Worker controller library.

This library owns the controller logic shared by Temporal worker charms:
validation, relation helpers, environment assembly, Pebble reconciliation, and
worker-related actions.
"""

import functools
import json
import logging
import os
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path

import hvac
import yaml
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.temporal_k8s.v0.temporal_host_info import TemporalHostInfoRequirer
from charms.temporal_worker_k8s.v0.temporal_worker_info import TemporalWorkerInfoProvider
from charms.vault_k8s.v0 import vault_kv
from ops import EventBase, Object, pebble
from ops.charm import CharmBase
from ops.jujuversion import JujuVersion
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, ModelError, SecretNotFoundError, WaitingStatus

# The unique Charmhub library identifier, never change it
LIBID = "c1013dac624807b83022333b680bad53"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

PYDEPS = ["ops>=2.21", "hvac==2.3.0", "cosl>=0.0.6", "pyyaml"]

logger = logging.getLogger(__name__)

_VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]

_REQUIRED_CHARM_CONFIG = ["namespace", "queue"]
_REQUIRED_CANDID_CONFIG = ["candid-url", "candid-username", "candid-public-key", "candid-private-key"]
_REQUIRED_OIDC_CONFIG = [
    "oidc-auth-type",
    "oidc-project-id",
    "oidc-private-key-id",
    "oidc-private-key",
    "oidc-client-email",
    "oidc-client-id",
    "oidc-auth-uri",
    "oidc-token-uri",
    "oidc-auth-cert-url",
    "oidc-client-cert-url",
]
_SUPPORTED_AUTH_PROVIDERS = ["candid", "google"]
_PROMETHEUS_PORT = 9000
_AUTH_SECRET_PARAMETERS = [
    "encryption-key",
    "auth-provider",
    "candid-url",
    "candid-username",
    "candid-public-key",
    "candid-private-key",
    "oidc-auth-type",
    "oidc-project-id",
    "oidc-private-key-id",
    "oidc-private-key",
    "oidc-client-email",
    "oidc-client-id",
    "oidc-auth-uri",
    "oidc-token-uri",
    "oidc-auth-cert-url",
    "oidc-client-cert-url",
]
_VAULT_NONCE_SECRET_LABEL = "nonce"  # nosec
_VAULT_CERT_PATH = "/vault/cert.pem"
_VAULT_CA_CERT_FILENAME = "ca.pem"


def _convert_env_var(config_var, prefix="TWC_"):
    """Convert config parameter to environment variable with prefix."""
    converted_env_var = config_var.upper().replace("-", "_")
    return prefix + converted_env_var


class _State:
    """Peer-relation-backed JSON state store."""

    def __init__(self, app, get_relation):
        """Construct the state store."""
        self.__dict__["_app"] = app
        self.__dict__["_get_relation"] = get_relation

    def __setattr__(self, name, value):
        """Set a value in the store."""
        self._get_relation().data[self._app].update({name: json.dumps(value)})

    def __getattr__(self, name):
        """Get a value from the store, or None."""
        value = self._get_relation().data[self._app].get(name, "null")
        return json.loads(value)

    def __delattr__(self, name):
        """Delete a value from the store, if present."""
        return self._get_relation().data[self._app].pop(name, None)

    def is_ready(self):
        """Report whether the backing relation is available."""
        return bool(self._get_relation())


def _log_event_handler(event_logger):
    """Log event-handler entry and exit with the provided logger."""

    def decorator(method):
        """Decorate an event handler."""

        @functools.wraps(method)
        def decorated(self, event):
            """Log around the decorated event handler."""
            event_logger.info(f"* running {self.__class__.__name__}.{method.__name__}")
            try:
                return method(self, event)
            finally:
                event_logger.info(f"* completed {self.__class__.__name__}.{method.__name__}")

        return decorated

    return decorator


def _process_env_variables(parsed_environment_data):
    """Process literal environment variables from parsed environment config."""
    charm_env = {}
    env_variables = parsed_environment_data.get("env", {})
    for env_variable in env_variables:
        key_name = env_variable.get("name")
        key_value = env_variable.get("value")
        if isinstance(key_value, (dict, list)):
            charm_env.update({key_name: json.dumps(key_value)})
        else:
            charm_env.update({key_name: key_value})

    return charm_env


def _process_juju_variables(charm, parsed_environment_data):
    """Process Juju user secrets from parsed environment config."""
    charm_env = {}
    if parsed_environment_data.get("juju") and not JujuVersion.from_environ().has_secrets:
        raise ValueError("Juju version does not support Juju user secrets")

    juju_variables = parsed_environment_data.get("juju", [])
    for juju_secret in juju_variables:
        try:
            secret_id = juju_secret.get("secret-id")
            key_name = juju_secret.get("name")
            from_key = juju_secret.get("key")

            secret = charm.model.get_secret(id=secret_id)
            secret_content = secret.get_content(refresh=True)

            if not key_name and not from_key:
                charm_env.update({key.upper().replace("-", "_"): value for key, value in secret_content.items()})
                continue

            charm_env.update({key_name: secret_content[from_key]})
        except SecretNotFoundError as e:
            raise ValueError(f"Juju secret `{secret_id}` not found") from e
        except ModelError as e:
            raise ValueError(f"Access permission not granted to charm for secret `{secret_id}`") from e
        except KeyError as e:
            logger.error(f"Error parsing secrets env: {e}")
            raise ValueError(f"Error parsing secrets env: {e}") from e

    return charm_env


def _process_vault_variables(charm, parsed_environment_data):
    """Process Vault secrets from parsed environment config."""
    charm_env = {}
    vault_variables = parsed_environment_data.get("vault", [])
    relation_name = charm.vault_relation.relation_name

    if vault_variables and not charm.model.relations[relation_name]:
        raise ValueError("No vault relation found to fetch secrets from")

    if vault_variables and charm.model.relations[relation_name]:
        try:
            vault_client = charm.vault_relation.get_vault_client()
        except Exception as e:
            logger.error("Unable to initialize vault client: %s", e)
            raise ValueError("Unable to initialize vault client. Remove relation and retry.") from e

        for item in vault_variables:
            key_name = item.get("name")
            from_key = item.get("key")
            path = item.get("path")
            try:
                secret = vault_client.read_secret(path=path, key=from_key)
            except Exception as e:
                raise ValueError(f"Unable to read vault secret `{from_key}` at path `{path}`: {e}") from e
            charm_env.update({key_name: secret})

    for key in charm_env:
        if key.startswith("TEMPORAL_") or key.startswith("TWC_"):
            raise ValueError("Environment variables cannot use reserved prefix 'TEMPORAL_' or 'TWC_'")

    return charm_env


def _parse_environment(yaml_string):
    """Parse and validate workload environment YAML config."""
    data = yaml.safe_load(yaml_string)

    env = data.get("env", [])
    if not isinstance(env, list) or not all(
        isinstance(item, dict) and "name" in item and "value" in item and len(item) == 2 for item in env
    ):
        logging.debug("Invalid environment structure: 'env' should be a list of dictionaries with 'name' and 'value'")
        raise ValueError("Invalid environment structure. Check logs")

    juju = data.get("juju", [])
    if not isinstance(juju, list) or not all(
        isinstance(item, dict)
        and ((set(item.keys()) == {"secret-id"}) or (set(item.keys()) == {"secret-id", "name", "key"}))
        for item in juju
    ):
        logging.debug(
            "Invalid environment structure: each item in 'juju' must either contain only 'secret-id' or all of "
            "'secret-id', 'name', and 'key'"
        )
        raise ValueError("Invalid environment structure. Check logs")

    vault = data.get("vault", [])
    if not isinstance(vault, list) or not all(
        isinstance(item, dict) and "path" in item and "name" in item and "key" in item and len(item) == 3
        for item in vault
    ):
        logging.debug(
            "Invalid environment structure: 'vault' should be a list of dictionaries with 'path', 'name', and 'key'"
        )
        raise ValueError("Invalid environment structure. Check logs")

    return {
        "env": [{"name": item.get("name"), "value": item.get("value")} for item in env],
        "juju": [
            {"secret-id": item.get("secret-id"), "name": item.get("name"), "key": item.get("key")} for item in juju
        ],
        "vault": [{"path": item.get("path"), "name": item.get("name"), "key": item.get("key")} for item in vault],
    }


class _VaultOperationError(Exception):
    """Exception raised for errors in Vault operations."""


class _VaultClient:
    """Small HashiCorp Vault client used by the worker library."""

    def __init__(self, address: str, cert_path: str, role_id: str, role_secret_id: str, mount_point: str):
        """Initialize the Vault client."""
        self.client = hvac.Client(
            url=address,
            verify=cert_path,
        )
        self.mount_point = mount_point
        self._authenticate(role_id, role_secret_id)

    def _authenticate(self, role_id: str, role_secret_id: str):
        """Authenticate the client using AppRole."""
        login_response = self.client.auth.approle.login(
            role_id=role_id,
            secret_id=role_secret_id,
            use_token=False,
        )

        self.client.token = login_response["auth"]["client_token"]

        if not self.client.is_authenticated():
            raise Exception("Vault authentication failed.")

    def read_secret(self, path: str, key: str):
        """Read a secret value from Vault."""
        try:
            secret = self.client.secrets.kv.v2.read_secret(path=path, mount_point=self.mount_point)
            return secret["data"]["data"][key]
        except Exception as e:
            raise Exception(f"Could not fetch from Vault: {e}") from e

    def write_secret(self, path: str, key: str, value: str):
        """Write a secret value to Vault."""
        try:
            self.client.secrets.kv.v2.patch(path=path, secret={key: value}, mount_point=self.mount_point)
            return
        except hvac.exceptions.InvalidPath:
            logger.info("Secret %s does not yet exist on path %s", key, path)

        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path, secret={key: value}, mount_point=self.mount_point
            )
        except Exception as e:
            raise _VaultOperationError(f"Vault write operation failed: {e}") from e


class _Postgresql(Object):
    """Client for postgresql relations."""

    def __init__(self, charm, relation_name: str = "database"):
        """Construct the PostgreSQL relation helper."""
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

        charm.framework.observe(charm.database.on.database_created, self._on_database_changed)
        charm.framework.observe(charm.database.on.endpoints_changed, self._on_database_changed)
        charm.framework.observe(getattr(charm.on, f"{relation_name}_relation_broken"), self._on_database_relation_broken)

    @_log_event_handler(logger)
    def _on_database_changed(self, event) -> None:
        """Handle database creation/change events."""
        if not self.charm.unit.is_leader():
            return

        if not self.charm._state.is_ready():
            event.defer()
            return

        self.charm.unit.status = WaitingStatus(f"handling {event.relation.name} change")

        self.update_db_relation_data_in_state(event)
        self.charm._update(event)

    @_log_event_handler(logger)
    def _on_database_relation_broken(self, event) -> None:
        """Handle broken relations with the database."""
        if not self.charm.unit.is_leader():
            return

        if not self.charm._state.is_ready():
            event.defer()
            return

        self.charm._state.database_connection = None
        self.charm._update(event)

    # flake8: noqa: C901
    def update_db_relation_data_in_state(self, event) -> bool:
        """Update database data from relation into peer relation databag."""
        if not self.charm.unit.is_leader():
            return False

        if not self.charm._state.is_ready():
            logger.info("charm peer state not ready, deferring db update event")
            event.defer()
            return False

        if self.charm.model.get_relation(self.relation_name) is None:
            return False

        relation_id = self.charm.database.relations[0].id
        relation_data = self.charm.database.fetch_relation_data()[relation_id]

        endpoints = relation_data.get("endpoints", "").split(",")
        if len(endpoints) < 1:
            return False

        primary_endpoint = endpoints[0].split(":")
        if len(primary_endpoint) < 2:
            return False

        db_conn = {
            "host": primary_endpoint[0],
            "port": primary_endpoint[1],
            "password": relation_data.get("password"),
            "user": relation_data.get("username"),
            "tls": relation_data.get("tls"),
        }

        if None in (db_conn["user"], db_conn["password"]):
            return False

        should_update = False
        fields_to_check = ["host", "user", "password", "tls"]
        database_connection = self.charm._state.database_connection or {}
        if any(database_connection.get(field, "") != db_conn[field] for field in fields_to_check):
            should_update = True

        self.charm._state.database_connection = db_conn

        return should_update


class _VaultRelation(Object):
    """Client for vault relation."""

    def __init__(self, charm, relation_name: str = "vault"):
        """Construct the Vault relation helper."""
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

        charm.framework.observe(charm.vault.on.connected, self._on_vault_connected)
        charm.framework.observe(charm.vault.on.ready, self._on_vault_ready)
        charm.framework.observe(charm.vault.on.gone_away, self._on_vault_gone_away)

    @_log_event_handler(logger)
    def _on_vault_connected(self, event: vault_kv.VaultKvConnectedEvent):
        """Handle Vault connected event."""
        relation = self.charm.model.get_relation(event.relation_name, event.relation_id)
        egress_subnet = str(self.charm.model.get_binding(relation).network.interfaces[0].subnet)
        self.charm.vault.request_credentials(relation, egress_subnet, self.get_vault_nonce())

    @_log_event_handler(logger)
    def _on_vault_ready(self, event: vault_kv.VaultKvReadyEvent):
        """Handle Vault ready event."""
        self.charm._update(event)

    @_log_event_handler(logger)
    def _on_vault_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent):
        """Handle Vault removed event."""
        self.charm._update(event)

    def update_vault_relation(self):
        """Update Vault relation binding."""
        binding = self.charm.model.get_binding(self.relation_name)
        if binding is not None:
            try:
                egress_subnet = str(binding.network.interfaces[0].subnet)
                relation = self.charm.model.get_relation(self.relation_name)
                self.charm.vault.request_credentials(relation, egress_subnet, self.get_vault_nonce())
            except Exception as e:
                logger.warning(f"failed to update vault relation - {repr(e)}")

    def get_vault_nonce(self):
        """Retrieve the Vault nonce."""
        try:
            secret = self.charm.model.get_secret(label=_VAULT_NONCE_SECRET_LABEL)
            nonce = secret.get_content(refresh=True)["nonce"]
            return nonce
        except ModelError as e:
            logger.debug(f"Secret {_VAULT_NONCE_SECRET_LABEL} not found: {e}")
            raise ModelError from e

    def get_vault_config(self):
        """Retrieve Vault configuration details."""
        relation = self.charm.model.get_relation(self.relation_name)
        if relation is None:
            logger.debug("No vault relation found")
            return None
        vault_url = self.charm.vault.get_vault_url(relation)
        ca_certificate = self.charm.vault.get_ca_certificate(relation)
        mount = self.charm.vault.get_mount(relation)
        unit_credentials = self.charm.vault.get_unit_credentials(relation)
        if not unit_credentials:
            raise ValueError("vault relation: failed to get unit_credentials")

        secret = self.charm.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content(refresh=True)
        role_id = secret_content["role-id"]
        role_secret_id = secret_content["role-secret-id"]

        certs_path = self.get_ca_cert_location_in_charm()
        with open(f"{certs_path}/{_VAULT_CA_CERT_FILENAME}", "w") as fd:
            fd.write(ca_certificate)

        return {
            "vault_address": vault_url,
            "vault_role_id": role_id,
            "vault_role_secret_id": role_secret_id,
            "vault_mount": mount,
        }

    def get_vault_client(self):
        """Initialize Vault client."""
        ca_certificate_path = self.get_ca_cert_location_in_charm()
        vault_config = self.get_vault_config()
        return _VaultClient(
            address=vault_config["vault_address"],
            role_id=vault_config["vault_role_id"],
            role_secret_id=vault_config["vault_role_secret_id"],
            mount_point=vault_config["vault_mount"],
            cert_path=f"{ca_certificate_path}/{_VAULT_CA_CERT_FILENAME}",
        )

    def get_ca_cert_location_in_charm(self) -> Path | None:
        """Return the CA certificate location in the charm."""
        storage = self.charm.model.storages.get("certs")
        if not storage:
            return None
        return storage[0].location if storage else None


class _VaultActions(Object):
    """Client for vault actions."""

    def __init__(self, charm, vault_relation_name: str = "vault"):
        """Construct the Vault action helper."""
        super().__init__(charm, "vault-actions")
        self.charm = charm
        self.vault_relation_name = vault_relation_name

        add_vault_secret_action = getattr(charm.on, "add_vault_secret_action", None)
        get_vault_secret_action = getattr(charm.on, "get_vault_secret_action", None)
        if add_vault_secret_action is not None:
            charm.framework.observe(add_vault_secret_action, self._on_add_vault_secret)
        if get_vault_secret_action is not None:
            charm.framework.observe(get_vault_secret_action, self._on_get_vault_secret)

    @_log_event_handler(logger)
    def _on_add_vault_secret(self, event):
        """Add Vault secret action handler."""
        try:
            self._validate_vault_relation()
        except Exception as e:
            event.fail(str(e))

        path, key, value = (event.params.get(param) for param in ["path", "key", "value"])
        if not all([path, key, value]):
            event.fail("`path`, `key` and `value` are required parameters")

        try:
            vault_client = self.charm.vault_relation.get_vault_client()
        except Exception:
            event.fail("Unable to initialize vault client. remove relation and retry.")

        try:
            vault_client.write_secret(path=path, key=key, value=value)
            self.charm._update(event)
        except ValueError as e:
            logger.error("Unable to create secret in vault: %s", str(e))
            event.fail(str(e))
            return

        event.set_results({"result": "secret successfully created"})

    @_log_event_handler(logger)
    def _on_get_vault_secret(self, event):
        """Get Vault secret action handler."""
        try:
            self._validate_vault_relation()
        except Exception as e:
            event.fail(str(e))

        path, key = (event.params.get(param) for param in ["path", "key"])
        if not all([path, key]):
            event.fail("`path` and `key` are required parameters")

        try:
            vault_client = self.charm.vault_relation.get_vault_client()
        except Exception as e:
            logger.error("Unable to initialize vault client: %s", e)
            event.fail("Unable to initialize vault client. Remove relation and retry.")
            return

        try:
            value = vault_client.read_secret(path=path, key=key)
        except Exception as e:
            logger.error(f"Unable to read vault secret `{key}` at path `{path}`: {e}")
            event.fail(f"Unable to read vault secret `{key}` at path `{path}`: {e}")
            return

        event.set_results({"result": value})

    def _validate_vault_relation(self):
        """Validate Vault relation."""
        container = self.charm.unit.get_container(self.charm.name)
        if not container.can_connect():
            raise Exception("Failed to connect to the container")

        if not self.charm.model.relations[self.vault_relation_name]:
            raise Exception("No vault relation found")


class TemporalWorker(Object):
    """Reusable Temporal Worker controller for Kubernetes charms."""

    def __init__(
        self,
        charm: CharmBase,
        *,
        container_name: str = "temporal-worker",
        service_name: str = "temporal-worker",
        entrypoint: str = "/app/scripts/start-worker.sh",
        prometheus_port: int = 9000,
        peer_relation: str = "peer",
        database_relation: str = "database",
        vault_relation: str = "vault",
        host_info_relation: str = "temporal-host-info",
        worker_info_relation: str = "temporal-worker-info",
        metrics_relation: str = "metrics-endpoint",
        logging_relation: str = "logging",
        dashboards_relation: str | None = "grafana-dashboard",
        extra_environment: Callable[[CharmBase], Mapping[str, str]] | None = None,
    ) -> None:
        """Initialize the Temporal Worker controller.

        Args:
            charm: The charm using this controller.
            container_name: Workload container name from metadata.yaml.
            service_name: Pebble service name.
            entrypoint: Executable workload entry point inside the container.
            prometheus_port: Port scraped by the Prometheus integration.
            peer_relation: Peer relation name used for controller state.
            database_relation: PostgreSQL relation name.
            vault_relation: Vault relation name.
            host_info_relation: Temporal host-info relation name.
            worker_info_relation: Temporal worker-info relation name.
            metrics_relation: Prometheus metrics relation name.
            logging_relation: Loki logging relation name.
            dashboards_relation: Grafana dashboard relation name, or None to disable.
            extra_environment: Optional callback for downstream environment overrides.
        """
        super().__init__(charm, "temporal-worker")
        self.charm = charm
        self.container_name = container_name
        self.service_name = service_name
        self.entrypoint = entrypoint
        self.prometheus_port = prometheus_port
        self.peer_relation = peer_relation
        self.database_relation = database_relation
        self.vault_relation = vault_relation
        self.host_info_relation = host_info_relation
        self.worker_info_relation = worker_info_relation
        self.metrics_relation = metrics_relation
        self.logging_relation = logging_relation
        self.dashboards_relation = dashboards_relation
        self._extra_environment = extra_environment

        self.state = _State(charm.app, lambda: charm.model.get_relation(self.peer_relation))
        self.database = DatabaseRequires(
            charm,
            relation_name=self.database_relation,
            database_name=charm.model.config.get("db-name", None),
        )
        charm._state = self.state
        charm.database = self.database
        self.postgresql = _Postgresql(charm, relation_name=self.database_relation)

        self.vault = vault_kv.VaultKvRequires(
            charm,
            relation_name=self.vault_relation,
            mount_suffix=charm.app.name,
        )
        charm.vault = self.vault
        self.vault_relation_helper = _VaultRelation(charm, relation_name=self.vault_relation)
        charm.vault_relation = self.vault_relation_helper
        self.vault_actions = _VaultActions(charm, vault_relation_name=self.vault_relation)

        self.metrics = MetricsEndpointProvider(
            charm,
            relation_name=self.metrics_relation,
            jobs=[{"static_configs": [{"targets": [f"*:{self.prometheus_port}"]}]}],
            refresh_event=charm.on.config_changed,
        )
        self.log_forwarder = LogForwarder(charm, relation_name=self.logging_relation)
        self.grafana_dashboards = (
            GrafanaDashboardProvider(charm, relation_name=self.dashboards_relation)
            if self.dashboards_relation is not None
            else None
        )
        self.worker_info = (
            TemporalWorkerInfoProvider(charm) if self.worker_info_relation == "temporal-worker-info" else None
        )
        self.host_info = TemporalHostInfoRequirer(charm) if self.host_info_relation == "temporal-host-info" else None

        charm.postgresql = self.postgresql
        charm.vault_actions = self.vault_actions
        charm._prometheus_scraping = self.metrics
        charm._log_forwarder = self.log_forwarder
        charm._grafana_dashboards = self.grafana_dashboards
        if self.worker_info is not None:
            charm.worker_info = self.worker_info
        if self.host_info is not None:
            charm.host_info = self.host_info

        charm.name = self.container_name
        charm._update = self.update
        charm._validate = self._validate
        charm._validate_pebble_plan = self._validate_pebble_plan
        charm.create_env = self.create_env
        charm.get_auth_config_from_juju_secret = self.get_auth_config_from_juju_secret

        self.framework.observe(charm.on.config_changed, self._on_config_changed)
        self.framework.observe(
            getattr(charm.on, f"{self.container_name.replace('-', '_')}_pebble_ready"),
            self._on_temporal_worker_pebble_ready,
        )
        restart_action = getattr(charm.on, "restart_action", None)
        if restart_action is not None:
            self.framework.observe(restart_action, self._on_restart)
        self.framework.observe(charm.on.update_status, self._on_update_status)
        self.framework.observe(charm.on.install, self._on_install)
        self.framework.observe(charm.on.secret_changed, self._on_secret_changed)
        if self.host_info is not None:
            self.framework.observe(self.host_info.on.temporal_host_info_changed, self.update)
            self.framework.observe(self.host_info.on.temporal_host_info_unavailable, self.update)

    @property
    def is_ready(self) -> bool:
        """Whether Pebble is available and validation currently passes."""
        container = self.charm.unit.get_container(self.container_name)
        if not container.can_connect():
            return False
        try:
            self._validate(None)
        except ValueError:
            return False
        return True

    @property
    def host(self) -> str | None:
        """Resolved Temporal host[:port]."""
        if self.host_info is not None and self.host_info.host and self.host_info.port:
            return f"{self.host_info.host}:{self.host_info.port}"
        return self._deprecated_host

    def update(self, event: EventBase | None = None) -> None:
        """Run validation, environment assembly, Pebble replan, and status update."""
        container = self.charm.unit.get_container(self.container_name)
        if not container.can_connect():
            if event is not None:
                event.defer()
            self.charm.unit.status = WaitingStatus("waiting for pebble api")
            return

        if not container.exists(self.entrypoint):
            logger.error(
                "The workload container does not have the expected entrypoint script. "
                "Please refresh the charm with another valid image"
            )
            self.charm.unit.status = BlockedStatus("Please refresh the charm with a valid worker image")
            return

        try:
            context = self.build_environment()
        except ValueError as err:
            self.charm.unit.status = BlockedStatus(str(err))
            return

        logger.info("Configuring Temporal worker")

        pebble_layer = self.build_pebble_layer(context)
        container.add_layer(self.service_name, pebble_layer, combine=True)

        try:
            container.replan()
        except pebble.ChangeError as e:
            logger.exception(f"Failed to replan pebble services: {e}")
            self.charm.unit.status = BlockedStatus(
                "Failed to start pebble services - please consult logs for further details"
            )
            return

        self.charm.unit.status = MaintenanceStatus("replanning application")

    def build_environment(self) -> dict[str, str]:
        """Compute the final workload environment without applying Pebble changes."""
        self._validate(None)
        charm_config_env = self.create_env() if self.charm.config.get("environment") else {}
        auth_config = self.get_auth_config_from_juju_secret() if self.charm.config.get("auth-secret-id") else {}

        context = {}
        proxy_vars = {
            "HTTP_PROXY": "JUJU_CHARM_HTTP_PROXY",
            "HTTPS_PROXY": "JUJU_CHARM_HTTPS_PROXY",
            "NO_PROXY": "JUJU_CHARM_NO_PROXY",
        }

        for key, env_var in proxy_vars.items():
            value = os.environ.get(env_var)
            if value:
                context.update({key: value})

        host = self._resolve_host()
        if host is None:
            raise ValueError("temporal-host-info relation not established; set deprecated `host` config as fallback")

        context.update(
            {
                "TWC_HOST": host,
                "TEMPORAL_HOST": host,
            }
        )

        context.update(
            {
                _convert_env_var(key, prefix="TWC_"): value
                for key, value in self.charm.config.items()
                if key not in ["environment", "auth-secret-id", "host"]
            }
        )

        context.update(
            {
                _convert_env_var(key, prefix="TEMPORAL_"): value
                for key, value in self.charm.config.items()
                if key not in ["environment", "auth-secret-id", "host"]
            }
        )

        if charm_config_env:
            context.update(charm_config_env)

        if auth_config:
            context.update(**auth_config)

        if self._extra_environment is not None:
            context.update(dict(self._extra_environment(self.charm)))

        context.update({"TWC_PROMETHEUS_PORT": self.prometheus_port, "TEMPORAL_PROMETHEUS_PORT": self.prometheus_port})

        if self.charm.model.get_relation(self.database_relation) and self.state.database_connection:
            context.update(
                {
                    "TEMPORAL_DB_HOST": self.state.database_connection.get("host"),
                    "TEMPORAL_DB_PORT": self.state.database_connection.get("port"),
                    "TEMPORAL_DB_PASSWORD": self.state.database_connection.get("password"),
                    "TEMPORAL_DB_USER": self.state.database_connection.get("user"),
                    "TEMPORAL_DB_TLS": self.state.database_connection.get("tls"),
                }
            )

        return context

    def build_pebble_layer(self, environment: Mapping[str, str] | None = None) -> dict:
        """Build the workload Pebble layer."""
        return {
            "summary": "temporal worker layer",
            "services": {
                self.service_name: {
                    "summary": "temporal worker",
                    "command": self.entrypoint,
                    "startup": "enabled",
                    "override": "replace",
                    "environment": dict(environment) if environment is not None else self.build_environment(),
                }
            },
        }

    @property
    def _deprecated_host(self) -> str | None:
        """Return configured fallback Temporal address (host[:port]), if set."""
        raw = self.charm.config.get("host")
        if raw is None:
            return None
        stripped = str(raw).strip()
        return stripped or None

    @_log_event_handler(logger)
    def _on_install(self, event):
        """Handle install event."""
        self.charm.unit.add_secret(
            {"nonce": secrets.token_hex(16)},
            label=_VAULT_NONCE_SECRET_LABEL,
            description="Nonce for vault-kv relation",
        )

    @_log_event_handler(logger)
    def _on_temporal_worker_pebble_ready(self, event):
        """Handle workload Pebble readiness."""
        if not self.state.is_ready():
            event.defer()
            return

        self.update(event)

    @_log_event_handler(logger)
    def _on_restart(self, event):
        """Restart Temporal worker action handler."""
        container = self.charm.unit.get_container(self.container_name)
        if not container.can_connect():
            event.fail("Failed to connect to the container")
            return

        self.charm.unit.status = MaintenanceStatus("restarting worker")
        container.restart(self.service_name)

        event.set_results({"result": "worker successfully restarted"})

    @_log_event_handler(logger)
    def _on_config_changed(self, event):
        """Handle configuration changes."""
        self.charm.unit.status = WaitingStatus("configuring temporal worker")
        self.update(event)

    @_log_event_handler(logger)
    def _on_secret_changed(self, event):
        """Handle secret changed hook."""
        self.update(event)

    @_log_event_handler(logger)
    def _on_update_status(self, event):
        """Handle update-status events."""
        should_update = self.postgresql.update_db_relation_data_in_state(event)
        if should_update:
            logger.info("updating charm to reflect new database connection info")
            self.update(event)
            return

        try:
            self._validate(event)
            if self.charm.config.get("environment"):
                self.create_env()
        except ValueError as err:
            self.charm.unit.status = BlockedStatus(str(err))
            return

        container = self.charm.unit.get_container(self.container_name)
        valid_pebble_plan = self._validate_pebble_plan(container)
        if not valid_pebble_plan:
            self.update(event)
            return

        self.charm.unit.status = ActiveStatus(
            f"worker listening to namespace {self.charm.config['namespace']!r} on queue {self.charm.config['queue']!r}"
        )

    def _validate_pebble_plan(self, container):
        """Validate Temporal worker Pebble plan."""
        try:
            plan = container.get_plan().to_dict()
            return bool(plan and plan["services"].get(self.service_name, {}))
        except pebble.ConnectionError:
            return False

    def get_auth_config_from_juju_secret(self) -> dict:
        """Get auth config from Juju secret."""
        auth_config = {}
        secret = self.charm.model.get_secret(id=self.charm.config.get("auth-secret-id"))
        secret_content = secret.get_content(refresh=True)

        if not secret_content["auth-provider"]:
            raise ValueError("Invalid config: auth-provider value missing from auth-secret")

        if secret_content["auth-provider"] == "candid":
            self._check_required_config(secret_content, _REQUIRED_CANDID_CONFIG)
        elif secret_content["auth-provider"] == "google":
            self._check_required_config(secret_content, _REQUIRED_OIDC_CONFIG)

        auth_config.update(
            {
                _convert_env_var(key, prefix="TWC_"): value
                for key, value in secret_content.items()
                if key in _AUTH_SECRET_PARAMETERS
            }
        )

        auth_config.update(
            {
                _convert_env_var(key, prefix="TEMPORAL_"): value
                for key, value in secret_content.items()
                if key in _AUTH_SECRET_PARAMETERS
            }
        )

        return auth_config

    def create_env(self) -> dict:
        """Create an environment dictionary from environment config."""
        self.vault_relation_helper.update_vault_relation()

        parsed_environment_data = _parse_environment(self.charm.config.get("environment"))

        env_variables = _process_env_variables(parsed_environment_data)
        juju_variables = _process_juju_variables(self.charm, parsed_environment_data)
        vault_variables = _process_vault_variables(self.charm, parsed_environment_data)

        return {**env_variables, **juju_variables, **vault_variables}

    def _check_required_config(self, config_object, config_list):
        """Check if required config has been set by user."""
        for param in config_list:
            if not config_object.get(param):
                raise ValueError(f"Invalid config: {param} value missing")

    def _validate(self, event):  # noqa: C901
        """Validate that configuration and relations are valid and ready."""
        log_level = self.charm.model.config.get("log-level", "info").lower()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(f"config: invalid log level {log_level!r}")

        if not self.state.is_ready():
            raise ValueError("peer relation not ready")

        self._check_required_config(self.charm.config, _REQUIRED_CHARM_CONFIG)

        auth_provider = self.charm.config.get("auth-provider", "")
        if auth_provider and not self.charm.config.get("auth-secret-id"):
            if auth_provider not in _SUPPORTED_AUTH_PROVIDERS:
                raise ValueError("Invalid config: auth-provider not supported")

            if auth_provider == "candid":
                self._check_required_config(self.charm.config, _REQUIRED_CANDID_CONFIG)
            elif auth_provider == "google":
                self._check_required_config(self.charm.config, _REQUIRED_OIDC_CONFIG)

        sample_rate = self.charm.config.get("sentry-sample-rate", 1.0)
        if self.charm.config["sentry-dsn"] and (sample_rate < 0 or sample_rate > 1):
            raise ValueError("Invalid config: sentry-sample-rate must be between 0 and 1")

        environment_config = self.charm.config.get("environment")
        if environment_config:
            try:
                yaml.safe_load(environment_config)
            except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
                raise ValueError(f"Incorrectly formatted `environment` config: {e}") from e

        if self.charm.model.get_relation(self.database_relation) and not self.charm.config.get("db-name"):
            raise ValueError("Invalid config: db name value missing")

    def _resolve_host(self) -> str | None:
        """Resolve Temporal host using relation data before deprecated config."""
        if self.host_info is not None and self.host_info.host and self.host_info.port:
            host = f"{self.host_info.host}:{self.host_info.port}"
            if self._deprecated_host:
                logger.warning(
                    "The `host` config option is deprecated and will be removed in a future release; "
                    "prefer the `temporal-host-info` relation. Ignoring `host` while relation data is present."
                )
            return host

        if self._deprecated_host:
            logger.warning(
                "The `host` config option is deprecated and will be removed in a future release; "
                "prefer the `temporal-host-info` relation."
            )
            return self._deprecated_host

        return None
