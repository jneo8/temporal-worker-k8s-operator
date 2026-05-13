# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Compatibility exports for environment processors."""

from charms.temporal_worker_k8s.v0.temporal_worker import (
    _parse_environment as parse_environment,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _process_env_variables as process_env_variables,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _process_juju_variables as process_juju_variables,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _process_vault_variables as process_vault_variables,
)
