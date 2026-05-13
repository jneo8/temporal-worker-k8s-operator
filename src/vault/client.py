# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Compatibility exports for the Vault client helper."""

from charms.temporal_worker_k8s.v0.temporal_worker import _VaultClient as VaultClient
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _VaultOperationError as VaultOperationError,
)
