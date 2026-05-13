# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Compatibility exports for the Vault relation helper."""

from charms.temporal_worker_k8s.v0.temporal_worker import (
    _VAULT_CA_CERT_FILENAME as VAULT_CA_CERT_FILENAME,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _VAULT_CERT_PATH as VAULT_CERT_PATH,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _VAULT_NONCE_SECRET_LABEL as VAULT_NONCE_SECRET_LABEL,
)
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _VaultRelation as VaultRelation,
)
