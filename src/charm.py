from charms.temporal_worker_k8s.v0.temporal_worker import TemporalWorker
from charms.temporal_worker_k8s.v0.temporal_worker import (
    _convert_env_var as convert_env_var,
)
from ops import main
from ops.charm import CharmBase


class TemporalWorkerK8SOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Ignore.
        """
        super().__init__(*args)
        self.worker = TemporalWorker(self)


if __name__ == "__main__":  # pragma: nocover
    main.main(TemporalWorkerK8SOperatorCharm)
