"""Original keyless bridge: exact request -> durable reservation -> fixture."""
from typing import Any, Mapping, Sequence

from bbr.ledger import Ledger
from .mock import MockProvider, ModelConfig, ProviderError, prepare_request, request_digest


class FixtureDispatch:
    """A fresh instance is scoped to one opaque task/model intervention.

    Caller archives responses for M reuse; dispatching the same label twice is
    refused. This implementation cannot initiate a live/model/network call.
    """

    def __init__(self, task_id: str, visible_task: Any, provider: MockProvider,
                 ledger: Ledger, config: ModelConfig = ModelConfig()):
        if not task_id or config.origin != "fixture" or config.endpoint_id != "offline":
            raise ProviderError("only scoped offline fixtures admitted")
        self.task_id, self.task = task_id, visible_task
        self.provider, self.ledger, self.config = provider, ledger, config
        self.labels: set[str] = set()

    def __call__(self, label: str, history: Sequence[Mapping[str, Any]]) -> Any:
        allowed = {"M:0", "R:1", "R:2", "R:3", "P:1", "P:2", "P:3"}
        if label not in allowed or label in self.labels or len(self.labels) >= 7:
            raise ProviderError("unique call ceiling or repeated dispatch")
        self.labels.add(label)  # malformed/failed requests consume the attempt.
        request = prepare_request(self.task, history, self.config)
        digest = request_digest(request)
        reservation = self.ledger.reserve(f"{self.task_id}:{self.config.config_id}:{label}", digest, "0")
        self.ledger.mark_sent(reservation)
        try:
            result = self.provider.propose(self.task, history, self.config, reservation)
        except (ValueError, TypeError):
            self.ledger.settle(reservation, "0", reason="offline fixture refused; no provider charge")
            raise
        self.ledger.settle(reservation, "0", reason="scripted fixture; no live result")
        return result
