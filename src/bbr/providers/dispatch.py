"""Original keyless bridge: exact request -> durable reservation -> fixture."""
from hashlib import sha256
import json
from typing import Any, Callable, Mapping, Sequence

from bbr.ledger import Ledger
from .mock import MockProvider, ModelConfig, ProviderError, canonical, prepare_request


class ReceiptSinkError(RuntimeError):
    """Archival sink failed after local retention; never retry the provider."""


class FixtureDispatch:
    """A fresh instance is scoped to one opaque task/model intervention.

    Caller archives responses for M reuse; dispatching the same label twice is
    refused. This implementation cannot initiate a live/model/network call.
    """

    def __init__(self, task_id: str, visible_task: Any, provider: MockProvider,
                 ledger: Ledger, config: ModelConfig = ModelConfig(), *,
                 campaign_id: str,
                 evidence_json: bytes | None = None, artifact_sha256: str | None = None,
                 receipt_sink: Callable[[Mapping[str, Any]], None] | None = None):
        if not task_id or config.origin != "fixture" or config.endpoint_id != "offline":
            raise ProviderError("only scoped offline fixtures admitted")
        self.task_id, self.task = task_id, visible_task
        self.provider, self.ledger, self.config = provider, ledger, config
        if any(type(value) is not str or not value.strip() or len(value) > 256
               for value in (campaign_id, task_id, config.model_id, config.config_id, config.endpoint_id)):
            raise ProviderError("bounded campaign/task/model/config identity required")
        if type(config.seed) is not int:
            raise ProviderError("model seed must be an integer")
        self.campaign_id, self.receipt_sink = campaign_id, receipt_sink
        self._receipt_bytes: list[bytes] = []
        # Freeze the full evidence before any reservation. Missing/unvalidated
        # evidence cannot use an old digest-only fixture as a compatibility path.
        initial = prepare_request(visible_task, (), config, evidence_json=evidence_json,
                                  artifact_sha256=artifact_sha256)
        if initial["visible_task"]["task_id"] != task_id:
            raise ProviderError("dispatch task ID differs from retained request")
        self.evidence_json, self.artifact_sha256 = evidence_json, artifact_sha256
        self.labels: set[str] = set()

    def receipt_snapshots(self) -> tuple[dict[str, Any], ...]:
        """Detached closed bbr.call-resource.v1 objects for the archive owner."""
        return tuple(json.loads(raw) for raw in self._receipt_bytes)

    def receipt_jsonl(self) -> bytes:
        """Canonical UTF-8 JSON per retained receipt, each terminated by LF."""
        return b"".join(raw + b"\n" for raw in self._receipt_bytes)

    def __call__(self, label: str, history: Sequence[Mapping[str, Any]]) -> Any:
        allowed = {"M:0", "R:1", "R:2", "R:3", "P:1", "P:2", "P:3"}
        if label not in allowed or label in self.labels or len(self.labels) >= 7:
            raise ProviderError("unique call ceiling or repeated dispatch")
        self.labels.add(label)  # malformed/failed requests consume the attempt.
        request = prepare_request(self.task, history, self.config,
                                  evidence_json=self.evidence_json,
                                  artifact_sha256=self.artifact_sha256)
        request_bytes = canonical(request)
        digest = sha256(request_bytes).hexdigest()
        if request["visible_task"]["task_id"] != self.task_id:
            raise ProviderError("dispatch task identity drift")
        reservation = self.ledger.reserve(f"{self.task_id}:{self.config.config_id}:{label}", digest, "0")
        # Only a successful durable mark owns this dispatch attempt. Reuse or a
        # concurrent failed mark is not another provider attempt/receipt.
        self.ledger.mark_sent(reservation)
        retained_record: bytes | None = None

        def capture(record: Mapping[str, Any]) -> None:
            nonlocal retained_record
            if record.get("request_sha256") != digest or canonical(record.get("request")) != request_bytes:
                raise ProviderError("retained provider record request drift")
            retained_record = canonical(record)

        try:
            try:
                result = self.provider.propose(self.task, history, self.config, reservation,
                                               evidence_json=self.evidence_json,
                                               artifact_sha256=self.artifact_sha256,
                                               record_sink=capture)
            except (ValueError, TypeError):
                self.ledger.settle(reservation, "0", reason="offline fixture refused; no provider charge")
                raise
            self.ledger.settle(reservation, "0", reason="scripted fixture; no live result")
            return result
        finally:
            frozen_request = json.loads(request_bytes)
            cfg = frozen_request["model_config"]
            receipt = {"schema": "bbr.call-resource.v1", "campaign_id": self.campaign_id,
                "origin": cfg["origin"], "task_id": frozen_request["visible_task"]["task_id"],
                "model_id": cfg["model_id"], "config_id": cfg["config_id"], "call_id": label,
                "request_id": reservation.request_id, "attempt": reservation.attempt,
                "request_sha256": digest, "request": frozen_request,
                "provider_record": None if retained_record is None else json.loads(retained_record),
                "provider_record_sha256": None if retained_record is None else sha256(retained_record).hexdigest(),
                "provider_record_reason": "exact fixture record unavailable before dispatch completion" if retained_record is None else None}
            raw = canonical(receipt)
            self._receipt_bytes.append(raw)
            if self.receipt_sink is not None:
                try:
                    self.receipt_sink(json.loads(raw))
                except Exception as exc:
                    raise ReceiptSinkError("resource receipt retained locally; archive sink failed; do not redispatch") from exc
