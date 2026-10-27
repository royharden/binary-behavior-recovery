# Scripted public provider format

Fixture files are closed JSON arrays accepted by `MockProvider.from_file`.
Each row contains exactly `request`, `request_sha256`, `response`, `usage`, `origin`.
The full request is `prepare_request(VisibleTask, history, ModelConfig,
evidence_json=..., artifact_sha256=...)`; hash it
with `request_digest`. No fuzzy task-name matching or default answer exists.
Usage is exactly `{"input_tokens":0,"output_tokens":0,"usd":"0"}` and origin
is `fixture`. The response must validate against the shared CandidateResponse.

Requests contain `visible_task`, `history`, `model_config`, `artifact_sha256` and
the complete `evidence` canonical public object. Digest-only legacy requests
refuse. Both fixture loading and replay require evidence <=48 KiB, exact canonical
bytes, VisibleTask evidence-digest equality and source-artifact equality, followed
by DL1's exact `PublicEvidenceEnvelope.from_json` / `validate_for` APIs. The full
envelope contains schema_version, artifact_sha256, evidence_sha256 and bundle;
evidence_sha256 hashes canonical bundle bytes, not envelope bytes. There is no
default or permissive validator. Missing producer code refuses explicitly.
Changing retained section bytes, addresses, imports, strings or truncation changes
the full request identity; it cannot match a previous scripted response.

No authored target/reference/expected-answer fixture is included: independent
admission and public corpus inputs remain pending. Supply admitted public scripted
fixtures later. Every presentation must say SCRIPTED FIXTURE / NO LIVE MODEL RESULT.
