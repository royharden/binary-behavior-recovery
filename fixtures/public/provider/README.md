# Scripted public provider format

Fixture files are closed JSON arrays accepted by `MockProvider.from_file`.
Each row contains exactly `request`, `request_sha256`, `response`, `usage`, `origin`.
The full request is `prepare_request(VisibleTask, history, ModelConfig)`; hash it
with `request_digest`. No fuzzy task-name matching or default answer exists.
Usage is exactly `{"input_tokens":0,"output_tokens":0,"usd":"0"}` and origin
is `fixture`. The response must validate against the shared CandidateResponse.

No authored target/reference/expected-answer fixture is included: independent
admission and public corpus inputs remain pending. Supply admitted public scripted
fixtures later. Every presentation must say SCRIPTED FIXTURE / NO LIVE MODEL RESULT.
