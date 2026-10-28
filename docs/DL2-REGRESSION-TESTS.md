# DL2 Round2 software regression tests

These are explicitly authored software-regression fixtures, origin `fixture`.
They are not benchmark/held-out/independent corpus data, expected corpus answers,
custodian receipts or evidence that candidate code ran. No independent author,
evaluator or human appointment is fabricated.

Owned test files:
- tests/test_runner_differential_replay.py
- tests/test_resource_strata.py
- tests/support/dl2/fixtures.py, __init__.py and trusted_transport_fixture.py

Runner tests use trusted fake backend objects, shared observations and inert source
strings. Candidate text is never compiled, imported or executed on the host.
Partition arithmetic and byte examples are software boundary fixtures. Replay
tests hash symbolic test bytes, not real ELFs/images, and the executable replay
path uses missing backends to verify infrastructure unknown. Symlink creation
without Windows privilege is a pytest skip, never an implicit passed link check.
Docker tests exercise only pure configuration/argv construction; the admission
callback raises if invoked, and no Docker process/container may start in them.
Separate bounded-pipe tests invoke only checked-in trusted_transport_fixture.py
with fixed echo/burst/sleep modes under the granted venv Python. This is trusted
software harness validation, never recovered/generated candidate code. Those
checks observe host pipe limits/owned-child cleanup only, not container isolation.

Resource tests use symbolic monetary values for Decimal assertions, never bills
or real spend. Strata tests deliberately stub the trusted score_rows boundary and
use a labeled 96-cell software table to check the projector's denominator and
primary-versus-nominal behavior. They DO NOT validate score_rows, independent
admission, an actual hidden-open receipt, bootstrap, or an executed campaign.
Three passing nominal variants share one identity while one failing variant has
another, yielding nominal3/4 versus equal-identity1/2; these are unit arithmetic
inputs only. No actual transformation corpus or private input pool is generated.

Focused future command, only after real INT environment-ready notification:

```powershell
$dl2Root = 'C:\Worktrees\PortfolioBuilder\binary-behavior-recovery\DL2-runner-differential-replay'
$dl2Python = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\binary-behavior-recovery\.venv-round2\Scripts\python.exe'
$dl2Receipts = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\binary-behavior-recovery\agentops\runs\M15-DIRTY-20261027\round2\receipts'
$env:PYTHONPATH = "$dl2Root\src;$dl2Root;$dl2Root\tests"
Set-Location -LiteralPath $dl2Root
& $dl2Python -m pytest -q tests/test_runner_differential_replay.py tests/test_resource_strata.py "--junitxml=$dl2Receipts\DL2-focused.xml" 2>&1 | Tee-Object -FilePath "$dl2Receipts\DL2-focused.log"
$dl2ExitCode = $LASTEXITCODE
Write-Output "PYTEST_EXIT=$dl2ExitCode"
```

The test-run receipt must additionally bind the actual candidate SHA/dirty patch
and exact fixture hashes, cwd/command, venv interpreter/package identities and
actual exit/count/skip/JUnit paths. No shared-environment mutation, editable
install or dependency setup is part of this command. Current source-only AST
checks use host Python3.11.3; they are NOT Python3.12/Pydantic/pytest runtime checks.

Current runtime activation is pending: RAM-blocked installs, no notified shared
environment and no granted image/container ownership. No Docker smoke or actual
isolated candidate validation is claimed. Execute-only DockerBackend source does
not provide CandidateValidationBackend; missing validation remains unavailable.
All actual tests and container checks must be recorded separately when authorized
and executed; source completeness does not turn unrun tests into passes.
