# vigilo-eval — plan

## ROI gate

Justified before Step 0: this is the second half of the original portfolio-feedback ask that started
the MemKit real-evidence work ("I especially want to do this with MemKit" implied Vigilo was next,
explicitly deprioritized). Vigilo's public page (techbots-dev) carries the same `results: {state:
"in progress"}` placeholder gap MemKit's page just closed with real M2 numbers. Vigilo is a real,
working Go daemon + TypeScript analyst (not a stub) -- experiments against it would be genuine
signal. Feasibility: Vigilo is Linux-only (collection depends on `/proc` and `inotify`, verified by
reading the real README and architecture diagram), so it cannot run directly on this macOS machine --
but Vigilo ships its own `Dockerfile`/`docker-compose.yml`, and Docker is confirmed installed and
working here. Real Linux runtime is directly available, same "real binary, real server, real
requests" discipline used for memkit-eval, not mocked.

## Step 0 -- first-principles check

(Type-1 plan: new evaluation harness, hard to unwind once built against wrong assumptions, same
class of work as memkit-eval. Not skipped.)

### Q1: What fundamental outcome are we trying to achieve?
Turn Vigilo's published detection-latency and false-positive-rate claims into genuine,
reproducible measurement against a real running daemon (Docker/Linux) -- not architecture-doc
plausibility. V2 (correlation gain), V4 (overhead), V5 (analyst cost/stability) stay documented as
planned, not built this pass -- mirrors how MemKit shipped M2 first and left M1/M3/M4 as
documented future work.

Confirmed by user.

### Q2: What assumption about the current/proposed approach are we accepting unexamined?
memkit-eval's synthetic+real-data split doesn't map cleanly onto Vigilo. The synthetic side
transfers well (scripted attack chains replayed against a real container = the analog of the
synthetic contradiction workload). But there's no "real data" equivalent readily available -- no
actual signer/validator host to monitor. The realistic substitute (real everyday dev activity on a
Docker container, watched for a bounded window) is genuinely real but is NOT the production
crypto-infra workload Vigilo targets, and that gap must be disclosed explicitly, the same way
MemKit's real-data cells disclose their small-n/single-operator scope -- not silently presented as
equivalent.

Confirmed by user. Two secondary gaps surfaced during this question, not dropped -- carried forward
as design constraints in A/B/C and as disclosed limitations in the eventual public writeup:
- V3's own documented design assumes a multi-week observation window for false-positive rate;
  infeasible in this session. Accepting a much shorter bounded window, disclosed honestly.
- Detection latency needs a different harness shape than memkit-eval's HTTP request/response
  timing -- Vigilo's latency is OS-event-to-alert, requiring real syscalls triggered inside the
  container and alert-observation, not a client-timing wrapper.

### Q3: If we started from zero, knowing only the constraints, would we arrive at this design?
Yes, given the real constraints:
- Docker container = the only way to run the real Linux-only daemon
- Generic webhook alerter = captures immediate-tier alerts without needing real Slack/Telegram
  credentials
- MCP server = the tool's own documented read interface (README: "no log-scraping fallback") --
  querying it, not touching SQLite directly
- Analyst tier (Claude-dependent, confirmed via `agent/agents/analyst.ts` importing
  `@anthropic-ai/sdk` and requiring `ANTHROPIC_API_KEY`) is blocked on the same Anthropic billing
  issue as MemKit's resolver -- V1 this pass measures immediate-tier detection latency only;
  analyst-verdict latency stays documented future work alongside V2/V4/V5, not silently attempted
  and left half-broken.

Confirmed by user.

### Q4: What does the framework/tool/pattern give us that we actually need vs. ceremony for someone else's threat model?
NEED: webhook alerter only, minimal config (watch_paths for fake keystore/secret paths), single
Docker container, whichever MCP tool(s) expose recent-event reads.
NOT NEEDED for this pass: Slack/Telegram/email transports, suppression-rule tuning (deliberately --
raw untuned FP rate is the honest out-of-box signal, tuning would flatter the number), cross-host
correlation, the analyst's other MCP tools if unused, eBPF roadmap.

Confirmed by user. Step 0 complete.

## Step 0.5 -- sentinel plan_validation

Verdict: approved_with_conditions. Necessity/direction confirmed sound (problem real, Docker the
simplest path, cheap reversibility). One BLOCKER, two HIGH, one MEDIUM, one LOW.

### BLOCKER (resolved below): shipped docker-compose.yml observes the HOST, not an isolated container
Vigilo's own `docker-compose.yml` mounts `/proc:/proc:ro` and `/home:/home:ro` from the host and
uses `network_mode: host` -- built for production host-observation, not eval isolation. Run
unmodified, a triggered "suspicious outbound connection" would egress from the real host's real IP
on the real network, and the daemon would watch the real host's real processes, not a controlled
workload -- directly contradicts the plan's containment premise and answers the safety question
this Step 0.5 pass was asked to check.
**Resolution**: vigilo-eval authors its own dedicated compose file, never reuses the shipped one.
No host `/proc` or `/home` mounts (container's own `/proc` shows only container PIDs -- exactly the
controlled surface wanted). Non-host network (bridge/internal-only). "Suspicious outbound" triggers
point at a listener inside the eval network, not the real internet. Non-privileged container,
no `--pid=host`.

### HIGH: detection-latency (V1) comparability risk
Two traps: (1) process/network collection is poll-based (`/proc`, `/proc/net/tcp`) -- latency is
dominated by poll interval (our config), not Vigilo's intrinsic behavior, unless poll config matches
the public V1 claim. (2) t0 (trigger) and t1 (alert received) must be captured in ONE clock domain --
capturing t1 on the macOS host while t0 fires inside the Linux container corrupts a ~1s measurement
across VM/host clock domains.
**Resolution**: pin V1's exact operational definition (event type, t0/t1, poll interval) before
Section A. Run the webhook listener inside the eval network (same clock domain as the container),
or derive t1 from the daemon's own event timestamp via MCP. Report poll interval alongside the
number.

### HIGH: false-positive rate can both overclaim and be vacuously zero
FP rate is workload-specific -- a dev container's noise profile isn't a signer's. Must be a
headline-level qualifier ("FP rate watching a dev container", not a Vigilo production property),
not a buried footnote. Also: if the benign window never actually touches watched paths/signal
classes, FP≈0 trivially, not because Vigilo is precise.
**Resolution**: benign workload must genuinely exercise watched paths/spawns/connections (non-vacuous
denominator). Headline number carries the workload-specific qualifier inline, mirroring MemKit's
"single-operator, not a benchmark" disclosure pattern.

### MEDIUM: immediate-tier scope must constrain which chains get triggered
Several signals (shell-spawn/RCE, exfil chain, priv-esc) are LLM-tier-only per the README. With the
analyst blocked on credits, triggering these produces no alert -- could be misread as a missed
detection rather than an out-of-scope signal.
**Resolution**: V1 triggers restricted to immediate-tier-firing signals only (keystore/key read,
`.env` write, suspicious outbound). `min_severity` set to match. LLM-only signals documented as
explicitly out of scope this pass, not silently absent.

### LOW: credential hygiene
Webhook-only choice already avoids real Slack/Telegram creds. Eval config/compose must carry no
real tokens -- placeholder/local-listener values only.

All conditions carried into Section A as binding design constraints below.

## A) File layout

```
vigilo-eval/
├── plan.md
├── docker/
│   ├── docker-compose.yml       # isolated eval compose -- bridge network, NO host /proc or /home mounts (BLOCKER fix)
│   └── config.eval.yaml         # minimal Vigilo config: fake keystore/.env watch_paths, webhook alerter only, min_severity=high
├── harness/
│   ├── trigger.py               # performs real OS-level actions inside the container (keystore read, .env write, outbound to in-network listener) -- immediate-tier signals only (MEDIUM fix)
│   ├── webhook_listener.py      # HTTP listener INSIDE the eval network -- captures alert arrival (t1) in the same clock domain as the trigger (HIGH fix)
│   ├── mcp_client.py            # queries Vigilo's real MCP server (:7070) -- the tool's own documented read interface, cross-checks t1
│   ├── latency.py               # V1: t0->t1 per chain, reports poll interval alongside the number (HIGH fix)
│   └── false_positive.py        # V3: bounded real-activity window, non-vacuous (workload must touch watched paths), workload-specific qualifier is headline-level not a footnote (HIGH fix)
├── scripts/
│   └── run_evaluation.py        # orchestrates: start container, run V1 N times, run V3 bounded window, write results
├── results/                     # gitignored -- raw run logs; only aggregate numbers get hand-transcribed to the public site
├── tests/                       # unit tests for scoring logic against fixture payloads, not a live container
├── pyproject.toml
└── .gitignore
```

Confirmed by user.


## B) Class/method/function structure

```
trigger.py:
  AttackChain(name, action: Callable)
  trigger_keystore_read(container) -> TriggerResult(chain_name, t0)
  trigger_env_write(container) -> TriggerResult
  trigger_suspicious_outbound(container, listener_addr) -> TriggerResult
  run_all_chains(container, n_repeats) -> list[TriggerResult]
  # immediate-tier signals ONLY (MEDIUM fix) -- no shell-spawn/exfil/priv-esc triggers

webhook_listener.py:
  WebhookListener.start() / .stop() / .get_alerts() -> list[AlertReceived(timestamp, payload)]
  # runs INSIDE eval network -- same clock domain as trigger.py (HIGH fix)

mcp_client.py:
  VigiloMCPClient.connect(url)
  .list_recent_events() -> list[DaemonEvent(timestamp, event_type, severity)]
  .find_matching_event(trigger_result) -> DaemonEvent | None

latency.py:
  LatencyMetric(chain_name, t0, t1, latency_ms, poll_interval_ms)
  compute_latency(trigger_result, alert) -> LatencyMetric
  aggregate_latencies(metrics) -> LatencyReport(median, p95, per_chain, poll_interval_used)
  # poll interval always reported alongside the number (HIGH fix)

false_positive.py:
  FalsePositiveWindow(start, end, alerts, watched_paths_touched: bool)
  run_benign_window(container, duration_s) -> FalsePositiveWindow
  # deliberately touches watched paths during the window -- non-vacuous (HIGH fix)
  compute_fp_rate(window) -> FPReport(fp_count, fp_rate_per_day, workload_qualifier)
  # refuses a vacuous FP=0 if watched_paths_touched is False

run_evaluation.py:
  main(): start eval compose -> wait daemon healthy -> run_all_chains x N -> run_benign_window -> write raw results -> stop compose
```

Confirmed by user (batch-approved with A/C, message: "sapproved all sections").

## C) Function pseudocode + failure cases

```
trigger_keystore_read/env_write/suspicious_outbound(container):
  - t0 = time.time() immediately before exec'ing the real action inside the container
  - exec fails -> raise loud, don't silently continue (fail-fast, not fail-open)
  - per-repeat variation in filenames -- Vigilo's own signal_dedup table would
    collapse identical repeated triggers into fewer alerts than fired, corrupting
    the latency sample size

WebhookListener:
  - runs INSIDE the eval docker network -- t1 recorded in the same clock domain as t0
  - malformed payload -> log raw body, keep the timestamp signal, don't crash listener

VigiloMCPClient.list_recent_events / find_matching_event:
  - exact MCP tool name verified empirically against the running server, not guessed
  - no match found -> return None; caller treats as a possible miss, never silently drops it

compute_latency:
  - negative latency (clock skew / mispairing) -> reject, don't report a nonsense number
  - poll_interval_ms read from the actual config file, never assumed

aggregate_latencies:
  - empty metrics (all triggers missed) -> explicit state="no data", never silently 0ms
    (mirrors memkit-eval's Metrics(state="incomplete") pattern)

run_benign_window:
  - benign activity generated INSIDE the container (package installs, file
    read/writes near-but-not-on watched paths, git ops) -- the isolated daemon
    can only see the container's own /proc post-BLOCKER-fix, not the host's
    (a real design implication of the Step 0.5 BLOCKER fix, surfaced here)
  - must deliberately touch watched paths at least once (non-vacuous requirement)

compute_fp_rate:
  - watched_paths_touched == False -> raise, refuse a vacuous FP=0
  - workload_qualifier ("bounded in-container dev activity, not a production
    signer workload") always attached, headline-level not footnote

run_evaluation.py main():
  - docker compose up -> wait daemon healthy -> triggers -> benign window -> write results
  - compose down in a finally block regardless of failure -- never leaves an orphaned container
```

Confirmed by user (batch-approved, message: "sapproved all sections").

## C.5) Sentinel plan_validation on structure

Verdict: approved_with_conditions. Two BLOCKER-class, three HIGH, two MEDIUM, one LOW. All are local
edits to B/C, no redesign needed. Grounded against real Go source (`internal/mcp/server.go`,
`internal/alerter/webhook.go`), not assumed.

### C1 (BLOCKER-class): triggers must exec into the DAEMON's own container
The daemon's collectors read ITS OWN namespaces (`/proc`, `/proc/net/tcp`, fsnotify on its own
mount ns). `docker exec` into a container joins that container's namespaces. If trigger.py execs
into a sibling container (e.g. the webhook listener's), actions land in a different net/pid
namespace and the daemon observes nothing. **Resolution**: trigger.py execs exclusively into the
daemon container by name; harness asserts the exec target == the daemon container at startup.

### C2 (BLOCKER-class): FP guard conflated positive-control with FP denominator
Section C said benign activity should be "near-but-not-on watched paths" AND "must touch watched
paths" -- contradictory. Touching a watched keystore is the designed true-positive signal, not a
false positive; counting it as FP either inflates the published rate (the exact overclaim Step 0.5
tried to prevent, inverted) or contributes nothing. **Resolution**: split into two concepts --
positive control (one deliberate watched-path touch, asserts daemon fires, confirms pipeline live,
NOT counted in FP math) vs FP denominator (benign activity observable by the collectors -- spawns,
nearby file opens, connections -- that should NOT fire; FP = any alert on this set). Non-vacuous
check becomes "daemon emitted >=1 benign-set event," not "watched path touched."

### H1: outbound chain is fragile to poll-miss and dedup collapse
Network collection is poll-based on /proc/net/tcp -- a connection opened and closed between polls
is a full miss (0 alerts), not just slow. Repeated connections to the same address are identical
signals -- signal_dedup collapses all but the first repeat. **Resolution**: hold the socket open
>= the configured poll interval (read from config, not guessed); vary destination PORT per repeat
so each is a distinct resource surviving dedup.

### H2: poll_interval qualifier was over-applied to fsnotify-based chains
File events (keystore read, .env write) are fsnotify-driven -- event-driven, not poll-bound. Only
the network chain is poll-bound. A single blended poll_interval_used scalar across all three chains
misleads a reader into thinking file-chain latency is poll-dominated too. **Resolution**: report
per-chain latency with a per-chain mechanism label (fsnotify vs poll); attach poll_interval only to
the network chain.

### H3: webhook payload timestamp is second-quantized -- unusable for a ~1s claim
Grounded in webhook.go: the webhook payload's timestamp field uses RFC3339 (whole-second
precision), unlike the ECS path's RFC3339Nano. For a ~1s immediate-tier claim, +/-1s error from a
second-quantized field cannot resolve the measurement. **Resolution**: t1 is pinned explicitly to
the listener's own HTTP receive wall-clock time (same clock domain as t0), never the payload's own
timestamp field. MCP event timestamps are a coarse cross-check only (detection-time, not
alert-arrival), never averaged into the reported number.

### M1: mcp_client's assumed tool name doesn't exist
Grounded in server.go: six real tools exist (get_file_access_events, get_process_events,
get_network_events, get_all_events, get_critical_events, get_events_ecs), not "list_recent_events"
(nor "5 tools" -- the README itself is stale on the count). All require a `since` RFC3339 param.
**Resolution**: mcp_client.py calls `get_all_events(since_rfc3339)` (or get_critical_events for
triage, noting it hard-codes severity=high, limit=50). Always pass a valid `since`.

### M2: no Vigilo version pin undermines the harness's own reproducibility premise
No schema-version field exists on the webhook payload or MCP tool set; if Vigilo's shape drifts,
the parser breaks silently and old results become unreproducible. **Resolution**: pin the Vigilo
build to a specific commit SHA/image tag in the eval compose, mirroring memkit-eval's pinning
discipline; record the SHA alongside published numbers.

### L1: fsnotify needs the watched files on the container's own filesystem, not a host bind mount
inotify doesn't reliably propagate across a host-bind-mounted volume. **Resolution**: seed fake
keystore/.env into the image or a named volume, not a host bind mount; assert config.eval.yaml's
watch_paths match trigger.py's targets exactly.

All resolutions folded into the corrected Section B/C below.

## B/C corrections (post-C.5)

```
trigger.py:
  DAEMON_CONTAINER = "vigilo-daemon"  # asserted at harness startup, never a sibling container
  trigger_keystore_read(daemon_container) -> TriggerResult(chain_name, t0, mechanism="fsnotify")
  trigger_env_write(daemon_container) -> TriggerResult(mechanism="fsnotify")
  trigger_suspicious_outbound(daemon_container, listener_addr, port) -> TriggerResult(mechanism="poll")
    # holds socket open >= poll_interval; varies PORT per repeat (dedup survival)
  run_all_chains(daemon_container, n_repeats) -> list[TriggerResult]
  # immediate-tier signals only; per-repeat filename variation for file chains,
  # per-repeat port variation for the network chain

false_positive.py:
  run_positive_control(daemon_container) -> bool
    # ONE deliberate watched-path touch; asserts daemon fires; confirms pipeline live;
    # NOT counted in FP math
  run_benign_window(daemon_container, duration_s) -> FalsePositiveWindow(benign_events_observed: bool)
    # activity observable by the collectors (spawns, nearby file opens, connections)
    # that should NOT fire -- distinct from the positive control
  compute_fp_rate(window) -> FPReport(fp_count, fp_rate_per_day, workload_qualifier)
    # raises if not window.benign_events_observed (non-vacuous, redefined per C2)

latency.py:
  LatencyMetric(chain_name, t0, t1, latency_ms, mechanism: "fsnotify"|"poll", poll_interval_ms: float | None)
  compute_latency(trigger_result, alert) -> LatencyMetric
    # t1 = listener's own HTTP receive wall-clock, NEVER the webhook payload's timestamp field (H3)
  aggregate_latencies(metrics) -> LatencyReport
    # per-chain median/p95, mechanism label per chain, poll_interval attached ONLY to poll-based chains

mcp_client.py:
  VigiloMCPClient.get_all_events(since_rfc3339: str) -> list[DaemonEvent]
  VigiloMCPClient.get_critical_events(since_rfc3339: str) -> list[DaemonEvent]  # severity=high hardcoded upstream
  .find_matching_event(trigger_result) -> DaemonEvent | None
    # coarse cross-check only (detection-time), never averaged into the reported latency number
```

Confirmed by user (batch-approved, message: "sapproved all sections").

## D) TDD plan

### Unit tests (fixture-driven, no live container, fast)
- `test_compute_latency_ms`: fixture TriggerResult(t0) + AlertReceived(t1) -> correct ms
- `test_compute_latency_rejects_negative`: t1 < t0 (clock skew/mispairing) -> rejected, not reported
- `test_aggregate_latencies_empty_reports_no_data`: empty metrics -> state="no data", never silent 0ms
- `test_aggregate_latencies_mechanism_labeling`: mixed fsnotify+poll metrics -> poll_interval attached
  only to poll-mechanism entries (H2 regression)
- `test_compute_fp_rate_vacuous_denominator_raises`: benign_events_observed=False -> raises (C2 regression)
- `test_compute_fp_rate_excludes_positive_control`: fixture with both a positive-control alert and
  benign-set alerts -> FP count excludes the positive-control one (C2 regression)
- `test_webhook_listener_malformed_payload_does_not_crash`: garbage POST body -> arrival time still
  recorded, listener stays alive
- `test_mcp_client_find_matching_event_no_match_returns_none`: no matching fixture event -> None,
  not an exception
- `test_trigger_repeats_vary_port`: generated outbound-chain repeat sequence uses distinct ports (H1
  regression, dedup-survival)

### Integration tests (black-box, live Docker, `@pytest.mark.integration`, skip-clean if Docker
unavailable -- mirrors memkit-eval's live-service skip pattern)
- `test_e2e_daemon_container_is_the_exec_target`: asserts harness startup check catches a
  misconfigured sibling-container target (C1 regression)
- `test_e2e_keystore_read_fires_immediate_alert`: real container, real trigger, real webhook capture
  -- asserts an alert arrives within a generous bounded timeout, not the exact published number
- `test_e2e_positive_control_confirms_pipeline_live`: separate from FP test, run first
- `test_e2e_benign_window_short_smoke`: 1-2 min bounded smoke window, catches structural bugs before
  committing to the full-length real run in scripts/run_evaluation.py

### Flakiness mitigation
- Bounded timeouts on every wait -- never block forever for an alert that won't arrive
- Report n actually captured, not assume 100% capture (matches memkit-eval's Metrics(n=...) pattern)
- Run: `pytest -m "not integration"` for fast local/CI-like runs, `pytest -m integration` for the
  live-Docker suite

Confirmed by user (batch-approved, message: "sapproved all sections").

## E) To-do commit list

Layers: backend + infra only (CLI eval harness, no frontend/middletier). Publish step touches
techbots-dev separately (content layer, different repo).

**Phase 1 — scaffold + isolated infra**
- `feat(infra): scaffold vigilo-eval repo, pyproject.toml, .gitignore`
- `feat(infra): isolated eval docker-compose.yml (bridge network, no host mounts, pinned Vigilo
  image SHA per M2) + config.eval.yaml (webhook-only alerter, min_severity=high)`
  - Tests: `test_e2e_daemon_container_is_the_exec_target`

**Phase 2 — triggers + webhook listener**
- `feat(harness): trigger.py -- immediate-tier attack chains, daemon-container-only exec (C1)`
  - Tests: `test_trigger_repeats_vary_port`
- `feat(harness): webhook_listener.py -- in-network HTTP listener, t1 = receive time (H3)`
  - Tests: `test_webhook_listener_malformed_payload_does_not_crash`

**Phase 3 — MCP client + latency (V1 complete)**
- `feat(harness): mcp_client.py -- get_all_events/get_critical_events (M1), cross-check only`
  - Tests: `test_mcp_client_find_matching_event_no_match_returns_none`
- `feat(harness): latency.py -- per-chain mechanism labeling (H2), reject negative latency`
  - Tests: `test_compute_latency_ms`, `test_compute_latency_rejects_negative`,
    `test_aggregate_latencies_empty_reports_no_data`, `test_aggregate_latencies_mechanism_labeling`
- `test: integration test_e2e_keystore_read_fires_immediate_alert`

**Phase 4 — false-positive scoring (V3 complete)**
- `feat(harness): false_positive.py -- positive control vs FP denominator split (C2)`
  - Tests: `test_compute_fp_rate_vacuous_denominator_raises`, `test_compute_fp_rate_excludes_positive_control`
- `test: integration test_e2e_positive_control_confirms_pipeline_live`,
  `test_e2e_benign_window_short_smoke`

**Phase 5 — orchestration + real run**
- `feat: run_evaluation.py -- full orchestration, compose down in finally regardless of failure`
- `chore: run the real full-length V1+V3 pass, write results/ (gitignored)`

**Phase 6 — publish**
- `feat(content): fold real V1/V3 numbers into techbots-dev's Vigilo results block` (separate repo,
  same pattern as MemKit's M2 update)

Confirmed by user (batch-approved, message: "sapproved all sections").

## F) Standard closing steps
- PR-review the changes as if another engineer, once built
- Apply recommended review changes, iterate tests to green
- Remove unnecessary comments from the code

## G) Decision sentence
(Type-1 bookend -- written by the user, from memory, no agent in the loop. Not yet written; plan
is not closed until the user writes this.)

Decision sentence (written by user, verbatim):
"running real experiments for vigilo to get real data"

Plan closed.

## Live verification findings (Phase 1)

Isolated compose stack verified live: network mode `docker_default` (not host), only
`config.eval.yaml` mounted (no `/proc`/`/home`), daemon starts clean with watchers on
`/app/keystore` and `/app/.env`.

**Real gap found**: README's detection table claims "keystore file **read**" triggers immediate
alerts, but `internal/collector/file.go` only watches `fsnotify.Write` and `fsnotify.Create` --
reads are not detected without the optional auditd integration (not configured for this eval).
Verified live: `cat` on the keystore path produced no alert; a write to the same path fired
correctly (severity=critical, source=file_access, captured by the webhook listener with the
expected whole-second RFC3339 payload timestamp, matching H3). **Correction**: trigger.py's file
chains are both WRITE-based (keystore write, .env write), not read-based -- matches what's actually
observable with this collector configuration.

Also found and fixed upstream (pushed to voltagebots/vigilo, commit aba4e0d): Dockerfile pinned
`golang:1.23-alpine` but `go.mod` requires `go 1.25.0` -- broke a clean docker build of the repo's
own documented Quick Start. Confirmed pre-existing e2e test failures in `test/e2e` are unrelated
(identical with the fix stashed out) and out of scope (a separate REST events-API bug, not the MCP
path this eval uses).

Vigilo pinned at commit aba4e0d94471145526cac6155d09163327d2f093 for this eval.

## Live verification findings (Phase 2, trigger.py)

Two more real, live-diagnosed gaps beyond Phase 1's file-watch bug:

1. **signal_cooldown default (1h) blocked repeat measurement**: config.eval.yaml's copied default
   suppressed ALL repeat alerts on the same resource for an hour. Fixed: `signal_cooldown: 0s`.
2. **Whole-second dedup granularity**: with cooldown=0, `signal_dedup`'s `IsDuplicate` (buffer/sqlite.go)
   compares whole-second RFC3339 strings -- two same-resource events landing in the same wall-clock
   second still collide. keystore_write sidesteps this with a distinct file path per repeat;
   env_write (single watched file, no path trick available) is spaced >1s between repeats instead.
3. **Outbound trigger targets the wrong port** (known gap, not yet fixed): port 8090 (the webhook
   listener) classifies as SeverityMedium ("non-standard port") in network_linux.go, below
   min_severity=high -- never fires. The real `suspiciousPorts` set (4444/4445/1337/31337) IS
   SeverityCritical, but nothing listens there today, so a connection attempt RSTs before
   /proc/net/tcp's poller can observe it as ESTABLISHED. **Next concrete task**: add a decoy
   accept-only listener on one of those ports.

Verified live end-to-end: 3x keystore_write -> 3 distinct critical alerts, correct resources.
3x env_write (spaced) -> confirmed firing (single watched file, HIGH severity, matches
severityForPath's `.env` entry).

Two upstream Vigilo bugs found live, fixed, mutation-tested, pushed:
- Dockerfile pinned golang:1.23, go.mod needs 1.25 (commit aba4e0d)
- watch_paths entries pointing at a single file were silently never watched (commit a434033)

Vigilo re-pinned at a434033b... (latest after both fixes) for this eval.
