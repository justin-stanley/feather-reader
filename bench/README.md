# Capacity bench (#263)

What one FeatherReader machine sustains — Fly `shared-cpu-1x`, 512 MB RAM,
1 GB volume — measured rather than assumed, so `max_feeds_global` (10,000),
`FEATHERREADER_POLL_BATCH` (50 per 60 s tick, 4 concurrent) and the DB-size
watermark (768 MiB in production) can be set from numbers. The result feeds the
registration decision (design/RELEASE-0.5.0.md, D4 and §7).

A standalone crate, like `bot/`: the app's build and its supply-chain gates
never see it.

## What is here

| file | what |
|---|---|
| `src/main.rs` | `synthfeeds`: serves N deterministic RSS feeds at `/f/{i}.xml`, with churn, `304`s and a fixed share of slow / 404 / 500 / oversized feeds; `/stats` counts what was served. `synthfeeds seed` prints the SQL that registers the feeds. |
| `collect.sh` | samples the app container (memory, CPU) and its database (read-only: feeds polled, overdue, erroring, entries, size) plus `synthfeeds`' counters, one CSV row per interval. |
| `Dockerfile` | the `synthfeeds` image, built on the host that runs it. |

### The synthetic feeds

Every byte is a function of `SYNTH_SEED`, the feed index and the simulated
clock, so a run repeats exactly.

- **Normal (94.5%)**: 20–50 items; bodies 6–18 KB, mean ~12 KB, matching
  production's stored bodies (mean 11.9 KB, p99 17.5 KB). Ordinary prose with
  links, emphasis and images, so the sanitizer does ordinary work.
- **Big (1%)**: 2,000 short items, 2–5 MB, like a large podcast feed.
- **Slow (2%)** answers after 3–8 s; **404 (1%)**; **500 (1%)**;
  **oversized (0.5%)**: a 9 MiB body, over the app's 8 MiB cap.
- **Churn**: 30% of feeds gain an item hourly, 40% daily, 20% weekly, 10% never.
  `ETag` and `Last-Modified` are honoured, so unchanged feeds answer `304`.
- `SYNTH_TIME_SCALE` speeds the simulated clock: at 24, a simulated day passes
  in an hour (pair it with a shorter poll interval on the app).

Hostile bodies are out of scope; #326 and #327 cover them.

## Decisions

- **Reachability: a public hostname via Cloudflare Tunnel** to `synthfeeds` on
  apps. The app's SSRF guard refuses private addresses, correctly, and has no
  runtime bypass; a public name exercises the real fetch path (DNS, TLS, the
  guard) with no code change. The hostname is added for the runs and removed
  after, with the owner's go.
- **Test bed: staging on `v0.5.0-rc.1`**, after the rc's functional soak
  checks, so the numbers describe the release that ships. Staging is
  test-account only; it is snapshotted first and restored after.

## A run

On apps, with the owner's go for the tunnel entry and the staging changes:

1. **Snapshot staging's volume** (stop, copy the DB file, start).
2. **Start `synthfeeds`**:
   `docker build -t synthfeeds:local bench/` then run it with `SYNTH_FEEDS=N`
   on a loopback port, and point the tunnel hostname at it. Check
   `https://<host>/health` answers `ok synthfeeds` from outside.
3. **Cap staging's CPU** to the Fly machine. Fly's shared vCPU guarantees ~1/16
   of a core and bursts to a full core on credit, so each size runs twice:
   `cpus: 1` (bursting) and `cpus: 0.25` (throttled). Memory stays at 512 MiB.
4. **Seed**: `synthfeeds seed https://<host> N 3600 | sqlite3 <staging db>` with
   staging stopped, so first polls are spread over an hour (a never-polled row
   is otherwise due at once). The poller selects any feed row; no subscription
   or PDS record is needed, and nothing sweeps unsubscribed feeds.
5. **Collect**: `bench/collect.sh featherreader-staging <db> http://127.0.0.1:8263 15 > N-cpus.csv`
   for at least two poll intervals after the first spread hour, plus a light
   `GET /` latency probe alongside.
6. **Repeat** for N = 100, 1,000, 5,000, 10,000, and sweep
   `FEATHERREADER_POLL_CONCURRENCY` 4 / 8 / 16 at the size where throughput
   flattens, for memory per concurrent poll.
7. **DB growth**: one run with `SYNTH_TIME_SCALE=24` and the app's poll
   interval and tick shortened to match, for a simulated day of churn per feed.
   Unsubscribed feeds' entries are read by nobody, so this is growth with no
   reads at all: the upper bound retention has to hold.
8. **Restore**: CPU cap off, the DB from the snapshot, `synthfeeds` stopped,
   the tunnel hostname removed.

## From numbers to settings

- **Poll batch / concurrency**: the highest throughput with peak memory under
  ~70% of 512 MiB and acceptable `GET /` latency, at both CPU caps.
- **`max_feeds_global`**: feeds the poller serves within one poll interval at
  the throttled cap, less ~30% headroom.
- **DB watermark**: kept at 768 MiB unless growth and the 1 GB volume say
  otherwise; from per-feed growth, how many feeds retention holds under it, per
  instance and per user (500-feed cap).

Results, and any changed defaults, go in design/RELEASE-0.5.0.md §7 and the
0.5.0 upgrade notes.

## Develop

```
cd bench
cargo test
cargo clippy --all-targets -- -D warnings
SYNTH_FEEDS=100 cargo run   # http://127.0.0.1:8263/f/0.xml
```
