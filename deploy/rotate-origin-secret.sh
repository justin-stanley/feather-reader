#!/usr/bin/env bash
#
# Rotate FEATHERREADER_ORIGIN_SECRET across BOTH sides that must agree: the
# Cloudflare Transform Rule that injects `X-Origin-Auth`, and the Fly secret that
# Caddy compares it against.
#
# Why automate a two-command change: the two sides disagree for as long as it
# takes to do the second one, and while they disagree EVERY non-/health request
# 403s. Done by hand — dashboard form, then a terminal — that window is however
# long a human takes. Done here it is one machine restart. See deploy/teardown.md
# for the house style; this is the same kind of tool.
#
# **Fly reports the machine HEALTHY for the whole window.** `/health` is exempt
# from the origin lock, so Caddy answers it 200 while every real request is
# refused. Nothing alerts. That is the single best reason to make this fast and
# scripted rather than careful and manual.
#
# DRY RUN IS THE DEFAULT. Nothing is written without --commit.
#
# Required env:
#   CF_API_TOKEN   Cloudflare token scoped to THIS ZONE -> Transform Rules -> Edit.
#                  Mint a single-purpose token; do not widen the DNS one.
#   CF_ZONE_ID     zone id for feather-reader.com (its own apex zone, NOT a
#                  justin-stanley.com subdomain — the homelab DNS token does not
#                  cover it)
# Optional:
#   FLY_APP        Fly app name (default: featherreader)
#   PUBLIC_URL     public origin to verify through   (default: https://feather-reader.com)
#   DIRECT_URL     *.fly.dev origin to verify against (default: https://featherreader.fly.dev)
#   NEW_SECRET     supply your own value instead of generating one
#
# Usage:
#   CF_API_TOKEN=... CF_ZONE_ID=... ./deploy/rotate-origin-secret.sh            # dry run
#   CF_API_TOKEN=... CF_ZONE_ID=... ./deploy/rotate-origin-secret.sh --commit   # do it
#
# The secret is never printed, never written to disk, and never passed as a
# command-line argument (where it would be visible in `ps`). It exists only in
# this shell's memory, in the Cloudflare rule, and in the Fly secret store.
set -euo pipefail

COMMIT=0
[ "${1:-}" = "--commit" ] && COMMIT=1
[ "${1:-}" = "--dry-run" ] && COMMIT=0

FLY_APP="${FLY_APP:-featherreader}"
PUBLIC_URL="${PUBLIC_URL:-https://feather-reader.com}"
DIRECT_URL="${DIRECT_URL:-https://featherreader.fly.dev}"
PHASE="http_request_late_transform"   # the phase "Modify Request Header" lives in

need() { [ -n "${!1:-}" ] || { echo "FATAL: \$$1 is required" >&2; exit 2; }; }
need CF_API_TOKEN
need CF_ZONE_ID
command -v fly     >/dev/null || { echo "FATAL: flyctl not on PATH" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FATAL: python3 not on PATH" >&2; exit 2; }
command -v openssl >/dev/null || { echo "FATAL: openssl not on PATH" >&2; exit 2; }

api="https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/rulesets/phases/${PHASE}/entrypoint"
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$1"; }

# --- 0. Preflight: the lock must be WORKING before we touch it ---------------
# Rotating a lock that is already broken turns one problem into two, and the
# post-checks below would then be indistinguishable from "the rotation failed".
echo "== preflight =="
before_public=$(code "${PUBLIC_URL}/about")
before_direct=$(code "${DIRECT_URL}/about")
printf '  via Cloudflare /about : %s (want 200)\n' "$before_public"
printf '  direct       /about : %s (want 403)\n' "$before_direct"
if [ "$before_public" != "200" ] || [ "$before_direct" != "403" ]; then
    echo "FATAL: the origin lock is not in a healthy state; fix that before rotating." >&2
    exit 3
fi

# --- 1. Read the ruleset and locate exactly one X-Origin-Auth rule ----------
echo "== reading the Transform Rules ruleset =="
ruleset=$(curl -s --max-time 30 -H "Authorization: Bearer ${CF_API_TOKEN}" \
                 -H "Content-Type: application/json" "$api")

# Everything about the ruleset is handled in python: bash cannot edit JSON
# safely, and a botched PUT replaces the WHOLE phase entrypoint.
summary=$(printf '%s' "$ruleset" | python3 -c '
import json,sys
d=json.load(sys.stdin)
if not d.get("success"):
    print("ERR " + json.dumps(d.get("errors","unknown")));sys.exit(0)
rules=d.get("result",{}).get("rules") or []
hits=[r for r in rules
      if (r.get("action_parameters") or {}).get("headers",{}).get("X-Origin-Auth")]
print("OK %d %d" % (len(rules), len(hits)))
for r in hits:
    h=r["action_parameters"]["headers"]["X-Origin-Auth"]
    print("   rule id=%s enabled=%s op=%s expr=%s" % (
        r.get("id","?"), r.get("enabled"), h.get("operation"),
        (r.get("expression") or "")[:70]))
')
case "$summary" in
    ERR*) echo "FATAL: Cloudflare API error: ${summary#ERR }" >&2; exit 4 ;;
esac
total=$(printf '%s' "$summary" | head -1 | awk '{print $2}')
hits=$(printf '%s'  "$summary" | head -1 | awk '{print $3}')
printf '%s\n' "$summary" | tail -n +2
echo "  rules in phase: ${total}; setting X-Origin-Auth: ${hits}"

# Fail closed on anything ambiguous. Two matching rules means we cannot know
# which one the origin actually honours, and zero means this zone is not the one
# injecting the header — either way, guessing would take the site down.
if [ "$hits" != "1" ]; then
    echo "FATAL: expected exactly 1 rule setting X-Origin-Auth, found ${hits}." >&2
    echo "       Rotate by hand, or fix the ruleset first." >&2
    exit 5
fi

# --- 2. Mint the new value ---------------------------------------------------
# hex, deliberately: Caddy's header matcher treats '*' as a GLOB, so a value
# containing one would accept every header sharing its prefix and the lock would
# silently stop locking. `rand -hex` cannot emit '*'. The entrypoint refuses to
# boot on one too, but that is a backstop, not a reason to generate carelessly.
NEW="${NEW_SECRET:-$(openssl rand -hex 32)}"
case "$NEW" in *"*"*) echo "FATAL: the new secret contains '*'; regenerate." >&2; exit 6 ;; esac
[ ${#NEW} -ge 32 ] || { echo "FATAL: the new secret is shorter than 32 chars." >&2; exit 6; }
echo "  new secret: generated, ${#NEW} chars (never printed)"

if [ "$COMMIT" != "1" ]; then
    cat <<'EOF'

== DRY RUN — nothing was written ==
Would, in this order and back to back:
  1. PUT the Transform Rules ruleset with the new X-Origin-Auth value
  2. fly secrets set FEATHERREADER_ORIGIN_SECRET=<new>   (restarts the machine)
  3. re-verify 200 via Cloudflare and 403 direct

Between 1 and 2 every non-/health request 403s, and Fly will report the machine
healthy throughout. Re-run with --commit when you are ready.
EOF
    exit 0
fi

# --- 3. Write Cloudflare, then Fly, back to back ----------------------------
# The 403 window opens here and closes when the machine is healthy again.
echo "== committing (403 window opens now) =="
new_ruleset=$(printf '%s' "$ruleset" | NEW_VALUE="$NEW" python3 -c '
import json,os,sys
d=json.load(sys.stdin); rs=d["result"]
for r in rs.get("rules",[]):
    hp=(r.get("action_parameters") or {}).get("headers",{})
    if "X-Origin-Auth" in hp:
        hp["X-Origin-Auth"]["value"]=os.environ["NEW_VALUE"]
# PUT takes only the mutable fields; ids/versions are rejected or ignored.
print(json.dumps({k:rs[k] for k in ("rules","name","description") if k in rs}))
')

put=$(printf '%s' "$new_ruleset" | curl -s --max-time 30 -X PUT \
        -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
        --data-binary @- "$api")
ok=$(printf '%s' "$put" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("success"))')
if [ "$ok" != "True" ]; then
    echo "FATAL: the Cloudflare PUT failed; NOTHING changed on Fly, so the lock is intact." >&2
    printf '%s' "$put" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("errors"),indent=2))' >&2
    exit 7
fi
echo "  cloudflare: updated"

# Passed via stdin-free env, not argv — a secret in argv is visible in `ps`.
if ! FEATHERREADER_ORIGIN_SECRET="$NEW" \
     sh -c 'fly secrets set FEATHERREADER_ORIGIN_SECRET="$FEATHERREADER_ORIGIN_SECRET" -a "$0"' "$FLY_APP"; then
    echo "FATAL: the Fly secret did not update, but CLOUDFLARE ALREADY MOVED." >&2
    echo "       The site is 403ing right now. Re-run the fly command, or revert" >&2
    echo "       the Cloudflare rule to the previous value." >&2
    exit 8
fi
echo "  fly: secret set (machine restarting)"

# --- 4. Verify, with the restart allowed for ---------------------------------
echo "== verifying =="
for _ in $(seq 1 60); do
    p=$(code "${PUBLIC_URL}/about")
    [ "$p" = "200" ] && break
    sleep 2
done
after_public=$(code "${PUBLIC_URL}/about")
after_direct=$(code "${DIRECT_URL}/about")
after_empty=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "X-Origin-Auth;" "${DIRECT_URL}/about")
after_health=$(code "${DIRECT_URL}/health")
printf '  via Cloudflare /about      : %s (want 200)\n' "$after_public"
printf '  direct       /about      : %s (want 403)\n' "$after_direct"
printf '  direct  empty header      : %s (want 403)\n' "$after_empty"
printf '  direct       /health      : %s (want 200, the one exemption)\n' "$after_health"

if [ "$after_public" = "200" ] && [ "$after_direct" = "403" ] && [ "$after_empty" = "403" ]; then
    echo "== rotation complete =="
    echo "   The OLD value remains in Fly's log history until it ages out (7 days,"
    echo "   no purge). It now opens nothing."
else
    echo "FATAL: post-rotation verification failed — the two sides may disagree." >&2
    echo "       Check the Cloudflare rule against 'fly secrets list' timestamps." >&2
    exit 9
fi
