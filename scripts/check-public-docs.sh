#!/bin/sh

set -eu

fail() {
  printf 'public docs check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "$1 is missing"
}

require_text() {
  file=$1
  pattern=$2
  description=$3
  grep -Eiq "$pattern" "$file" || fail "$file lacks $description"
}

README=README.md
SECURITY=SECURITY.md
THREAT_MODEL=docs/threat-model.md
PROTOCOL=docs/protocol.md
ISSUE_CONFIG=.github/ISSUE_TEMPLATE/config.yml
BUG_FORM=.github/ISSUE_TEMPLATE/bug-report.yml
SECURITY_FORM=.github/ISSUE_TEMPLATE/security-sensitive-change.yml

require_file "$README"
require_text "$README" 'security-first browser terminal gateway' 'security-first positioning'
require_text "$README" 'browser terminals.*security-sensitive|shell-equivalent' 'browser-terminal warning'
require_text "$README" 'localhost.*(not|does not).*security boundary|malicious.*website|DNS rebinding' 'localhost browser-risk warning'
require_text "$README" 'pre-release' 'pre-release status'
require_text "$README" 'xterm\.js browser terminal|browser.*terminal flow' 'implemented M1 browser terminal'
require_text "$README" 'production.*(not implemented|still planned|not.*safe)|not make.*production-safe' 'pre-release production limitation'
require_text "$README" 'mode.*dev.*production|production mode' 'implemented mode gating'
require_text "$README" 'dev(elopment)? identity.*loopback|loopback.*dev(elopment)? identity' 'loopback-only development identity'
require_text "$README" 'direct TLS|rustls' 'implemented direct TLS listener'
require_text "$README" 'no (plaintext|HTTP) fallback|never falls back.*(plaintext|HTTP)' 'no plaintext fallback'
require_text "$README" 'certificate.*private.key|private.key.*certificate' 'direct TLS certificate and key configuration'
require_text "$README" 'stable.*(secret|path)|secret.safe.*(error|diagnostic)|diagnostic.*(not|never).*path' 'secret-safe TLS startup diagnostics'
require_text "$README" 'contract.only|does not yet trust.*identity header|Chunk 2\.2.*trusted.*proxy' 'contract-only trusted-proxy boundary'
require_text "$README" 'rate limit.*audit.*SSH.*record|audit.*SSH.*record.*packag' 'future production controls'
require_text "$README" 'Refs #8' 'Chunk 2.1 changelog reference'
require_text "$README" 'cargo test --workspace' 'Rust verification command'
require_text "$README" 'npm.*(test:e2e|run test:e2e)' 'frontend browser-test command'
require_text "$README" '127\.0\.0\.1|localhost-only' 'localhost-only default'
require_text "$README" 'inspired by Shell In A Box' 'Shell In A Box inspiration statement'
require_text "$README" 'not a fork' 'not-a-fork statement'
require_text "$README" 'clean-room' 'clean-room rule'
require_text "$README" '\(SECURITY\.md\)' 'security policy link'
require_text "$README" '\(docs/threat-model\.md\)' 'threat-model link'
require_text "$README" '\(CONTRIBUTING\.md\)' 'contribution link'
require_text "$README" '\(LICENSE-MIT\)' 'MIT license link'
require_text "$README" '\(LICENSE-APACHE\)' 'Apache license link'

require_file "$SECURITY"
require_text "$SECURITY" 'github\.com/tkolsto/ttygate/security/advisories/new' 'private advisory URL'
require_text "$SECURITY" 'do not.*public (issue|discussion|pull request)|not.*public (issue|discussion|pull request)' 'public-disclosure warning'
require_text "$SECURITY" 'acknowledge|assessment|coordinate' 'maintainer response process'
require_text "$SECURITY" 'no guaranteed response|cannot promise|no response-time guarantee' 'non-guaranteed response time'
require_text "$SECURITY" 'supported versions' 'supported-version policy'
require_text "$SECURITY" 'latest.*main' 'pre-release main-branch support'
require_text "$SECURITY" 'no released versions|no releases' 'absence of releases'

require_file "$THREAT_MODEL"
for heading in 'Scope and status' 'Security objectives' 'Assets' 'Trust boundaries' 'Attacker capabilities' 'Threats and planned mitigations' 'Dangerous anti-features' 'Residual risks' 'Maintaining this model'; do
  require_text "$THREAT_MODEL" "^#+[[:space:]]+$heading" "$heading section"
done
require_text "$THREAT_MODEL" 'shared (daemon.s )?OS user|shared OS user|same Unix user' 'shared OS-user residual risk'
require_text "$THREAT_MODEL" 'recordings.*sensitive|sensitive.*recordings' 'recording sensitivity'
require_text "$THREAT_MODEL" 'malicious (websites|sites)|cross-site WebSocket' 'malicious-browser attacker'
require_text "$THREAT_MODEL" 'DNS rebinding' 'DNS-rebinding threat'
require_text "$THREAT_MODEL" 'out of scope|non-goals' 'out-of-scope assumptions'
require_text "$THREAT_MODEL" 'pre-release|not yet implemented|planned' 'implementation-status distinction'
require_text "$THREAT_MODEL" 'Chunk 2\.1.*(implemented|enforces)|implemented.*Chunk 2\.1' 'implemented Chunk 2.1 controls'
require_text "$THREAT_MODEL" 'trusted.proxy.*(contract.only|Chunk 2\.2)|Chunk 2\.2.*trusted.proxy' 'future trusted-proxy identity enforcement'
require_text "$THREAT_MODEL" 'rate limit.*audit.*SSH.*record|audit.*SSH.*record.*packag' 'future control boundaries'

require_file "$PROTOCOL"
for heading in 'Scope' 'Versioning and compatibility' 'WebSocket framing' 'Control messages' 'Validation and limits' 'Protocol errors and close semantics' 'Backpressure'; do
  require_text "$PROTOCOL" "^#+[[:space:]]+$heading" "$heading section"
done

require_file "$ISSUE_CONFIG"
require_text "$ISSUE_CONFIG" 'blank_issues_enabled:[[:space:]]*false' 'disabled blank issues'
require_text "$ISSUE_CONFIG" 'security/advisories/new' 'private-reporting contact'
require_file "$BUG_FORM"
require_text "$BUG_FORM" 'security/advisories/new' 'private vulnerability routing'
require_text "$BUG_FORM" 'remove.*(secret|sensitive)|redact' 'secret-redaction warning'
require_text "$BUG_FORM" 'not.*(vulnerability|security vulnerability)' 'public-disclosure confirmation'
require_file "$SECURITY_FORM"
require_text "$SECURITY_FORM" 'not.*(vulnerability|security vulnerability)' 'public-change vulnerability warning'
require_text "$SECURITY_FORM" 'threat.model' 'threat-model impact field'
require_text "$SECURITY_FORM" 'trust boundar' 'trust-boundary field'
require_text "$SECURITY_FORM" 'negative|abuse' 'negative-path field'

if grep -Eini '\b(TODO|FIXME|master)\b|generated by|AI attribution' \
  "$README" "$SECURITY" "$THREAT_MODEL" "$ISSUE_CONFIG" "$BUG_FORM" "$SECURITY_FORM"; then
  fail 'delivered public docs contain prohibited text'
fi

printf 'All public documentation checks passed.\n'
