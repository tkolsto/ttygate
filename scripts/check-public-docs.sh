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

reject_text() {
  file=$1
  pattern=$2
  description=$3
  if grep -Eiq "$pattern" "$file"; then
    fail "$file still contains $description"
  fi
}

README=README.md
SECURITY=SECURITY.md
THREAT_MODEL=docs/threat-model.md
ROADMAP=docs/roadmap.md
REWRITE_PLAN=docs/ttygate-rewrite-plan.md
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
require_text "$README" 'Chunk 2\.2.*(complete|implemented).*Refs #9|Refs #9.*Chunk 2\.2' 'implemented Chunk 2.2 status'
require_text "$README" 'Chunk 2\.3.*(complete|implemented).*Refs #24|Refs #24.*Chunk 2\.3' 'implemented Chunk 2.3 status'
require_text "$README" 'Chunk 2\.4.*(complete|implemented).*Refs #10|Refs #10.*Chunk 2\.4' 'implemented Chunk 2.4 status'
require_text "$README" '\[audit\].*|audit configuration' 'audit configuration'
require_text "$README" 'literal.*path|path.*literal' 'literal audit destination'
require_text "$README" '0600|owner.only' 'restrictive audit permissions'
require_text "$README" 'JSONL.*append|append.*JSONL' 'append-only JSONL behavior'
require_text "$README" 'terminal input.*(not|never)|exclude.*terminal' 'audit terminal-content secrecy'
require_text "$README" 'actual.*socket peer|listener.*peer' 'audit source provenance'
require_text "$README" 'audit.*(failure|unavailable).*(fail|den|refus)|fail.*audit' 'audit failure policy'
require_text "$README" 'rotation.*retention|retention.*rotation' 'operator retention and rotation responsibility'
require_text "$README" 'filesystem.*trust|trusted filesystem' 'audit filesystem trust boundary'
require_text "$README" '10 session requests.*60 seconds|session requests.*10.*60' 'session request rate defaults'
require_text "$README" '20 authentication failures.*60 seconds|authentication failures.*20.*60' 'authentication failure rate defaults'
require_text "$README" 'fixed.window.*first request|first.request.*fixed.window' 'fixed-window semantics'
require_text "$README" 'global-session-limit.*identity-session-limit' 'distinct concurrency errors'
require_text "$README" 'actual socket peer|socket peer.*authoritative' 'authoritative socket-peer boundary'
require_text "$README" 'requires exactly one occurrence|identity header.*exactly one' 'single identity-header contract'
require_text "$README" 'semantic HTTP.*field value|HTTP parser.*optional whitespace' 'semantic HTTP optional-whitespace contract'
require_text "$README" 'strip every|inject exactly one canonical identity header' 'trusted-proxy strip-and-inject responsibility'
require_text "$README" 'IPv4.mapped|mapped IPv4' 'IPv4-mapped address policy'
require_text "$README" 'session and WSS requests|cookie.*session ticket' 'proxy identity authority propagation'
require_text "$README" 'record.*deploy.*release|recording.*deployment' 'future production controls'
require_text "$README" 'Chunk 3\.1 \(Refs #11\) implements|Chunk 3\.1.*(complete|implemented).*Refs #11' 'implemented Chunk 3.1 status'
require_text "$README" 'StrictHostKeyChecking=yes' 'strict host-key policy'
require_text "$README" 'CertificateFile=/dev/null' 'pinned certificate policy'
require_text "$README" 'ssh_executable' 'ssh executable configuration field'
require_text "$README" 'identity_file' 'ssh identity configuration field'
require_text "$README" 'known_hosts' 'ssh known-hosts configuration field'
require_text "$README" 'user_policy' 'ssh user policy configuration field'
require_text "$README" 'fixed.*same-as-auth-user.*mapping' 'complete user-policy vocabulary'
require_text "$README" 'unencrypted.*Ed25519|Ed25519.*unencrypted' 'unencrypted Ed25519 identity provisioning'
require_text "$README" 'newline-terminated' 'newline-terminated material contract'
require_text "$README" 'capability probe|probes.*ssh -G|ssh -G' 'startup capability probe'
require_text "$README" 'OpenSSH 9\.2' 'OpenSSH compatibility floor'
require_text "$README" 'fails closed before bind|before bind.*fails closed|no weaker runtime fallback' 'fail-closed SSH startup'
require_text "$README" 'ssh-host-key-failed' 'curated SSH host-key error code'
require_text "$README" 'UpdateHostKeys=no|never modifies.*known.hosts' 'no host-key learning'
require_text "$README" 'remote (command|process)(s|es)? (may|can) (outlive|persist|continue)' 'remote-side cleanup limit'
require_text "$README" 'agent forwarding' 'deferred agent scope'
require_text "$README" 'certificate authentication' 'deferred certificate scope'
require_text "$README" 'ProxyJump|bastion' 'deferred proxy scope'
require_text "$README" 'Chunk 4\.1.*(complete|implemented).*Refs #12|Refs #12.*Chunk 4\.1' 'implemented Chunk 4.1 status'
# shellcheck disable=SC2016 # Backticks are literal Markdown delimiters in this regex.
require_text "$README" '\[`?Dockerfile`?\]\(Dockerfile\)' 'Docker package entry point'
require_text "$README" 'packaging/systemd/ttygated\.service' 'systemd package entry point'
require_text "$README" 'UID.*65532|65532.*UID' 'stable container identity'
require_text "$README" 'Type=notify|sd_notify' 'systemd readiness contract'
require_text "$README" 'PrivateNetwork.*(absent|omitted|cannot)|cannot.*PrivateNetwork' 'systemd network namespace exception'
require_text "$README" 'PrivateUsers.*(absent|omitted|cannot)|cannot.*PrivateUsers' 'systemd user namespace exception'
require_text "$README" 'Chunks? 4\.2.*4\.3|4\.2.*and.*4\.3' 'remaining packaging and release scope'
require_text "$THREAT_MODEL" 'Chunk 4\.1.*(implements|implemented).*Docker.*systemd|Docker.*systemd.*Refs #12' 'implemented Chunk 4.1 packaging status'
reject_text "$THREAT_MODEL" 'packaging, deployment examples, and release work remain planned' 'stale all-packaging-is-planned status'
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
require_text "$THREAT_MODEL" 'Chunk 2\.2.*(implemented|enforces)|implemented.*Chunk 2\.2' 'implemented Chunk 2.2 controls'
require_text "$THREAT_MODEL" 'Chunk 2\.3.*(implemented|enforces)|implemented.*Chunk 2\.3' 'implemented Chunk 2.3 controls'
require_text "$THREAT_MODEL" 'Chunk 2\.4.*(implemented|enforces)|implemented.*Chunk 2\.4' 'implemented Chunk 2.4 controls'
require_text "$THREAT_MODEL" 'rotation.*retention|retention.*rotation' 'audit retention and rotation ownership'
require_text "$THREAT_MODEL" 'filesystem.*trust|trusted filesystem' 'audit filesystem trust boundary'
require_text "$THREAT_MODEL" 'durab|fsync|power loss' 'audit durability limit'
require_text "$THREAT_MODEL" 'Forwarded.*X-Forwarded-For.*X-Real-IP.*(not|never)|not.*Forwarded.*rate.limit' 'forwarding-header rate-limit non-authority'
require_text "$THREAT_MODEL" 'distributed.*(remain|residual|not prevent)|does not prevent.*distributed' 'distributed-source residual risk'
require_text "$THREAT_MODEL" 'actual socket peer|socket peer.*authoritative' 'authoritative proxy peer boundary'
require_text "$THREAT_MODEL" 'semantic HTTP field' 'semantic HTTP field-value boundary'
require_text "$THREAT_MODEL" 'optional whitespace.*(parser|removed)|parser.*optional whitespace' 'HTTP optional-whitespace boundary'
require_text "$THREAT_MODEL" 'record.*packag.*release|recording.*packaging' 'future control boundaries'
require_text "$THREAT_MODEL" 'Chunk 3\.1 \(Refs #11\) implements|implemented.*Chunk 3\.1' 'implemented Chunk 3.1 controls'
require_text "$THREAT_MODEL" 'StrictHostKeyChecking=yes' 'implemented strict host-key mitigation'
require_text "$THREAT_MODEL" 'CertificateFile=/dev/null' 'pinned implicit-certificate mitigation'
require_text "$THREAT_MODEL" 'option lexer|re-lex|expansion syntax' 'SSH option-value grammar boundary'
require_text "$THREAT_MODEL" 'unencrypted.*(identity|private key)|daemon-readable.*(identity|private key)' 'daemon-readable identity residual risk'
require_text "$THREAT_MODEL" 'remote (command|process)(s|es)? (may|can) (outlive|persist|continue)' 'remote-process residual risk'
require_text "$THREAT_MODEL" 'known.hosts.*(operator|accuracy|provision)|operator.*known.hosts' 'operator known-hosts responsibility'

require_file "$ROADMAP"
require_text "$ROADMAP" 'Chunk 2\.2.*Trusted reverse-proxy auth provider' 'Chunk 2.2 heading'
require_text "$ROADMAP" 'Status.*complete.*Refs #9' 'complete Chunk 2.2 roadmap status'
require_text "$ROADMAP" 'Chunk 2\.3.*Rate and concurrency limits' 'Chunk 2.3 heading'
require_text "$ROADMAP" 'Status.*complete.*Refs #24' 'complete Chunk 2.3 roadmap status'
require_text "$ROADMAP" 'Chunk 2\.4.*Audit subsystem' 'Chunk 2.4 heading'
require_text "$ROADMAP" 'Status.*complete.*Refs #10' 'complete Chunk 2.4 roadmap status'
require_text "$ROADMAP" 'M2 exit.*complete|M2.*Status.*complete' 'complete M2 status'
require_text "$ROADMAP" 'Chunk 3\.1.*OpenSSH subprocess target' 'Chunk 3.1 heading'
require_text "$ROADMAP" 'Status.*complete.*Refs #11' 'complete Chunk 3.1 roadmap status'
require_text "$ROADMAP" 'M3 exit.*complete|M3.*Status.*complete' 'complete M3 status'

require_file "$REWRITE_PLAN"
require_text "$REWRITE_PLAN" 'Implemented in Chunk 2\.2.*Refs #9|Chunk 2\.2.*implemented.*Refs #9' 'implemented Chunk 2.2 rewrite-plan status'
require_text "$REWRITE_PLAN" 'Implemented in Chunk 2\.3.*Refs #24|Chunk 2\.3.*implemented.*Refs #24' 'implemented Chunk 2.3 rewrite-plan status'
require_text "$REWRITE_PLAN" 'Implemented in Chunk 2\.4.*Refs #10|Chunk 2\.4.*implemented.*Refs #10' 'implemented Chunk 2.4 rewrite-plan status'
require_text "$REWRITE_PLAN" 'global-session-limit.*identity-session-limit' 'stable concurrency error codes'
require_text "$REWRITE_PLAN" 'semantic HTTP field' 'rewrite-plan semantic HTTP field-value contract'
require_text "$REWRITE_PLAN" 'optional whitespace.*(parser|framing)|parser.*optional whitespace' 'rewrite-plan HTTP optional-whitespace contract'
require_text "$REWRITE_PLAN" 'Implemented in Chunk 3\.1.*Refs #11|Chunk 3\.1.*implement.*Refs #11' 'implemented Chunk 3.1 rewrite-plan status'
require_text "$REWRITE_PLAN" 'ssh_executable' 'rewrite-plan ssh executable field'
require_text "$REWRITE_PLAN" 'identity_file' 'rewrite-plan ssh identity field'
require_text "$REWRITE_PLAN" 'Phase 3.*(complete|implemented)|M3.*complete' 'complete rewrite-plan Phase 3 status'

if grep -Eini 'contract-only|does not yet trust( or consume)? the identity header|provider unavailable|trusted-proxy enforcement remains Chunk 2\.2|Future in Chunk 2\.2|production authentication (and|is|remains)[^.]*planned' \
  "$README" "$THREAT_MODEL" "$ROADMAP" "$REWRITE_PLAN"; then
  fail 'public docs still describe trusted-proxy authentication as unavailable'
fi

if grep -Eini 'SSH( execution)?(, [^.]*)? remains? (planned|future|incomplete)|SSH backend is not (yet )?implemented|SSH, recording|later audit, SSH|but SSH[^.]*planned' \
  "$README" "$THREAT_MODEL" "$ROADMAP" "$REWRITE_PLAN"; then
  fail 'public docs still describe the SSH backend as unimplemented'
fi

require_file "$PROTOCOL"
for heading in 'Scope' 'Versioning and compatibility' 'WebSocket framing' 'Control messages' 'Validation and limits' 'Protocol errors and close semantics' 'Backpressure'; do
  require_text "$PROTOCOL" "^#+[[:space:]]+$heading" "$heading section"
done
require_text "$PROTOCOL" 'ssh-host-key-failed' 'protocol SSH host-key error code'
require_text "$PROTOCOL" 'Unknown and mismatched host keys' 'shared host-key failure statement'

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
