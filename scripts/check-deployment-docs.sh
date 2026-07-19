#!/bin/sh

# Regex contracts below intentionally single-quote literal Nginx $variables.
# shellcheck disable=SC2016

set -eu

fail() {
  printf 'deployment docs check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "$1 is missing"
}

require_executable() {
  [ -x "$1" ] || fail "$1 is not executable"
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
    fail "$file contains $description"
  fi
}

require_job_text() {
  job=$1
  pattern=$2
  description=$3
  job_text=$(
    awk -v heading="  $job:" '
      $0 == heading { inside = 1; next }
      inside && $0 ~ /^  [A-Za-z0-9_-]+:/ { exit }
      inside { print }
    ' "$CI"
  )
  [ -n "$job_text" ] || fail "$CI lacks $job job"
  printf '%s\n' "$job_text" | grep -Eq "$pattern" ||
    fail "$CI $job job lacks $description"
}

CADDY=packaging/reverse-proxy/Caddyfile
NGINX=packaging/reverse-proxy/nginx.conf
CONFIG=packaging/reverse-proxy/ttygate.toml
GUIDE=packaging/reverse-proxy/README.md
SMOKE=scripts/smoke-reverse-proxy.sh
AUTH_FIXTURE=scripts/fixtures/reverse-proxy-auth.mjs
SESSION_FIXTURE=scripts/fixtures/reverse-proxy-session.mjs
CI=.github/workflows/ci.yml
README=README.md
ROADMAP=docs/roadmap.md
REWRITE_PLAN=docs/ttygate-rewrite-plan.md
THREAT_MODEL=docs/threat-model.md
DOCKERIGNORE=.dockerignore

for file in \
  "$CADDY" \
  "$NGINX" \
  "$CONFIG" \
  "$GUIDE" \
  "$SMOKE" \
  "$AUTH_FIXTURE" \
  "$SESSION_FIXTURE"; do
  require_file "$file"
done
require_executable "$SMOKE"
require_file "$DOCKERIGNORE"
require_text "$DOCKERIGNORE" '^\.ttygate-chunk42-\*$' 'ephemeral proxy fixture exclusion'

# Caddy terminates TLS, delegates authentication, copies one authenticated
# identity over any client value, removes upstream credentials, and proxies
# every path. Do not rewrite the copied header again: Caddy evaluates
# reverse_proxy header placeholders after header deletion.
require_text "$CADDY" 'terminal\.example\.invalid:8443' 'reserved external HTTPS authority'
require_text "$CADDY" 'tls[[:space:]]+/etc/ttygate-proxy/tls/certificate\.pem[[:space:]]+/etc/ttygate-proxy/tls/private-key\.pem' 'operator-supplied TLS material'
require_text "$CADDY" 'forward_auth[[:space:]]+auth-gateway:9000' 'authentication subrequest'
require_text "$CADDY" 'uri[[:space:]]+/verify' 'fixed authentication verification endpoint'
require_text "$CADDY" 'copy_headers[[:space:]]+X-Authenticated-User' 'canonical authenticated identity copy'
require_text "$CADDY" 'request_header[[:space:]]+-X-Authenticated-User' 'client identity removal before authentication'
require_text "$CADDY" 'header_up[[:space:]]+-Authorization' 'authorization removal'
require_text "$CADDY" 'header_up[[:space:]]+Host[[:space:]]+\{http\.request\.host\}' 'external Host preservation'
require_text "$CADDY" 'reverse_proxy[[:space:]]+ttygated:7681' 'private ttygate backend'
reject_text "$CADDY" 'tls[[:space:]]+internal|tls_insecure' 'insecure TLS convenience'
reject_text "$CADDY" 'header_up[[:space:]]+[+-]?X-Authenticated-User' 'post-auth identity rewrite'

# Nginx has an explicit redirect, TLS listener, auth_request flow, identity
# replacement, and HTTP/1.1 hop-by-hop header forwarding for WebSockets.
require_text "$NGINX" 'listen[[:space:]]+8080' 'plaintext redirect listener'
require_text "$NGINX" 'return[[:space:]]+308[[:space:]]+https://terminal\.example\.invalid:8443\$request_uri' 'fixed-authority HTTPS redirect'
require_text "$NGINX" 'listen[[:space:]]+8443[[:space:]]+ssl' 'TLS listener'
require_text "$NGINX" 'server_name[[:space:]]+terminal\.example\.invalid' 'reserved external authority'
require_text "$NGINX" 'ssl_certificate[[:space:]]+/etc/ttygate-proxy/tls/certificate\.pem' 'certificate path'
require_text "$NGINX" 'ssl_certificate_key[[:space:]]+/etc/ttygate-proxy/tls/private-key\.pem' 'private-key path'
require_text "$NGINX" 'auth_request[[:space:]]+/_ttygate_auth' 'authentication subrequest'
require_text "$NGINX" 'auth_request_set[[:space:]]+\$authenticated_identity[[:space:]]+\$upstream_http_x_authenticated_user' 'canonical auth response capture'
require_text "$NGINX" 'proxy_set_header[[:space:]]+X-Authenticated-User[[:space:]]+""' 'client identity removal before authentication'
require_text "$NGINX" 'proxy_set_header[[:space:]]+Authorization[[:space:]]+""' 'authorization removal'
require_text "$NGINX" 'proxy_set_header[[:space:]]+X-Authenticated-User[[:space:]]+\$authenticated_identity' 'client identity replacement'
require_text "$NGINX" 'proxy_set_header[[:space:]]+Host[[:space:]]+\$http_host' 'external Host preservation'
require_text "$NGINX" 'proxy_http_version[[:space:]]+1\.1' 'HTTP/1.1 upstream transport'
require_text "$NGINX" 'proxy_set_header[[:space:]]+Upgrade[[:space:]]+\$http_upgrade' 'WebSocket Upgrade forwarding'
require_text "$NGINX" 'proxy_set_header[[:space:]]+Connection[[:space:]]+\$connection_upgrade' 'conditional WebSocket Connection forwarding'
require_text "$NGINX" 'server[[:space:]]+ttygated:7681' 'private ttygate backend'
require_text "$NGINX" 'proxy_pass[[:space:]]+http://ttygate_backend' 'private ttygate upstream use'
require_text "$NGINX" 'client_body_temp_path[[:space:]]+/tmp/' 'read-only-root client temp path'
require_text "$NGINX" 'fastcgi_temp_path[[:space:]]+/tmp/' 'read-only-root FastCGI temp path'
require_text "$NGINX" 'proxy_temp_path[[:space:]]+/tmp/' 'read-only-root proxy temp path'
require_text "$NGINX" 'scgi_temp_path[[:space:]]+/tmp/' 'read-only-root SCGI temp path'
require_text "$NGINX" 'uwsgi_temp_path[[:space:]]+/tmp/' 'read-only-root uwsgi temp path'
reject_text "$NGINX" 'ssl_verify_client[[:space:]]+off|proxy_ssl_verify[[:space:]]+off' 'explicit TLS verification weakening'
reject_text "$NGINX" 'return[[:space:]]+30[1278][[:space:]]+https://\$host' 'client-controlled redirect authority'

# The matching application config is production-only, externally HTTPS, and
# trusts one conspicuous documentation address rather than forwarding claims.
require_text "$CONFIG" '^bind[[:space:]]*=[[:space:]]*"0\.0\.0\.0:7681"$' 'private service-network listener'
require_text "$CONFIG" '^mode[[:space:]]*=[[:space:]]*"production"$' 'production mode'
require_text "$CONFIG" '^public_url[[:space:]]*=[[:space:]]*"https://terminal\.example\.invalid:8443"$' 'matching external HTTPS public URL'
require_text "$CONFIG" '^trusted_sources[[:space:]]*=[[:space:]]*\["192\.0\.2\.10/32"\]$' 'single documentation proxy address'
require_text "$CONFIG" '^provider[[:space:]]*=[[:space:]]*"trusted-proxy"$' 'trusted-proxy authentication'
require_text "$CONFIG" '^identity_header[[:space:]]*=[[:space:]]*"x-authenticated-user"$' 'matching canonical identity header'
require_text "$CONFIG" '^recording[[:space:]]*=[[:space:]]*false$' 'disabled recording'
require_text "$CONFIG" 'type[[:space:]]*=[[:space:]]*"pty"' 'local PTY target example'
require_text "$CONFIG" 'type[[:space:]]*=[[:space:]]*"ssh"' 'strict SSH target example'
require_text "$CONFIG" 'StrictHostKeyChecking|known_hosts' 'strict host-key material'
reject_text "$CONFIG" '0\.0\.0\.0/0|::/0|provider[[:space:]]*=[[:space:]]*"dev"|public_url[[:space:]]*=[[:space:]]*"http://' 'unsafe production application setting'

# Operator documentation owns all deployment and residual-risk boundaries.
for pattern in \
  'browser.*TLS.*proxy|TLS.*proxy.*browser' \
  'only.*proxy.*reach' \
  'backend listener' \
  'actual socket peer' \
  'Forwarded.*(not|never).*authority|not.*trust.*Forwarded' \
  '(strip|remove|replace).*client.*identity' \
  'public_url.*Origin|Origin.*public_url' \
  'WebSocket' \
  'Secure.*HttpOnly.*SameSite|secure cookie' \
  'compromised.*proxy.*impersonat' \
  'Cloudflare Access' \
  'validate.*JWT|JWT.*signature' \
  'Tailscale-User-Login' \
  'Funnel.*(not|does not).*identity|identity.*not.*Funnel' \
  'localhost|loopback' \
  '0600|owner.only' \
  'rotation.*retention.*shipping|retention.*rotation' \
  '(does not|never|exclude).*terminal input|terminal input.*(not|never)' \
  'test certificate.*not.*production|not.*production.*test certificate|test-only.*not.*production' \
  'Caddy.*Nginx|Nginx.*Caddy' \
  'caddy validate' \
  'nginx -t' \
  'Refs #12'; do
  require_text "$GUIDE" "$pattern" "operator guidance matching $pattern"
done
require_text "$GUIDE" 'https://caddyserver\.com/docs/' 'official Caddy documentation link'
require_text "$GUIDE" 'https://nginx\.org/en/docs/' 'official Nginx documentation link'
require_text "$GUIDE" 'https://developers\.cloudflare\.com/' 'official Cloudflare documentation link'
require_text "$GUIDE" 'https://tailscale\.com/docs/' 'official Tailscale documentation link'
reject_text "$GUIDE" 'self.signed.*is production.safe|trust CF-Access-Authenticated-User-Email alone' 'unsafe provider or certificate claim'

# The shared harness must validate and exercise both exact configurations,
# scan audit secrecy, and guarantee cleanup.
for pattern in \
  'caddy validate' \
  'nginx -t' \
  'openssl.*req' \
  'reverse-proxy-session\.mjs' \
  'untrusted.*peer' \
  'public_url' \
  'development.*auth|provider.*dev' \
  'plaintext.*production' \
  'audit' \
  'docker rm' \
  'docker network rm' \
  'attacker\.example\.invalid' \
  'image reference must be digest-pinned' \
  'trap.*EXIT'; do
  require_text "$SMOKE" "$pattern" "smoke coverage matching $pattern"
done
require_text "$SMOKE" 'trap.*HUP.*INT.*TERM' 'signal cancellation cleanup'
require_text "$AUTH_FIXTURE" 'X-Authenticated-User' 'synthetic canonical identity'
require_text "$AUTH_FIXTURE" 'authorization' 'synthetic upstream authentication'
require_text "$SESSION_FIXTURE" 'Sec-WebSocket-Key' 'WebSocket lifecycle'
require_text "$SESSION_FIXTURE" 'Sec-WebSocket-Accept' 'WebSocket handshake proof'
require_text "$SESSION_FIXTURE" 'node:tls|connect.*servername' 'TLS-protected WebSocket transport'
require_text "$SESSION_FIXTURE" '/api/sessions' 'ticket issuance'
require_text "$SESSION_FIXTURE" '/healthz' 'proxied health check'
require_text "$SESSION_FIXTURE" 'missing authentication' 'missing authenticated identity denial'
require_text "$SESSION_FIXTURE" 'spoofed-user' 'client identity spoof rejection'
require_text "$SESSION_FIXTURE" 'wrong-origin' 'incorrect Origin denial'
require_text "$SESSION_FIXTURE" 'scanAuditText' 'complete audit secrecy scan'
require_text "$SESSION_FIXTURE" 'starts\.size !== ends\.size' 'exact audit lifecycle correlation'
require_text "$SESSION_FIXTURE" 'terminal_input' 'terminal input audit exclusion'
require_text "$SESSION_FIXTURE" 'terminal_output' 'terminal output audit exclusion'

# Required CI uses separate immutable proxy jobs and publishes no artifacts.
require_text "$CI" '^  caddy-deployment:' 'separate Caddy deployment job'
require_text "$CI" '^  nginx-deployment:' 'separate Nginx deployment job'
for job in caddy-deployment nginx-deployment; do
  require_job_text "$job" '^    runs-on: ubuntu-latest$' 'Linux runner'
  require_job_text "$job" '^    timeout-minutes: [1-9][0-9]*$' 'bounded timeout'
  require_job_text "$job" 'actions/checkout@[0-9a-f]{40}' 'immutable checkout action'
done
require_job_text caddy-deployment 'caddy:[^[:space:]]+@sha256:[0-9a-f]{64}' 'digest-pinned Caddy image'
require_job_text caddy-deployment '\./scripts/smoke-reverse-proxy\.sh caddy' 'Caddy smoke lifecycle'
require_job_text nginx-deployment 'nginx:[^[:space:]]+@sha256:[0-9a-f]{64}' 'digest-pinned Nginx image'
require_job_text nginx-deployment '\./scripts/smoke-reverse-proxy\.sh nginx' 'Nginx smoke lifecycle'
reject_text "$CI" 'actions/upload-artifact|gh[[:space:]]+release|action-gh-release|attest-build-provenance|sbom|cosign' 'Chunk 4.3 publication behavior'

# Public documents must complete Chunk 4.2 while retaining the release gate.
for pattern in \
  'production deployment checklist' \
  'auth(entication)? provider.*matrix' \
  'local PTY' \
  'strict.host.key.*SSH|SSH.*strict.host.key' \
  'schema_version.*event_type|synthetic audit' \
  'Shell In A Box' \
  'shared.*OS user|same.*OS user' \
  'no arbitrary command|browser.*not.*command' \
  'no native SSH|OpenSSH subprocess' \
  'no automatic host.key learning|UpdateHostKeys=no' \
  'no built.in Cloudflare|Cloudflare.*not built.in' \
  'no native ACME|ACME.*not' \
  'Chunk 4\.3' \
  'pre-release|not production.ready'; do
  require_text "$README" "$pattern" "README checklist matching $pattern"
done
require_text "$ROADMAP" 'Chunk 4\.2.*complete.*Refs #12|Status.*complete.*Refs #12' 'complete Chunk 4.2 status'
require_text "$REWRITE_PLAN" 'Chunk 4\.2.*complete.*Refs #12|verified.*Caddy.*Nginx' 'verified Phase 4 deployment status'
require_text "$THREAT_MODEL" 'Chunk 4\.2.*(implements|implemented).*Caddy.*Nginx|verified.*reverse.proxy' 'implemented deployment mitigation'
for file in "$README" "$ROADMAP" "$REWRITE_PLAN" "$THREAT_MODEL"; do
  require_text "$file" 'Chunk 4\.3|release.*remain' 'remaining Chunk 4.3 release gate'
done

printf 'All deployment documentation checks passed.\n'
