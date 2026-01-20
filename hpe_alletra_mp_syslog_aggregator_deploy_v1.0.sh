##################################################################################
#  Copyright 2026 Hewlett Packard Enterprise Development LP						 #
#																				 #
#  Licensed under the Apache License, Version 2.0 (the "License");				 #
#  you may not use this file except in compliance with the License.				 #
#  You may obtain a copy of the License at										 #
#																				 #
#  http://www.apache.org/licenses/LICENSE-2.0									 #
#																				 #
#  Unless required by applicable law or agreed to in writing, software			 #
#  distributed under the License is distributed on an "AS IS" BASIS,			 #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		 #
#  See the License for the specific language governing permissions and			 #
#  limitations under the License.												 #
##################################################################################
#  SPDX-FileCopyrightText:  Copyright Hewlett Packard Enterprise Development LP  #
##################################################################################

#!/usr/bin/env bash
set -euo pipefail

########################################
# Settings (no td-agent)
########################################
SVC=fluentd
CONF=/etc/fluent/fluentd.conf

CERT_DIR=/etc/fluentd/certs
ENV_DIR=/etc/fluentd/env
LOG_DIR=/var/log/hpe
BUFFER_DIR=$LOG_DIR/buffer

SERVER_KEY=$CERT_DIR/server.key
SERVER_CRT=$CERT_DIR/server.crt
CA_CRT=$CERT_DIR/ca.crt
CSR_PATH=$CERT_DIR/server.csr
CSR_CONF=$CERT_DIR/csr.conf
ENV_FILE=$ENV_DIR/transport.env

SYMLINK_HELPER=/usr/local/sbin/fluentd-host-symlinks.sh
SYMLINK_SERVICE=/etc/systemd/system/fluentd-host-symlinks.service
SYMLINK_TIMER=/etc/systemd/system/fluentd-host-symlinks.timer

FLUENTD_USER="_fluentd"
FLUENTD_GROUP="_fluentd"

log()  { printf "\n[+] %s\n" "$*"; }
warn() { printf "\n[!] %s\n" "$*" >&2; }

########################################
# 1) Install Fluentd v6 LTS for Ubuntu Noble
########################################
install_fluentd() {
  if ! systemctl list-unit-files | grep -q '^fluentd\.service'; then
    log "Installing Fluentd (fluent-package v6 LTS) for Ubuntu Noble..."
    curl -fsSL https://fluentd.cdn.cncf.io/sh/install-ubuntu-noble-fluent-package6-lts.sh | sudo sh
  else
    log "Fluentd already installed; proceeding."
  fi
  
  if ! sudo fluent-gem list | grep '^fluent-plugin-rewrite-tag-filter'; then
    sudo fluent-gem install fluent-plugin-rewrite-tag-filter
  else
    log " Fluentd plugin rewrite-tag-filter already installed; proceeding."
  fi
}

########################################
# 2) Prepare directories
########################################
ensure_dirs() {
  sudo install -d -m 0755 -o root -g root /etc/fluentd
  sudo install -d -m 0750 -o root -g "${FLUENTD_GROUP}" "$CERT_DIR"
  sudo install -d -m 0750 -o root -g "${FLUENTD_GROUP}" "$ENV_DIR"
  sudo install -d -m 0775 -o root -g _fluentd "$LOG_DIR"
  sudo install -d -m 0775 -o root -g _fluentd "$BUFFER_DIR"
}

########################################
# 3) Environment file for passphrase
########################################
write_env_file() {
  if [ ! -f "$ENV_FILE" ]; then
    log "Generating strong random passphrase, writing EnvironmentFile"
    PASSPHRASE=$(openssl rand -base64 48 | tr -d '\n')
    printf "FLUENTD_TLS_KEY_PASSPHRASE=%s\n" "$PASSPHRASE" | sudo tee "$ENV_FILE" >/dev/null
  fi
  sudo chown root:"${FLUENTD_GROUP}" "$ENV_FILE"
  sudo chmod 0640 "$ENV_FILE"

  # systemd override to load the env file
  sudo install -d -m 0755 -o root -g root "/etc/systemd/system/${SVC}.service.d"
  cat <<EOF | sudo tee "/etc/systemd/system/${SVC}.service.d/override.conf" >/dev/null
[Service]
EnvironmentFile=$ENV_FILE
EOF
}

########################################
# 4) Write Fluentd configuration (TLS + per-host files)
########################################
write_fluentd_config() {
  log "Writing Fluentd configuration to $CONF"
  sudo tee "$CONF" >/dev/null <<'EOFCONF'
# =========================
# System / Fluentd own logs
# =========================
<system>
  <log>
    rotate_age 7
    rotate_size 104857600
  </log>
</system>

# =========================
# Source: Syslog over TLS
# =========================
<source>
  @type syslog
  @id in_syslog_tls_alletra
  tag alletra.syslog
  port 6514
  bind 0.0.0.0
  message_length_limit 8192
  <transport tls>
    cert_path           /etc/fluentd/certs/server.crt
    private_key_path    /etc/fluentd/certs/server.key
    private_key_passphrase "#{ENV['FLUENTD_TLS_KEY_PASSPHRASE']}"
    client_cert_auth    false
    version             TLS1_2
  </transport>
  <parse>
    @type regexp
    expression /^(?:<\d+>)?(?<event.ingested>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+3PAR_(?<host.name>\S+)\s+(?:(?:MsgCode: 0x[0-9a-fA-F]+ )?)(?<event.provider>\S+)\s+(?<event.module>\S+)\s+(?<message>.+)$/
  </parse>
</source>

# ==========================================
# Filter unwanted
# ==========================================

<filter **>
  @type grep
  <or>
    <exclude>
      key message  
      pattern /\b127\.(\d{1,3}\.){2}\d{1,3}\b(:\d+)?/
    </exclude>

    <exclude>
      key event.provider
      pattern /(^cli_auth_info_sock$|^user_auth_succeded$)/i
    </exclude>
  </or>
</filter>

# ==========================================
# Tag based on event.dataset
# ==========================================

<match alletra.syslog.**>
  @type rewrite_tag_filter
  emit_mode record

# Audit logs
  <rule>
    key event.provider
    pattern /^audit_log_record$/i
    tag audit.log
  </rule>

# Authentication logs
  <rule>
    key event.provider
    pattern /^ssh_bad_password$/i
    tag ssh.login.fail
  </rule>
  <rule>
    key event.provider
    pattern /^cli_auth_success$/i
    tag cli.auth.success
  </rule>
  <rule>
    key event.provider
    pattern /^cli_auth_logout$/i
    tag cli.auth.logout
  </rule>
  <rule>
    key event.provider
    pattern /^wsapi_concurrent_login$/i
    tag wsapi.concurrent.login
  </rule>
  <rule>
    key event.provider
    pattern /^user_auth_succeeded$/i
    tag auth.user.succeeded
  </rule>
  <rule>
    key event.provider
    pattern /^user_locked$/i
    tag user.locked
  </rule>

# Ransomware monitoring
  <rule>
    key event.provider
    pattern /^sysmgr_rware_alert_snap$/i
    tag rware.snap
  </rule>
  <rule>
    key event.provider
    pattern /^rware_monitoring$/i
    tag rware.detect
  </rule>
  
# Root Activity
  <rule>
    key event.provider
    pattern /^root_activity_login$/i
    tag root.login
  </rule>
  <rule>
    key event.provider
    pattern /^root_activity_logout$/i
    tag root.logout
  </rule>
  <rule>
    key event.provider
    pattern /^root_activity_command$/i
    tag root.command
  </rule>

# CLI error
  <rule>
    key event.provider
    pattern /^cli_cmd_err_args$/i
    tag cli.error
  </rule>

</match>


# Second filter: catch-all for anything not retagged above
<match alletra.syslog.**>
  @type rewrite_tag_filter
  emit_mode record

  # If event.dataset exists but isn't one of the known values
  <rule>
    key event.provider
    pattern /^((?!user_locked|cli_cmd_err_args|user_auth_succeded|user_auth_succeeded|audit_log_record|wsapi_concurrent_login|cli_auth_info_sock|cli_auth_success|cli_auth_logout|rware_monitoring|sysmgr_rware_alert_snap|root_activity_login|root_activity_logout|root_activity_command).)*$/i
    tag other
  </rule>

  # If event.dataset is missing entirely, fall back to message presence
  <rule>
    key message
    pattern /.+/
    tag other
  </rule>
</match>


# =========================================================
# ROOT ACTIVITY
# =========================================================

<filter root.command>
  @type record_transformer
  enable_ruby true
  <record>
    # --- Extraction from the message ---
    # --- Layout expected: 
    # --- root[PID]: <src_ip> <src_port> <dst_ip> <dst_port>: /root: <command>
    source.ip             ${record["message"][/root\[\d+\]:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+:\s+\/root:\s+(.+?)$/, 1]}
    source.port           ${record["message"][/root\[\d+\]:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+:\s+\/root:\s+(.+?)$/, 2]}
    process.command_line  ${record["message"][/root\[\d+\]:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+:\s+\/root:\s+(.+?)$/, 3]}
    user.name             root
    # --- ECS event classification ---
    event.kind      alert
    event.type      indicator
    event.category  threat
    event.action    root_activity
    event.severity  73
  </record>
</filter>

<filter root.login>
  @type record_transformer
  enable_ruby true
  <record>
    source.ip       ${record["message"][/from\s+(\d+\.\d+\.\d+\.\d+)/, 1]}
    user.name       root
    # --- ECS event classification
    event.kind      alert
    event.type      indicator
    event.category  ["authentication","threat"]
    event.action    root_login
    event.outcome   success
    event.severity  73
  </record>
</filter>
# =========================================================
# AUDIT LOGS
# =========================================================
<filter audit.log>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected: 
    # --- Audit: <event.code>|<user.name>|<user.role>|<source.ip>|<source.port>|<event.action>|<event.outcome>|<process.name>|<process.command_line>
    event.code            ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[0] : nil}
    user.name             ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[1] : nil}
    user.role             ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[2] : nil}
    source.ip             ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[3].split(":")[0] : nil}
    source.port           ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[3].split(":")[1] : nil}
    event.action          ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[4] : nil}
    event.outcome         ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[5] : nil}
    process.name          ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[6] : nil}
    process.command_line  ${record["message"].start_with?("Audit:") ? record["message"].sub(/^Audit: /, "").split("|")[7] : nil}
    
    # --- ECS event classification
    event.kind            event
    event.type            ["change","info"]
    event.category        ["configuration","iam"]
  </record>
</filter>


<filter audit.log>
  @type record_transformer
  enable_ruby true
  <record>
    event.kind ${ (record["process.command_line"].to_s =~ /(SET_LOGIN_POLICY|setminpasswordclasses|set_maxloginattempts_status|set_consec_maxlogincount|set_lockout_duration|setminpasswordlen|Authentication failed)/i) ? "alert" : "event" }
    event.severity ${ (record["process.command_line"].to_s =~ /(SET_LOGIN_POLICY|setminpasswordclasses|set_maxloginattempts_status|set_consec_maxlogincount|set_lockout_duration|setminpasswordlen|Authentication failed)/i) ? "73" : "21" }

  </record>
</filter>


# =========================================================
# RANSOMWARE DETECTION
# =========================================================
<filter rware.detect>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected: 
    # --- Ransomware monitoring detected suspicious data on volume <vv.name> [(vv_id)]. Note that [x] detections were muted since the previous alert on this VV.

    vv.name        ${record["message"] =~ /on volume (\S+) \d+/ ? $1 : nil}
    event.action   ransomware monitoring detected suspicious data on volume
    event.provider  ransomware.alert
    process.name   ransomware detection

    # --- ECS event classification
    event.kind     alert
    event.type     indicator
    event.severity 73
    event.category ["malware","threat"]
    rule.category  ransomware
  </record>
</filter>

<filter rware.snap>
  @type record_transformer 
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected:
    # --- On VV <vv.name> [(vv_id)], the system created a ransomware alert snapshot <vv.snap> [(snap_id)]
    vv.name        ${record["message"] =~ /On VV (\S+) \(/ ? $1 : nil}
    vv.snap        ${record["message"] =~ /snapshot (\S+) \(/ ? $1 : nil}
    event.action   the system created a ransomware alert snapshot
    process.name   ransomware detection
    event.provider  ransomware.alert

    # --- ECS event classification
    event.kind     alert
    event.type     indicator
    event.severity 73
    event.category ["malware","threat"]
    rule.category  ransomware
  </record>
</filter>

# =========================================================
# FAILED SSH LOGIN
# =========================================================
<filter ssh.login.fail>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected:
    # --- User <user.name> presented an incorrect password via ssh from <source.ip> .
    user.name       ${record["message"] =~ /User (?:invalid user\s+)?(\S+)/ ? $1 : nil}
    source.ip       ${record["message"] =~ /from ([\d\.]+)\b/ ? $1 : nil}
    event.reason    incorrect SSH password or key
    event.provider   ssh.authentication

    # --- ECS event classification
    event.kind      alert
    event.type      ["access","denied"]
    event.severity  47
    event.category  authentication
    rule.category   failed login
    event.outcome   failure
    process.name    ssh
  </record>
</filter>

# =========================================================
# AUTHENTICATION MESSAGES
# =========================================================


<filter cli.auth.success>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected:
    # --- [<process.name>] User <user.name> from <source.ip> was successfully authenticated using <auth.method>
    user.name       ${ (record["message"] =~ /\bUser\s+([^\s;]+)/i) ? $1 : nil }
    source.ip       ${ (record["message"] =~ /\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i) ? $1 : nil }
    process.name    ${ (record["message"] =~ /\[([^\]]+)\]\s*:/) ? $1 : nil }

    # --- ECS event classification
    event.kind      event
    event.type      allowed
    event.category  authentication
    event.action    login
    event.outcome   success
  </record>
</filter>

<filter cli.auth.logout>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected:
    # --- [<process.name>] User <user.name> from <source.ip> logged out: connected since YYYY-MM-DD HH:MM:SS XYZ
    user.name       ${ (record["message"] =~ /\bUser\s+([^\s;]+)/i) ? $1 : nil }
    source.ip       ${ (record["message"] =~ /\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i) ? $1 : nil }
    process.name    ${ (record["message"] =~ /\[([^\]]+)\]\s*:/) ? $1 : nil }

    # --- ECS event classification
    event.kind      event
    event.type      allowed
    event.category  authentication
    event.action    logout
    event.outcome   success
  </record>
</filter>

<filter user.locked>
  @type record_transformer
  enable_ruby
  <record>
    # --- Extraction from the message ---
    # --- Layout expected:
    # --- User account <user.name> has been locked due to multiple failed authentication attempts.
    user.name       ${ (record["message"] =~ /\baccount\s+([^\s;]+)/i) ? $1 : nil }

    # --- ECS event classification
    event.kind      alert
    event.type      denied
    event.severity  47
    event.category  authentication
    event.action    user locked
  </record>
</filter>

# =========================================================
# CLI COMMAND ERROR MESSAGES
# =========================================================

<filter cli.error>
  @type record_transformer
  enable_ruby true
  <record>

    # --- Extraction from the message ---
    # --- Layout expected:
    # --- {<user.name> <user.role> all {{0 8}} -1 <source.ip>:<source.port> session} Command: <process.command_line> Error: {<error.message>}.

    # First token inside the initial { ... } block
    user.name            ${ record["message"][/^\{(\S+)\s/, 1] }
    # Second token inside the initial { ... } block
    user.role            ${ record["message"][/^\{\S+\s+(\S+)/, 1] }
    # First IP found in the message (IPv4) BEFORE port separator
    source.ip            ${ record["message"][/(\d{1,3}(?:\.\d{1,3}){3}):\d+/, 1] }
    # Port immediately following the first IP
    source.port          ${ record["message"][/\d{1,3}(?:\.\d{1,3}){3}:(\d+)/, 1] }
    # Everything between "Command:" and "Error:"
    process.command_line ${ (s = record["message"][/Command:\s*(.*?)\s*Error:/m, 1]) && s.strip }
    # Everything after "Error:"
    message        ${ (s = record["message"][/Error:\s*(.*)\s*\z/m, 1]) && s.strip }

    # --- ECS event classification
    event.kind           event
    event.type           error
    event.outcome        failure
    event.category       configuration
    event.action         cli error
  </record>
</filter>

<filter cli.error>
  @type record_transformer
  enable_ruby true
  <record>
    event.kind           ${ (record["message"].to_s =~ /(until its retention time is expired)/i) ? "alert" : "event" }
    event.severity       ${ (record["message"].to_s =~ /(until its retention time is expired)/i) ? "73" : "21" }

  </record>
</filter>


# =========================================================
# OUTPUT: ECS JSON — per-host daily files (no compression)
# =========================================================
<match **>
  @type file
  @id out_ecs_file

  path /var/log/fluentd/ecs/${host.name}.%Y%m%d
  append true

  <format>
    @type json
    include_time_key true
    localtime true
  </format>

#  <inject>
#    tag_key fluent_tag
#    include_tag_key true
#  </inject>

  <buffer host.name,time>
    @type file
    path /var/log/hpe/buffer
    chunk_keys host.name,time
    timekey 1d
    timekey_use_utc true
    timekey_wait 10m
    flush_mode interval
    flush_interval 2s
    flush_at_shutdown true
  </buffer>
</match>

EOFCONF
}

########################################
# 5) Generate encrypted RSA key & CSR with SANs (PEM)
########################################
generate_key_and_csr() {
  PASSPHRASE_VALUE=$(sudo awk -F= '/^FLUENTD_TLS_KEY_PASSPHRASE=/{print $2}' "$ENV_FILE")

  if [ ! -f "$SERVER_KEY" ]; then
    log "Generating AES-256–encrypted RSA private key (4096-bit)"
    openssl genpkey -algorithm RSA \
      -pkeyopt rsa_keygen_bits:4096 \
      -aes256 -pass pass:"$PASSPHRASE_VALUE" \
      -out "$SERVER_KEY"
  else
    log "Private key already present; skipping generation."
  fi

  # Permissions so _fluentd can read the key
  sudo chown root:"${FLUENTD_GROUP}" "$SERVER_KEY"
  sudo chmod 0640 "$SERVER_KEY"
  sudo chown root:"${FLUENTD_GROUP}" "$CERT_DIR"
  sudo chmod 0750 "$CERT_DIR"
  sudo chmod 0755 /etc/fluentd

  # Prompt DN & SANs, build CSR config
  log "Prompting for CSR DN fields and SANs (DNS/IP)"
  read -r -p "Country (C, 2-letter code) [e.g. GB]: " C || true
  read -r -p "State/Province (ST) [e.g. England]: " ST || true
  read -r -p "Locality/City (L) [e.g. Bristol]: " L || true
  read -r -p "Organization (O) [e.g. Your Company Ltd]: " O || true
  read -r -p "Organizational Unit(s) (OU, comma-separated): " OU || true
  read -r -p "Common Name (CN, FQDN): " CN || true
  read -r -p "Email Address (optional): " EMAIL || true
  read -r -p "Subject Alternative Names (DNS, comma-separated): " DNS_LIST || true
  read -r -p "Subject Alternative Names (IP, comma-separated): " IP_LIST || true

  trim() { echo "$1" | awk '{$1=$1;print}'; }
  esc()  { echo "$1" | sed 's,/,\\/,g'; }

  C=$(esc "${C:-}"); ST=$(esc "${ST:-}"); L=$(esc "${L:-}"); O=$(esc "${O:-}")
  CN=$(esc "${CN:-}"); EMAIL=$(esc "${EMAIL:-}")

  OU_SEG=""
  if [ -n "${OU:-}" ]; then
    IFS=',' read -r -a OU_ARR <<< "$OU"
    for ou in "${OU_ARR[@]}"; do
      ou_trim=$(trim "$ou"); ou_esc=$(esc "$ou_trim")
      [ -n "$ou_esc" ] && OU_SEG="$OU_SEG/OU=$ou_esc"
    done
  fi

  declare -a DNS_ARR IP_ARR
  [ -n "${DNS_LIST:-}" ] && IFS=',' read -r -a DNS_ARR <<< "$DNS_LIST"
  [ -n "${IP_LIST:-}" ] && IFS=',' read -r -a IP_ARR <<< "$IP_LIST"
  if [[ -n "$CN" && "$CN" =~ ^[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+$ ]]; then
    DNS_ARR+=("$CN")
  fi

  alt_dns=""; alt_ip=""; declare -A seen; idx=1
  for d in "${DNS_ARR[@]}"; do
    d_trim=$(trim "$d"); [ -z "$d_trim" ] && continue; d_trim=${d_trim,,}
    if [ -z "${seen[DNS:$d_trim]:-}" ]; then
      seen[DNS:$d_trim]=1; alt_dns+="DNS.$idx = $d_trim"$'\n'; idx=$((idx+1))
    fi
  done
  idx=1
  for ip in "${IP_ARR[@]}"; do
    ip_trim=$(trim "$ip"); [ -z "$ip_trim" ] && continue
    if [ -z "${seen[IP:$ip_trim]:-}" ]; then
      seen[IP:$ip_trim]=1; alt_ip+="IP.$idx = $ip_trim"$'\n'; idx=$((idx+1))
    fi
  done

  cat <<EOF | sudo tee "$CSR_CONF" >/dev/null
[req]

[req_ext]
subjectAltName = @alt_names

[alt_names]
${alt_dns}${alt_ip}
EOF
  sudo chown root:"${FLUENTD_GROUP}" "$CSR_CONF"
  sudo chmod 0644 "$CSR_CONF"

  SUBJ="/C=${C}/ST=${ST}/L=${L}/O=${O}${OU_SEG}/CN=${CN}"
  [ -n "$EMAIL" ] && SUBJ="$SUBJ/emailAddress=$EMAIL"

  log "Creating CSR (PEM) at $CSR_PATH"
  openssl req -new -sha256 -key "$SERVER_KEY" -passin pass:"$PASSPHRASE_VALUE" \
    -subj "$SUBJ" -reqexts req_ext -config "$CSR_CONF" -out "$CSR_PATH"
  # CSR is PEM by default: -----BEGIN CERTIFICATE REQUEST-----

  sudo chown root:"${FLUENTD_GROUP}" "$CSR_PATH"
  sudo chmod 0644 "$CSR_PATH"

  log "CSR preview (Subject & SANs)"
  openssl req -in "$CSR_PATH" -noout -text | sed -n '/Subject:/p;/Subject Alternative Name/,+5p'
  
  sudo cat $CSR_PATH
  echo "\nSubmit the CSR to your CA now. Press Enter to continue when ready to paste certificates."
  read -r
}

########################################
# 6) Pause to paste server.crt and ca.crt (PEM)
########################################
paste_certs() {
  if [ ! -f "$SERVER_CRT" ]; then
    log "Paste the issued server certificate (PEM). End with CTRL-D."
    sudo bash -c "cat > '$SERVER_CRT'"
  else
    log "Server certificate already exists; skipping paste."
  fi
  if [ ! -f "$CA_CRT" ]; then
    log "Paste the CA certificate (PEM). End with CTRL-D."
    sudo bash -c "cat > '$CA_CRT'"
  else
    log "CA certificate already exists; skipping paste."
  fi

  # Permissions for crt files
  sudo chown root:"${FLUENTD_GROUP}" "$SERVER_CRT" "$CA_CRT"
  sudo chmod 0644 "$SERVER_CRT" "$CA_CRT"
}

########################################
# 7) Symlink helper + timer (per-host current)
########################################
setup_symlink_helper() {
  log "Installing per-host symlink helper & daily systemd timer (00:15 UTC)"
  sudo tee "$SYMLINK_HELPER" >/dev/null <<'EON'
#!/usr/bin/env bash
set -euo pipefail

DIR=/var/log/hpe
cd "$DIR" 2>/dev/null || exit 0
shopt -s nullglob

# latest_file[host] = filename (host.YYYYMMDD.log)
# latest_date[host] = YYYYMMDD
declare -A latest_filesudo
declare -A latest_date

# Match files like: HOST.20251210.log
for f in *.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].log; do
  base="${f##*/}"               # e.g., CZ2D3409V4.20251210.log
  host="${base%%.*}"            # CZ2D3409V4
  rest="${base#${host}.}"       # 20251210.log
  date="${rest%%.*}"            # 20251210

  # Keep the newest per host by comparing the YYYYMMDD string
  if [[ -z "${latest_date[$host]+x}" || "$date" > "${latest_date[$host]}" ]]; then
    latest_date[$host]="$date"
    latest_file[$host]="$f"
  fi
done

# Create/update symlinks: HOST.current.log -> HOST.YYYYMMDD.log
for host in "${!latest_file[@]}"; do
  ln -sfn "${latest_file[$host]}" "${host}.current.log"
  echo "Updated symlink: ${host}.current.log -> ${latest_file[$host]}"
done
EON
  sudo chmod 0755 "$SYMLINK_HELPER"; sudo chown root:root "$SYMLINK_HELPER"

  sudo tee "$SYMLINK_SERVICE" >/dev/null <<'EOSVC'
[Unit]
Description=Update per-host Fluentd current log symlinks
After=fluentd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fluentd-host-symlinks.sh
EOSVC

  sudo tee "$SYMLINK_TIMER" >/dev/null <<'EOTMR'
[Unit]
Description=Daily update of per-host Fluentd symlinks

[Timer]
OnCalendar=*-*-* 00:00:00 UTC
Persistent=true
Unit=fluentd-host-symlinks.service
AccuracySec=1min

[Install]
WantedBy=timers.target
EOTMR

  sudo systemctl daemon-reload
  sudo systemctl enable --now fluentd-host-symlinks.timer
  sudo systemctl start fluentd-host-symlinks.service || true
}

########################################
# 8) Restart & verify
########################################
restart_and_verify() {
  log "Reloading systemd & restarting $SVC"
  sudo systemctl daemon-reload
  sudo systemctl enable "$SVC"
  sudo systemctl restart "$SVC"
  sudo systemctl status "$SVC" --no-pager || true

  log "Verifying TLS listener on 6514"
  sudo ss -lntp | grep 6514 || warn "No 6514 listener found yet."
}

########################################
# Main
########################################
install_fluentd
ensure_dirs
write_env_file
write_fluentd_config
generate_key_and_csr
paste_certs
setup_symlink_helper
restart_and_verify

log "Done."
