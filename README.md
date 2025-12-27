# AMP Mikrotik Port Forwarder

A Go tool that polls [CubeCoders AMP](https://cubecoders.com/AMP) for running game server instances and automatically synchronizes port forwarding rules on a chain of Mikrotik routers.

## Features

- Automatically detects running game servers from AMP
- Creates and updates NAT/firewall rules on Mikrotik routers
- Supports a chain of N routers (WAN -> internal -> ... -> AMP VM)
- Handles both TCP and UDP ports
- Includes hairpin NAT for LAN clients accessing via external hostname
- Dry-run mode for testing
- TLS support for secure router API connections
- Systemd service for automatic startup
- Configuration via CLI flags or environment variables (no config file needed)

## Architecture

```
Internet -> Router[0] (WAN) -> Router[1] -> ... -> Router[N-1] -> AMP VM
```

- **Router[0]** (first): Handles WAN dstnat + hairpin NAT
- **Router[1..N-1]** (subsequent): Handle dstnat + forward filter rules

The tool creates aggregated firewall rules with comma-separated port lists. You only need to position the rules once in your firewall - the tool will update the port lists as game servers start and stop.

## Installation

### Build from source

```bash
go install github.com/jtdoepke/amp-mikrotik-port-forwarder@latest
```

Or clone and build:

```bash
git clone https://github.com/jtdoepke/amp-mikrotik-port-forwarder.git
cd amp-mikrotik-port-forwarder
go build -o amp-port-sync .
sudo mv amp-port-sync /usr/local/bin/
```

## Quick Start

1. [Set up AMP](#amp-setup) with an API user
2. [Configure your Mikrotik router(s)](#mikrotik-router-setup) with an API user
3. [Install the systemd service](#systemd-service-setup) or run manually:

```bash
amp-port-sync sync \
  --amp-url http://localhost:8080/ \
  --amp-username admin \
  --amp-password-file /run/secrets/amp-password \
  --target-ip 192.168.100.10 \
  --router name=wan,address=192.168.1.1:8728,username=amp-sync,password-file=/run/secrets/router-pw,wan-interface=WAN,lan-subnet=192.168.0.0/16 \
  --once
```

## Configuration Reference

### CLI Flags

| Flag | Description |
|------|-------------|
| `--amp-url` | AMP API URL (default: `http://127.0.0.1:8080/`) |
| `--amp-username` | AMP username |
| `--amp-password` | AMP password (direct) |
| `--amp-password-file` | Path to file containing AMP password |
| `--target-ip` | Final destination IP (the AMP VM) |
| `--protocols` | Protocols to forward (default: `tcp,udp`) |
| `--router` | Router config (can be repeated, see below) |
| `--once` | Run once and exit |
| `--dry-run` | Show what would change without making changes |
| `--interval` | Polling interval (default: `1m`) |
| `-v, --verbose` | Enable verbose logging |

### Environment Variables

All settings can be configured via environment variables with the `AMP_SYNC_` prefix:

| Variable | Description |
|----------|-------------|
| `AMP_SYNC_AMP_URL` | AMP API URL |
| `AMP_SYNC_AMP_USERNAME` | AMP username |
| `AMP_SYNC_AMP_PASSWORD` | AMP password (direct) |
| `AMP_SYNC_AMP_PASSWORD_FILE` | Path to AMP password file |
| `AMP_SYNC_TARGET_IP` | Target IP for port forwarding |
| `AMP_SYNC_PROTOCOLS` | Comma-separated protocols |

#### Router Configuration (indexed)

Routers are configured using indexed environment variables:

```bash
# Router 0 (WAN-facing, required)
export AMP_SYNC_ROUTER_0_NAME=wan-router
export AMP_SYNC_ROUTER_0_ADDRESS=192.168.1.1:8728
export AMP_SYNC_ROUTER_0_USERNAME=amp-sync
export AMP_SYNC_ROUTER_0_PASSWORD=secretpassword       # or use PASSWORD_FILE
export AMP_SYNC_ROUTER_0_PASSWORD_FILE=/run/secrets/pw
export AMP_SYNC_ROUTER_0_WAN_INTERFACE=ether1          # or use WAN_INTERFACE_LIST
export AMP_SYNC_ROUTER_0_WAN_INTERFACE_LIST=WAN        # alternative: use an interface list
export AMP_SYNC_ROUTER_0_WAN_HOSTNAME=example.com      # recommended for hairpin NAT
export AMP_SYNC_ROUTER_0_LAN_SUBNET=192.168.0.0/16     # required for first router
export AMP_SYNC_ROUTER_0_FORWARD_TO=192.168.2.1        # only if chaining to another router

# TLS options (optional)
export AMP_SYNC_ROUTER_0_USE_TLS=true                  # enable TLS (use port 8729)
export AMP_SYNC_ROUTER_0_TLS_INSECURE=true             # skip cert verification (default: true)
export AMP_SYNC_ROUTER_0_TLS_CA_FILE=/path/to/ca.crt   # CA cert for verification
```

### Router Flag Format

The `--router` flag uses comma-separated key=value pairs:

```bash
--router name=wan,address=192.168.1.1:8728,username=amp-sync,password-file=/secrets/pw,wan-interface=WAN,lan-subnet=192.168.0.0/16
```

Available keys:

| Key | Description | Required |
|-----|-------------|----------|
| `name` | Router name (for logging) | No |
| `address` | RouterOS API address (host:port) | Yes |
| `username` | RouterOS username | Yes |
| `password` | RouterOS password (direct) | Yes* |
| `password-file` | Path to password file | Yes* |
| `use-tls` | Enable TLS (`true`/`false`) | No |
| `tls-insecure` | Skip cert verification (default: `true`) | No |
| `tls-ca-file` | Path to CA certificate file | No |
| `wan-interface` | WAN interface name | First router** |
| `wan-interface-list` | WAN interface list name | First router** |
| `wan-hostname` | Hostname for hairpin NAT (see below) | No |
| `lan-subnet` | LAN subnet for hairpin (CIDR) | First router |
| `forward-to` | Next hop IP address | All except last |

\* Either `password` or `password-file` is required.
\** Either `wan-interface` or `wan-interface-list` is required for the first router.

### TLS Configuration

To use TLS for router API connections:

1. **With self-signed certs (default)**: Enable TLS and skip verification:
   ```bash
   --router address=192.168.1.1:8729,use-tls=true,tls-insecure=true,...
   ```

2. **With CA verification**: Provide the CA certificate:
   ```bash
   --router address=192.168.1.1:8729,use-tls=true,tls-insecure=false,tls-ca-file=/path/to/ca.crt,...
   ```

See [TLS Certificate Setup](#tls-certificate-setup) for creating certificates on Mikrotik.

### Hairpin NAT

Hairpin NAT allows LAN clients to connect to game servers using the external hostname (e.g., `games.example.com`) instead of the internal IP. Without hairpin NAT, these connections would fail because the traffic would be sent to the WAN IP from inside the LAN.

The tool creates hairpin rules that:
1. Match traffic destined for the WAN IP
2. Redirect it to the game server
3. Masquerade the source so return traffic routes correctly

**`wan-hostname` vs auto-detection:**

If `wan-hostname` is not set, the tool queries an external service (`icanhazip.com`) to detect your public IP. However, **using `wan-hostname` is recommended** when you have a DDNS hostname:

| Method | Pros | Cons |
|--------|------|------|
| `wan-hostname` | Matches exactly what clients resolve; works with CDNs/load balancers; no external dependency | Requires a hostname |
| Auto-detection | Works without a hostname; gets current IP immediately | Depends on external service; may get wrong IP with carrier-grade NAT or multi-WAN |

**Why `wan-hostname` is more correct:** Hairpin NAT must match the destination IP that LAN clients actually connect to. When a client resolves `games.example.com`, they get an IP from DNS and send packets there. The hairpin rule must match that same IP.

If your public IP just changed but DNS hasn't propagated yet:
- With `wan-hostname`: Rule matches the old IP (from DNS) → hairpin works for clients still using cached DNS
- With auto-detection: Rule matches the new IP → hairpin breaks until DNS propagates

**Recommendation:**
- Use `wan-hostname` if you have a DDNS hostname (e.g., `games.example.com`)
- Use auto-detection only for simple setups without a hostname, or with a static IP

### Password Resolution

Passwords can be provided via:
1. **Password file** (preferred for secrets management): `--amp-password-file` or `AMP_SYNC_ROUTER_0_PASSWORD_FILE`
2. **Direct value**: `--amp-password` or `AMP_SYNC_AMP_PASSWORD`

Password files take precedence over direct values when both are specified.

## Setup Guides

### AMP Setup

The tool connects to AMP's HTTP API to discover running game server instances and their ports.

#### Creating API Credentials

1. Log into the AMP web interface
2. Go to **User Menu** (top right) → **Account Details**
3. Click the **API Keys** tab
4. Click **Create API Key**
5. Give it a descriptive name (e.g., "Port Forwarder")
6. Save the username and password shown

Alternatively, you can use your regular AMP username/password, though a dedicated API user is recommended.

#### Required Permissions

The API user needs access to:
- **ADSModule** - To list game server instances
- Read access to instance information (ports, status)

A "Super Admin" role has all required permissions. For minimal permissions, create a role with "View ADS Instances" capability.

#### How Ports Are Discovered

The tool queries AMP for all running instances and extracts ports from their "Application Endpoints". Each endpoint specifies:
- Port number
- Protocol (TCP/UDP, defaults to TCP if not specified)

Only ports from **running** instances are synchronized. When an instance stops, its ports are removed from the firewall rules.

#### Testing the Connection

```bash
amp-port-sync debug amp \
  --url http://localhost:8080/ \
  --username your-api-user \
  --password-file /path/to/password
```

This will list all instances and their detected ports.

### Mikrotik Router Setup

The tool uses the RouterOS API to manage firewall rules. Each router needs an API user with appropriate permissions.

#### Enabling the API Service

By default, the API service may be disabled. Enable it via WinBox, WebFig, or terminal:

```routeros
# Enable plain-text API (port 8728)
/ip service enable api

# Or enable API-SSL (port 8729) - recommended
/ip service enable api-ssl
```

#### Creating an API User

Create a dedicated user with minimal permissions:

```routeros
# Create a group with API access and firewall management
/user group add name=amp-sync policy=read,write,api,!ftp,!local,!password,!policy,!reboot,!romon,!sensitive,!sniff,!ssh,!telnet,!test,!web,!winbox

# Create the user
/user add name=amp-sync group=amp-sync password=YourSecurePassword
```

The user needs:
- `api` - Access to the API service
- `read` - Read firewall rules
- `write` - Create/modify/delete firewall rules

#### Firewall Rule Positioning

The tool creates firewall rules with specific comments (e.g., `amp-sync:wan-dstnat:tcp`). **You must position these rules correctly in your firewall chain.**

After the first sync, position the rules in your NAT chains:

```routeros
# View created rules
/ip firewall nat print where comment~"amp-sync"

# Move rules to the correct position (example: position 2)
/ip firewall nat move [find comment="amp-sync:wan-dstnat:tcp"] 2
/ip firewall nat move [find comment="amp-sync:wan-dstnat:udp"] 3
# etc.
```

For filter rules on subsequent routers:

```routeros
/ip firewall filter print where comment~"amp-sync"
/ip firewall filter move [find comment="amp-sync:forward:tcp"] 2
```

**Important**: Rules should be positioned:
- NAT rules: Before any MASQUERADE or DROP rules
- Filter rules: In the FORWARD chain, before any DROP rules

### Systemd Service Setup

The tool includes systemd unit files for running as a service.

#### Installation

```bash
# Copy the binary
sudo cp amp-port-sync /usr/local/bin/

# Copy systemd units
sudo cp systemd/amp-port-sync.service /etc/systemd/system/
sudo cp systemd/amp-port-sync-oneshot.service /etc/systemd/system/
sudo cp systemd/amp-port-sync.timer /etc/systemd/system/

# Create configuration directory
sudo mkdir -p /etc/amp-port-sync

# Create the environment file (see example below)
sudo nano /etc/amp-port-sync/env

# Set permissions
sudo chmod 600 /etc/amp-port-sync/env

# Reload systemd
sudo systemctl daemon-reload
```

#### Environment File Example

Create `/etc/amp-port-sync/env`:

```bash
# AMP Configuration
AMP_SYNC_AMP_URL=http://localhost:8080/
AMP_SYNC_AMP_USERNAME=amp-api-user
AMP_SYNC_AMP_PASSWORD_FILE=/etc/amp-port-sync/amp-password

# Target (the AMP VM)
AMP_SYNC_TARGET_IP=192.168.100.10

# Protocols (optional, defaults to tcp,udp)
# AMP_SYNC_PROTOCOLS=tcp,udp

# Router 0 - WAN-facing router
AMP_SYNC_ROUTER_0_NAME=wan-router
AMP_SYNC_ROUTER_0_ADDRESS=192.168.1.1:8729
AMP_SYNC_ROUTER_0_USERNAME=amp-sync
AMP_SYNC_ROUTER_0_PASSWORD_FILE=/etc/amp-port-sync/router-password
AMP_SYNC_ROUTER_0_USE_TLS=true
AMP_SYNC_ROUTER_0_TLS_INSECURE=true
AMP_SYNC_ROUTER_0_WAN_INTERFACE_LIST=WAN
AMP_SYNC_ROUTER_0_WAN_HOSTNAME=games.example.com
AMP_SYNC_ROUTER_0_LAN_SUBNET=192.168.0.0/16
```

Create password files:

```bash
echo "your-amp-password" | sudo tee /etc/amp-port-sync/amp-password
echo "your-router-password" | sudo tee /etc/amp-port-sync/router-password
sudo chmod 600 /etc/amp-port-sync/*-password
```

#### Service Modes

**Continuous mode** (recommended): Runs continuously, polling at regular intervals.

```bash
sudo systemctl enable --now amp-port-sync.service
```

**Timer mode**: Runs periodically via systemd timer (every 1 minute by default).

```bash
sudo systemctl enable --now amp-port-sync.timer
```

#### Viewing Logs

```bash
# Follow logs
journalctl -u amp-port-sync -f

# View recent logs
journalctl -u amp-port-sync --since "1 hour ago"
```

## Examples

### Single Router

A single WAN-facing router forwarding directly to the AMP VM:

```bash
amp-port-sync sync \
  --amp-url http://localhost:8080/ \
  --amp-username admin \
  --amp-password-file /run/secrets/amp-password \
  --target-ip 192.168.100.10 \
  --router name=wan,address=192.168.1.1:8728,username=amp-sync,password-file=/run/secrets/router-pw,wan-interface=ether1,wan-hostname=games.example.com,lan-subnet=192.168.0.0/16
```

### Multi-Router Chain

Two routers: WAN router forwards to internal router, which forwards to AMP VM:

```bash
# Using environment variables
export AMP_SYNC_AMP_URL=http://localhost:8080/
export AMP_SYNC_AMP_USERNAME=admin
export AMP_SYNC_AMP_PASSWORD_FILE=/run/secrets/amp-password
export AMP_SYNC_TARGET_IP=192.168.100.10

# Router 0: WAN-facing
export AMP_SYNC_ROUTER_0_NAME=wan-router
export AMP_SYNC_ROUTER_0_ADDRESS=192.168.1.1:8728
export AMP_SYNC_ROUTER_0_USERNAME=amp-sync
export AMP_SYNC_ROUTER_0_PASSWORD_FILE=/run/secrets/wan-router-pw
export AMP_SYNC_ROUTER_0_WAN_INTERFACE_LIST=WAN
export AMP_SYNC_ROUTER_0_WAN_HOSTNAME=games.example.com
export AMP_SYNC_ROUTER_0_LAN_SUBNET=192.168.0.0/16
export AMP_SYNC_ROUTER_0_FORWARD_TO=192.168.2.1

# Router 1: Internal, forwards to AMP VM
export AMP_SYNC_ROUTER_1_NAME=internal-router
export AMP_SYNC_ROUTER_1_ADDRESS=192.168.2.1:8728
export AMP_SYNC_ROUTER_1_USERNAME=amp-sync
export AMP_SYNC_ROUTER_1_PASSWORD_FILE=/run/secrets/internal-router-pw
# No FORWARD_TO - this is the last router, uses TARGET_IP

amp-port-sync sync --once
```

### Kubernetes / Container Deployment

This tool is designed for containerized environments. Example using K8s secrets:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amp-port-sync
spec:
  replicas: 1
  selector:
    matchLabels:
      app: amp-port-sync
  template:
    metadata:
      labels:
        app: amp-port-sync
    spec:
      containers:
      - name: amp-port-sync
        image: ghcr.io/jtdoepke/amp-mikrotik-port-forwarder:latest
        args: ["sync"]
        env:
        - name: AMP_SYNC_AMP_URL
          value: "http://amp-service:8080/"
        - name: AMP_SYNC_AMP_USERNAME
          valueFrom:
            secretKeyRef:
              name: amp-credentials
              key: username
        - name: AMP_SYNC_AMP_PASSWORD_FILE
          value: "/run/secrets/amp-password"
        - name: AMP_SYNC_TARGET_IP
          value: "10.0.50.100"
        - name: AMP_SYNC_ROUTER_0_NAME
          value: "wan-router"
        - name: AMP_SYNC_ROUTER_0_ADDRESS
          value: "10.0.1.1:8729"
        - name: AMP_SYNC_ROUTER_0_USERNAME
          value: "amp-sync"
        - name: AMP_SYNC_ROUTER_0_PASSWORD_FILE
          value: "/run/secrets/router-password"
        - name: AMP_SYNC_ROUTER_0_USE_TLS
          value: "true"
        - name: AMP_SYNC_ROUTER_0_WAN_INTERFACE_LIST
          value: "WAN"
        - name: AMP_SYNC_ROUTER_0_LAN_SUBNET
          value: "10.0.0.0/8"
        volumeMounts:
        - name: amp-password
          mountPath: /run/secrets/amp-password
          subPath: password
        - name: router-password
          mountPath: /run/secrets/router-password
          subPath: password
      volumes:
      - name: amp-password
        secret:
          secretName: amp-credentials
      - name: router-password
        secret:
          secretName: router-credentials
```

### Dry Run

Test what changes would be made without actually modifying the router:

```bash
amp-port-sync sync --once --dry-run [other flags...]
```

## Firewall Rules Reference

The tool creates the following rules (you must position them in your firewall):

### First Router (WAN-facing)

| Comment | Chain | Action | Description |
|---------|-------|--------|-------------|
| `amp-sync:wan-dstnat:tcp` | dstnat | dst-nat | Forward WAN TCP traffic |
| `amp-sync:wan-dstnat:udp` | dstnat | dst-nat | Forward WAN UDP traffic |
| `amp-sync:hairpin-dstnat:tcp` | dstnat | dst-nat | Hairpin NAT for LAN (TCP) |
| `amp-sync:hairpin-dstnat:udp` | dstnat | dst-nat | Hairpin NAT for LAN (UDP) |
| `amp-sync:hairpin-masq:tcp` | srcnat | masquerade | Hairpin masquerade (TCP) |
| `amp-sync:hairpin-masq:udp` | srcnat | masquerade | Hairpin masquerade (UDP) |

### Subsequent Routers

| Comment | Chain | Action | Description |
|---------|-------|--------|-------------|
| `amp-sync:dstnat:tcp` | dstnat | dst-nat | Forward to next hop (TCP) |
| `amp-sync:dstnat:udp` | dstnat | dst-nat | Forward to next hop (UDP) |
| `amp-sync:forward:tcp` | forward | accept | Allow forwarded traffic (TCP) |
| `amp-sync:forward:udp` | forward | accept | Allow forwarded traffic (UDP) |

## Troubleshooting

### Connection Issues

**Cannot connect to AMP:**
- Verify AMP URL is correct and accessible
- Check username/password credentials
- Ensure the API user has required permissions
- Test with: `amp-port-sync debug amp --url <url> --username <user> --password-file <file>`

**Cannot connect to router:**
- Verify the API service is enabled (`/ip service print`)
- Check the address includes the correct port (8728 for API, 8729 for API-SSL)
- Verify username/password
- Check firewall rules aren't blocking API access
- For TLS issues, try `tls-insecure=true` first

**Permission denied on router:**
- Ensure the user has `api`, `read`, and `write` policies
- Check the user group has firewall access

### TLS Certificate Setup

To use TLS with certificate verification, create a self-signed certificate on your Mikrotik router:

```routeros
# Create a self-signed certificate
/certificate add name=api-cert common-name=router.local days-valid=3650 key-size=2048

# Sign the certificate
/certificate sign api-cert

# Assign to API-SSL service
/ip service set api-ssl certificate=api-cert

# Verify
/ip service print detail where name=api-ssl
```

To export the certificate for client verification:

```routeros
# Export the certificate (public key only)
/certificate export-certificate api-cert
```

Download the exported `.crt` file from the router's file storage and use it with `tls-ca-file`:

```bash
--router address=192.168.1.1:8729,use-tls=true,tls-insecure=false,tls-ca-file=/path/to/cert_api-cert.crt,...
```

### Debugging

Enable verbose logging to see detailed information:

```bash
amp-port-sync sync --once -v [other flags...]
```

For systemd service:

```bash
# View all logs
journalctl -u amp-port-sync

# Follow logs in real-time
journalctl -u amp-port-sync -f

# View logs with debug output (if running with -v)
journalctl -u amp-port-sync --since "10 minutes ago"
```

### Common Issues

**Rules created but not working:**
- Rules may be in wrong position in the firewall chain
- Use `/ip firewall nat print` to check rule order
- Move rules before any DROP or MASQUERADE rules

**Ports not detected from AMP:**
- Only running instances are scanned
- Check that instances have "Application Endpoints" configured
- Use `amp-port-sync debug amp` to see what's detected

**Hairpin NAT not working:**
- If using `wan-hostname`: verify it resolves to the expected IP (`dig games.example.com`)
- If using auto-detection: check that `icanhazip.com` returns your actual WAN IP
- Check `lan-subnet` covers your LAN clients (e.g., `192.168.0.0/16` for all 192.168.x.x addresses)
- Ensure hairpin rules are positioned correctly in NAT chains
- See [Hairpin NAT](#hairpin-nat) for details on `wan-hostname` vs auto-detection

## License

MIT License - see LICENSE file for details.
