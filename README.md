# Suricata IDS Lab — Network Intrusion Detection

A hands-on blue-team lab simulating a small network, deploying Suricata as a Network IDS, and validating detection with real attacks (Nmap port scanning, Hydra SSH brute-forcing).

## Objective

Deploy and configure Suricata on a Linux server to monitor network traffic, write custom detection rules, and verify detection against simulated attacks from a Kali Linux machine.

## Architecture
Kali Linux (attacker) Ubuntu Server (target)
192.168.80.131 ---> 192.168.80.133
nmap, hydra Suricata IDS (ET Open + custom rules)
|
v
fast.log / eve.json

- **Hypervisor:** VMware Workstation
- **Network:** NAT, both VMs on the same subnet
- **Target:** Ubuntu Server 24.04 LTS, Suricata 8.0.7
- **Attacker:** Kali Linux 2026.2

## What was done

1. Deployed Ubuntu Server and Kali Linux VMs on an isolated NAT network.
2. Installed Suricata and loaded the ET Open ruleset (69,000+ rules).
3. Fixed a YAML configuration error (missing `%YAML 1.1 / ---` header) and corrected the capture interface.
4. Verified detection with `nmap -sS` and `nmap -A` scans from Kali — confirmed packet inspection via `fast.log`.
5. Wrote two custom detection rules (see `rules/local.rules`):
   - SYN scan detection (threshold-based, flags `S`)
   - SSH brute-force detection (threshold-based on port 22)
6. Installed Hydra on Kali and ran an SSH brute-force attempt against the target — confirmed the custom rule fired correctly.

## Custom rules
alert tcp any any -> $HOME_NET any (msg:“LOCAL Nmap SYN scan detected”; flags:S; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000001; rev:1;)

alert tcp any any -> $HOME_NET 22 (msg:“LOCAL SSH brute force attempt”; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:1000003; rev:1;)

## Results

| Attack | Tool | Detected | Alert |
|---|---|---|---|
| TCP SYN scan | nmap -sS | ✅ | `LOCAL Nmap SYN scan detected` |
| OS/service detection | nmap -A | ✅ | Logged via SSH service fingerprint |
| SSH brute force | Hydra | ✅ | `LOCAL SSH brute force attempt` |

See `/screenshots` for full evidence (config, rule loading, alerts).

## Challenges & fixes

- **YAML parsing error**: config file was missing the required `%YAML 1.1` / `---` header after an edit — re-added it.
- **Interface mismatch**: default config pointed to `eth0`; corrected to `ens33` (actual VMware adapter name).
- **threshold syntax typo**: `seconds` was mistyped as `seconde`, causing a PCRE parse error — corrected and retested with `suricata -T`.

## What I learned

- How Suricata loads and validates YAML configuration, and how to debug parsing errors.
- Writing custom Suricata rules: `flags`, `threshold`, `flow`, `classtype`, `sid`.
- The difference between noise (ICMP decode warnings) and real alerts when reading `fast.log`.
- Basic network reconnaissance and brute-force techniques, from the attacker's perspective, to understand what a defender needs to detect.

## Next steps

- Centralize alerts in a SIEM (Wazuh) for dashboarding and correlation.
- Add more custom rules (e.g. detecting specific CVE exploitation attempts).
