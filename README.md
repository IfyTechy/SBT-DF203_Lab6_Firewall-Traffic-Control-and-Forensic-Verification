# SBT-DF203-Lab6: Firewall Traffic Control and Forensic Verification Using TShark/Wireshark

A formal digital forensics investigation analyzing the network and application-level impact of host-based `iptables` firewall rules on TCP port 80 traffic. The lab verifies baseline HTTP communication, enforces source-specific traffic control, compares packet capture behaviors (`.pcapng`), and validates ruleset restoration.

---

## 📌 Investigation Overview

- **Lead Examiner:** Nebeuwa Ifeanyichukwu Raphael
- **Course & Lab:** SBT-DF203 — Basic Networking Skills for Digital Forensics (Lab 6)
- **Primary Tools:** `iptables`, `tshark`, `wireshark`, `curl`, `apache2`, `sha256sum`
- **Environment:** Kali Linux Web Server (`192.168.190.129/24`) and Windows 10 Client (`192.168.190.128/24`) in an isolated VMware Host-Only network (`192.168.190.0/24`)

### Key Analytical Findings
- **Baseline Integrity:** Preserved original empty `iptables` state (`evidence/iptables_original.txt`) with standard empty-file SHA-256 digest (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- **Allowed Traffic Baseline:** Baseline capture (`evidence/http_allowed.pcapng`, 18 packets) confirmed complete TCP 3-way handshakes and HTTP 200 OK responses for GET requests to `/firewall_lab.html`.
- **Blocked Traffic Behavior:** Insertion of `iptables -I INPUT 1 -s 192.168.190.128 -p tcp --dport 80 -j DROP` resulted in 5 client SYN packets (1 initial SYN + 4 retransmissions) with 0 SYN-ACK responses, validating silent packet dropping.
- **Rule Verification & Recovery:** Exact rule deletion using `iptables -D` (verified via `iptables -C`) fully restored HTTP access, yielding successful `HTTP/1.1 200 OK` responses on subsequent `curl` tests.

---

## 📁 Repository Structure

```text
SBT-DF203-Lab6/
├── evidence/
│   ├── iptables_original.txt       # Original firewall ruleset export before modification
│   ├── ip6tables_original.txt      # Original IPv6 firewall ruleset export
│   ├── http_allowed.pcapng         # Captured baseline allowed HTTP traffic (18 packets)
│   └── http_blocked.pcapng         # Captured blocked HTTP traffic showing SYN retransmissions
├── reports/
│   ├── iptables_original_hash.txt  # SHA-256 verification log for original firewall state
│   ├── http_allowed_analysis.txt   # TShark field extractions for baseline allowed HTTP session
│   ├── http_blocked_analysis.txt   # TShark field extractions showing blocked SYN retransmissions
│   ├── allowed_vs_blocked.tsv      # Comparative frame-by-frame timeline analysis
│   ├── rule_verification.txt       # Log confirming DROP rule presence/absence checks
│   └── iptables_restored.txt       # Restored firewall state dump post-cleanup
└── README.md
```

## ⚙️ Execution & Methodology

**1. Evidence Preservation & Baseline Setup**

Preserve initial host firewall state and verify local Apache HTTP server readiness:

```Bash
mkdir -p ~/SBT-DF203-Lab6/{evidence,reports,working}
cd ~/SBT-DF203-Lab6

# Export original firewall states and generate SHA-256 digests
sudo iptables-save | tee evidence/iptables_original.txt
sudo ip6tables-save | tee evidence/ip6tables_original.txt
sha256sum evidence/iptables_original.txt | tee reports/iptables_original_hash.txt

# Verify Apache web service readiness
sudo systemctl enable --now apache2
curl -v [http://127.0.0.1/firewall_lab.html](http://127.0.0.1/firewall_lab.html)
```

**2. Capture Allowed HTTP Baseline**

Monitor interface eth0 for TCP port 80 traffic while executing client requests from Windows 10 (192.168.190.128):

```Bash
# Capture baseline allowed traffic
sudo tshark -i eth0 -a duration:30 -f "tcp port 80" -w evidence/http_allowed.pcapng

# Extract key HTTP fields for evidence verification
tshark -r evidence/http_allowed.pcapng -Y 'http' -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e http.request.method -e http.request.uri -e http.response.code \
  | tee reports/http_allowed_analysis.txt
```

**3. Implement & Verify Target DROP Rule**

Insert a narrow DROP rule targeting TCP port 80 from the specific Windows client IP:

Bash
# Insert DROP rule at position 1 of INPUT chain
sudo iptables -I INPUT 1 -s 192.168.190.128 -p tcp --dport 80 -j DROP

# Verify rule existence non-destructively
sudo iptables -C INPUT -s 192.168.190.128 -p tcp --dport 80 -j DROP && echo "Rule verified present."
4. Capture Blocked Traffic & Resolve Permissions
Capture connection attempts during active blocking. (Note: Handled root-ownership path permissions by buffering via /tmp):

```Bash
# Capture blocked traffic stream
sudo timeout 30 tshark -i eth0 -f "tcp port 80" -w /tmp/http_blocked.pcapng
sudo mv /tmp/http_blocked.pcapng evidence/http_blocked.pcapng
sudo chmod 644 evidence/http_blocked.pcapng

# Analyze TCP flags to verify retransmissions (0x002 = SYN)
tshark -r evidence/http_blocked.pcapng -Y 'tcp.port==80' -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e tcp.flags \
  | tee reports/http_blocked_analysis.txt
```

**5. Rule Cleanup & Service Restoration**

Delete the exact firewall rule specification and confirm total recovery:

```Bash
# Remove exact matching rule
sudo iptables -D INPUT -s 192.168.190.128 -p tcp --dport 80 -j DROP

# Confirm removal and log restored state
sudo iptables -C INPUT -s 192.168.190.128 -p tcp --dport 80 -j DROP || echo "Rule successfully removed."
sudo iptables -L INPUT -n -v --line-numbers | tee reports/iptables_restored.txt
```

## 🔒 Forensic Analysis & Comparison Summary

| Indicator / Feature | Allowed Capture (`http_allowed.pcapng`) | Blocked Capture (`http_blocked.pcapng`) |
| -------- | -------- | -------- |
| Client SYN Observed | Yes (`192.168.190.128:49677 → :80`) | Yes (`192.168.190.128:49680 → :80`) |
| Server SYN-ACK Observed	| Yes (`192.168.190.129:80 → :49677`)	| No (Silent drop by firewall) |
| TCP Handshake State |	Completed successfully | Failed (Stuck in SYN_SENT) |
| HTTP Request / Response	| `GET /firewall_lab.html` / `HTTP 200 OK`	| None (Layer 7 never reached) |
| Packet Pattern	| Standard Handshake → Data → FIN Tear-down	| 5 repeated SYN retransmissions over 15s |
| Client Application Output	| `200 OK` (Web page rendered)	| Connection timeout / failure |

## ⚠️ Key Operational Notes & Forensic Insights

**1.DROP vs. REJECT Differences:** A DROP action silently discards incoming SYN packets, forcing client TCP stacks to retransmit until timing out. Conversely, a REJECT action actively sends a TCP RST or ICMP Port Unreachable frame back to the client, triggering an immediate connection refusal.

**2.Rule Management Safeguard:** Always use iptables -D with full rule parameters rather than deleting by line numbers (iptables -D INPUT 1), as concurrent chain modifications can cause unintended deletion of active rules.










