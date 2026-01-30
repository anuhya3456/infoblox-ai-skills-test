# Known limitations / trade-offs

1. **Subnet inference is heuristic**  
   The pipeline derives `subnet_cidr` using simple defaults (e.g., `/24` for private IPv4). In real IPAM, the authoritative subnet comes from inventory/IPAM context, not from a guess.

2. **FQDN derivation uses a single default domain**  
   Missing FQDNs are filled as `hostname.corp.example.com`. Real environments often have multiple domains, split-horizon DNS, and site- or business-unit–specific suffixes.

3. **Device type inference is shallow**  
   When `device_type` is missing, inference is based on a few string cues (hostname prefixes / notes). This is brittle and should be supplemented with richer signals (vendor/OUI, DHCP fingerprints, CMDB attributes) and/or an LLM with strict JSON output.

4. **Owner parsing is best-effort**  
   Free-text owners like “ops” or “platform” are treated as teams; names and email extraction are heuristic and may misclassify ambiguous strings.

5. **Reserved/special IP interpretation lacks policy context**  
   Addresses like loopback (127.0.0.1) or link-local (169.254/16, fe80::/10) are flagged as anomalies, but an organization could intentionally track them for lab/testing use.
