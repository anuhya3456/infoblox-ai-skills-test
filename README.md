# Infoblox — AI + DDI Take‑Home (Option 3: Data Cleaning via LLM)

## Challenge
Clean, normalize, and enrich `inventory_raw.csv` into a structured dataset fit for IPAM/DNS/DHCP workflows. Use deterministic rules first; use LLMs only where rules are weak. Log every prompt and explain your iterations briefly.

## Deliverables
1. `inventory_clean.csv`
2. `anomalies.json`
3. `prompts.md`
4. `approach.md`
5. `cons.md`
6. `run.py` or `run.sh`
7. (Optional) `ddi_ideas.md`

## Target Schema
```
ip, ip_valid, ip_version, subnet_cidr,
hostname, hostname_valid, fqdn, fqdn_consistent, reverse_ptr,
mac, mac_valid,
owner, owner_email, owner_team,
device_type, device_type_confidence,
site, site_normalized,
source_row_id, normalization_steps
```

## Provided
- `inventory_raw.csv` (synthetic)
- `run_ipv4_validation.py.txt` (example IPv4 normalization)
- `TEMPLATES/` (documents to fill)
- `run.py.txt` (orchestrator you can extend)
