#!/usr/bin/env python3
"""
Single entry point to regenerate:
- inventory_clean.csv
- anomalies.json

Usage:
  python run.py --input inventory_raw.csv --outdir .
"""
from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
import ipaddress

import pandas as pd


OWNER_EMAIL_RE = re.compile(r"([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})", re.I)

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)

MAC_RE_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
MAC_RE_DASH = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")
MAC_RE_DOTS = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")
MAC_RE_PLAIN = re.compile(r"^[0-9A-Fa-f]{12}$")


def normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def parse_ipv4_loose(s: str) -> tuple[str | None, bool]:
    """
    Accepts IPv4 with leading zeros (e.g., 192.168.010.005), but rejects
    non-numeric, wrong octet count, or out-of-range octets.
    Returns (normalized, ok).
    """
    if not re.fullmatch(r"[0-9.]+", s):
        return None, False
    parts = s.split(".")
    if len(parts) != 4:
        return None, False
    nums: list[int] = []
    for p in parts:
        if p == "" or not re.fullmatch(r"\d+", p):
            return None, False
        n = int(p)
        if n < 0 or n > 255:
            return None, False
        nums.append(n)
    norm = ".".join(str(n) for n in nums)
    try:
        ipaddress.IPv4Address(norm)
    except Exception:
        return None, False
    return norm, True


def parse_ip(value) -> tuple[str | None, bool, int | None, list[str]]:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None, False, None, []
    orig = str(value)
    s = str(value).strip()
    steps: list[str] = []
    if s != orig:
        steps.append("trim_ip")

    # Remove IPv6 zone index (e.g., fe80::1%eth0)
    if "%" in s:
        s = s.split("%", 1)[0]
        steps.append("strip_ipv6_zone")

    # IPv6
    try:
        ip = ipaddress.ip_address(s)
        if isinstance(ip, ipaddress.IPv6Address):
            return str(ip).lower(), True, 6, steps
    except Exception:
        pass

    # Loose IPv4
    norm, ok = parse_ipv4_loose(s)
    if ok and norm is not None:
        if norm != s:
            steps.append("normalize_ipv4_leading_zeros")
        return norm, True, 4, steps

    return None, False, None, steps


def normalize_mac(value) -> tuple[str | None, bool, list[str]]:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None, False, []
    orig = str(value)
    s = str(value).strip()
    steps: list[str] = []
    if s != orig:
        steps.append("trim_mac")

    mac_raw: str | None = None
    if MAC_RE_COLON.match(s):
        mac_raw = s
    elif MAC_RE_DASH.match(s):
        mac_raw = s.replace("-", ":")
        steps.append("dash_to_colon")
    elif MAC_RE_DOTS.match(s):
        mac_raw = s.replace(".", "")
        steps.append("cisco_dots_to_plain")
    elif MAC_RE_PLAIN.match(s):
        mac_raw = s
    else:
        return None, False, steps

    hex12 = mac_raw.replace(":", "").lower()
    mac = ":".join(hex12[i : i + 2] for i in range(0, 12, 2))
    return mac, True, steps + ["lowercase_mac", "canonicalize_mac"]


def normalize_hostname(value) -> tuple[str | None, bool, list[str]]:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None, False, []
    orig = str(value)
    s = str(value).strip()
    steps: list[str] = []
    if s != orig:
        steps.append("trim_hostname")
    low = s.lower()
    if low != s:
        steps.append("lowercase_hostname")

    # Here we treat "hostname" as a single label (no dots)
    valid = bool(HOSTNAME_RE.match(low)) and ("." not in low)
    return low, valid, steps


def normalize_fqdn(hostname: str | None, fqdn_value) -> tuple[str | None, bool, list[str]]:
    steps: list[str] = []
    if fqdn_value is None or (isinstance(fqdn_value, float) and math.isnan(fqdn_value)) or str(fqdn_value).strip() == "":
        if hostname:
            steps.append("derive_fqdn_default_domain")
            fqdn = f"{hostname}.corp.example.com"
            return fqdn, True, steps
        return None, False, steps

    orig = str(fqdn_value)
    fqdn = str(fqdn_value).strip().lower()
    if fqdn != orig:
        steps.append("normalize_fqdn_lower_trim")
    valid = bool(HOSTNAME_RE.match(fqdn))
    return fqdn, valid, steps


def parse_owner(value) -> tuple[str | None, str | None, str | None, list[str]]:
    if value is None or (isinstance(value, float) and math.isnan(value)) or str(value).strip() == "":
        return None, None, None, []
    orig = str(value)
    s = normalize_whitespace(str(value))
    steps: list[str] = []
    if s != orig:
        steps.append("normalize_owner_whitespace")

    email: str | None = None
    m = OWNER_EMAIL_RE.search(s)
    if m:
        email = m.group(1).lower()
        steps.append("extract_owner_email")

    team: str | None = None
    m2 = re.search(r"\(([^)]+)\)", s)
    if m2:
        team = m2.group(1).strip().lower()
        steps.append("extract_owner_team_parens")

    name = re.sub(OWNER_EMAIL_RE, "", s)
    name = re.sub(r"\([^)]+\)", "", name)
    name = normalize_whitespace(name)
    if name == "":
        name = None
    else:
        name = name.lower()
        steps.append("normalize_owner_name")

    if team is None and name in {"ops", "sec", "platform", "facilities"}:
        team = name
        name = None
        steps.append("infer_owner_team_from_keyword")

    return name, email, team, steps


def infer_device_type(hostname: str | None, notes: str | None, device_type_value) -> tuple[str | None, float, list[str]]:
    if device_type_value is None or (isinstance(device_type_value, float) and math.isnan(device_type_value)) or str(device_type_value).strip() == "":
        hn = (hostname or "").lower()
        nt = str(notes).lower() if notes is not None else ""
        if "edge" in nt or "gw" in nt:
            return "router", 0.60, ["infer_from_notes_edge_gw"]
        if hn.startswith("printer"):
            return "printer", 0.70, ["infer_from_hostname_printer"]
        if hn.startswith("srv") or "db host" in nt:
            return "server", 0.70, ["infer_from_hostname_srv_or_notes_db"]
        if hn.startswith("iot") or "camera" in nt:
            return "iot", 0.70, ["infer_from_notes_camera"]
        return None, 0.0, ["device_type_missing"]

    s = str(device_type_value).strip().lower()
    steps: list[str] = []
    if s != str(device_type_value):
        steps.append("normalize_device_type_lower_trim")

    known = {"server", "switch", "printer", "iot", "router"}
    if s in known:
        return s, 0.95, steps
    return s, 0.40, steps + ["device_type_unknown"]


def normalize_site(value) -> tuple[str | None, str | None, list[str]]:
    if value is None or (isinstance(value, float) and math.isnan(value)) or str(value).strip() == "":
        return None, None, []
    orig = str(value)
    s = normalize_whitespace(str(value)).lower()
    steps: list[str] = []
    if s != orig:
        steps.append("normalize_site_lower_trim")

    if s in {"blr campus", "blr campus"}:
        return orig, "blr-campus", steps + ["map_site_blr"]
    if s in {"hq bldg 1", "hq-building-1", "hq", "hq building 1"}:
        return orig, "hq", steps + ["map_site_hq"]
    if s.startswith("lab"):
        return orig, s.replace(" ", "-"), steps + ["map_site_lab"]
    if s.startswith("dc"):
        return orig, s.replace(" ", "-"), steps + ["map_site_dc"]
    return orig, s.replace(" ", "-"), steps + ["site_slugify"]


def derive_subnet_cidr(ip_str: str | None, version: int | None) -> str | None:
    if not ip_str or not version:
        return None
    ip = ipaddress.ip_address(ip_str)
    if version == 4:
        if ip.is_private:
            return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip_str}/32", strict=False))
    if version == 6:
        if ip.is_link_local or ip.is_private:
            return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
        return str(ipaddress.ip_network(f"{ip_str}/128", strict=False))
    return None


def reverse_ptr(ip_str: str | None) -> str | None:
    if not ip_str:
        return None
    return ipaddress.ip_address(ip_str).reverse_pointer


def ip_anomalies(ip_str: str | None, version: int | None) -> list[dict]:
    if not ip_str or not version:
        return []
    ip = ipaddress.ip_address(ip_str)
    out: list[dict] = []

    def add(issue_type: str, action: str, field: str = "ip") -> None:
        out.append({"fields": [field], "issue_type": issue_type, "recommended_action": action})

    if version == 4:
        if ip.is_loopback:
            add("reserved_loopback", "Exclude or tag as test/localhost.")
        if ip.is_link_local:
            add("link_local_apipa", "Verify device networking; consider excluding.")
        if ip.is_multicast:
            add("multicast", "Verify if record should be removed.")

        if ip.is_private:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            if ip == net.network_address:
                add("network_id", "Confirm intended subnet and correct IP.")
            if ip == net.broadcast_address:
                add("broadcast", "Confirm intended subnet and correct IP.")

    if version == 6 and ip.is_link_local:
        add("link_local_ipv6", "Ensure scope/interface is tracked separately if needed.")

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="inventory_raw.csv", help="Path to raw CSV")
    ap.add_argument("--outdir", default=".", help="Output directory")
    args = ap.parse_args()

    in_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(in_path)

    cleaned_rows: list[dict] = []
    anomalies: list[dict] = []

    for _, r in df.iterrows():
        row_id = int(r["source_row_id"])
        steps: list[str] = []

        ip_norm, ip_ok, ip_ver, ip_steps = parse_ip(r.get("ip"))
        steps += ip_steps
        if not ip_ok:
            anomalies.append({"source_row_id": row_id, "fields": ["ip"], "issue_type": "invalid_ip",
                              "recommended_action": "Correct or remove invalid IP value."})
        else:
            for a in ip_anomalies(ip_norm, ip_ver):
                anomalies.append({"source_row_id": row_id, **a})

        subnet = derive_subnet_cidr(ip_norm, ip_ver) if ip_ok else None
        revptr = reverse_ptr(ip_norm) if ip_ok else None

        hn, hn_ok, hn_steps = normalize_hostname(r.get("hostname"))
        steps += hn_steps
        if hn and not hn_ok:
            anomalies.append({"source_row_id": row_id, "fields": ["hostname"], "issue_type": "invalid_hostname",
                              "recommended_action": "Fix hostname to RFC1123 single-label format."})

        fqdn, fqdn_ok, fqdn_steps = normalize_fqdn(hn, r.get("fqdn"))
        steps += fqdn_steps
        fqdn_consistent = bool(fqdn and hn and fqdn.startswith(hn + "."))
        if fqdn and hn and not fqdn_consistent:
            anomalies.append({"source_row_id": row_id, "fields": ["fqdn", "hostname"], "issue_type": "fqdn_inconsistent",
                              "recommended_action": "Ensure FQDN begins with hostname label or correct one of the fields."})

        mac, mac_ok, mac_steps = normalize_mac(r.get("mac"))
        steps += mac_steps
        if r.get("mac") is None or (isinstance(r.get("mac"), float) and math.isnan(r.get("mac"))):
            anomalies.append({"source_row_id": row_id, "fields": ["mac"], "issue_type": "missing_mac",
                              "recommended_action": "Populate MAC if available; otherwise leave null."})
        elif not mac_ok:
            anomalies.append({"source_row_id": row_id, "fields": ["mac"], "issue_type": "invalid_mac",
                              "recommended_action": "Fix MAC formatting to 6-byte hex."})

        owner_name, owner_email, owner_team, owner_steps = parse_owner(r.get("owner"))
        steps += owner_steps
        owner_disp = owner_name or (owner_email.split("@")[0] if owner_email else owner_team)
        if owner_disp:
            owner_disp = owner_disp.lower()

        dev, dev_conf, dev_steps = infer_device_type(hn, r.get("notes"), r.get("device_type"))
        steps += dev_steps
        if dev is None:
            anomalies.append({"source_row_id": row_id, "fields": ["device_type"], "issue_type": "missing_device_type",
                              "recommended_action": "Classify device_type or leave null with low confidence."})
        elif dev_conf < 0.70:
            anomalies.append({"source_row_id": row_id, "fields": ["device_type"], "issue_type": "low_confidence_device_type",
                              "recommended_action": "Review device_type classification; add more rules or use LLM."})

        site_raw, site_norm, site_steps = normalize_site(r.get("site"))
        steps += site_steps

        cleaned_rows.append({
            "ip": ip_norm,
            "ip_valid": bool(ip_ok),
            "ip_version": f"IPv{ip_ver}" if ip_ver else None,
            "subnet_cidr": subnet,
            "hostname": hn,
            "hostname_valid": bool(hn_ok),
            "fqdn": fqdn,
            "fqdn_consistent": bool(fqdn_consistent),
            "reverse_ptr": revptr,
            "mac": mac,
            "mac_valid": bool(mac_ok) if mac else False,
            "owner": owner_disp,
            "owner_email": owner_email,
            "owner_team": owner_team,
            "device_type": dev,
            "device_type_confidence": round(float(dev_conf), 2),
            "site": None if site_raw is None else site_raw,
            "site_normalized": site_norm,
            "source_row_id": row_id,
            "normalization_steps": ";".join(steps) if steps else "",
        })

    pd.DataFrame(cleaned_rows).to_csv(outdir / "inventory_clean.csv", index=False)
    (outdir / "anomalies.json").write_text(json.dumps(anomalies, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
