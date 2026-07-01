#!/usr/bin/env python3
"""Standard-library helper for Universal Log Scrubber optional processing.

PowerShell remains the orchestrator and the safety authority.  This helper reads
one JSON control document from stdin and writes one JSON result to stdout.  Salts
and token-map context are intentionally kept out of argv/process listings.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import platform
import re
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


TOKEN_RE = re.compile(
    r"^(HV_)?(PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM|FIELD|LABEL)_[A-F0-9]{4,}$|"
    r"^UNMAPPED_(UPN|PRINCIPAL|DNS|OBJECT|IP)_[A-F0-9]{4,}$|"
    r"^(BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+$",
    re.IGNORECASE,
)

SHAPE_DETECTORS = (
    ("SID", "SID", "S-1-", re.compile(r"S-1-\d+(?:-\d+)+")),
    ("GUID", "GUID", "", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("Email/UPN", "UNMAPPED_UPN", "@", re.compile(r"[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("IPv4", "IP", "", re.compile(r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)")),
    ("DOMAIN\\user", "PRINCIPAL", "\\", re.compile(r"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+")),
    ("FQDN", "DNS", ".", re.compile(r"(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")),
    ("LongHex", "CERT", "", re.compile(r"(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])")),
    ("JWT", "JWT", "eyJ", re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")),
    ("AWS_ARN", "ARN", "arn:", re.compile(r"arn:aws[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[0-9]*:[A-Za-z0-9_/.:\-]+")),
    ("AWS_Key", "AWSKEY", "", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("CloudInstance", "INSTANCE", "i-", re.compile(r"\bi-[0-9a-f]{8,17}\b")),
    ("MAC", "MAC", "", re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")),
    ("IPv6", "IP6", ":", re.compile(r"(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:")),
    ("Base64Blob", "BLOB", "", re.compile(r"(?<![A-Za-z0-9+/=_])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")),
)

SECRET_PREFILTER_RE = re.compile(
    r"(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])",
    re.IGNORECASE,
)

SECRET_PATTERNS = (
    ("PEM", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.IGNORECASE | re.DOTALL), 0, "PEM"),
    ("Authorization secret", re.compile(r"\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+([A-Za-z0-9+/_=.\-]{12,})", re.IGNORECASE), 1, "SECRET"),
    ("Key/value secret", re.compile(r"\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*[\"']?([^\"'\s;,]{8,})", re.IGNORECASE), 1, "SECRET"),
    ("Connection string", re.compile(r"\b(?:Server|Data Source)=[^;\r\n]+;(?:[^;\r\n]+;){0,8}(?:Password|Pwd)=[^;\r\n]+", re.IGNORECASE), 0, "CONNSTR"),
    ("API key", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16})\b"), 0, "APIKEY"),
    ("High entropy secret", re.compile(r"\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*[\"']?([A-Za-z0-9+/_=\-.]{24,})", re.IGNORECASE), 1, "SECRET"),
)

DEFAULT_LABEL_RULES = (
    ("SecretLabels", ("api key", "api_key", "apikey", "access token", "access_token", "refresh token", "refresh_token", "client secret", "client_secret", "secret", "password", "passwd", "pwd", "authorization", "auth token", "bearer token"), "SECRET"),
    ("PrincipalLabels", ("account name", "account", "user name", "username", "user", "principal", "subject", "actor", "caller", "login", "identity", "client user"), "PRINCIPAL"),
    ("DomainTenantLabels", ("account domain", "domain", "tenant", "tenant id", "tenantid", "organization", "org", "realm"), "X500"),
    ("HostLabels", ("host", "hostname", "server", "server name", "machine", "machine name", "computer", "computer name", "device", "workstation", "workstation name", "client name", "target server name", "pod", "container", "node", "instance"), "DNS"),
    ("AddressLabels", ("ip", "ip address", "src_ip", "dst_ip", "source ip", "destination ip", "source address", "destination address", "source network address", "client address", "remote addr", "remote_addr", "x-forwarded-for"), "IP"),
    ("UrlLabels", ("url", "uri", "endpoint", "callback", "redirect_uri", "redirect uri"), "URI"),
    ("ObjectIdLabels", ("session", "session id", "sessionid", "request id", "requestid", "correlation id", "correlationid", "trace id", "traceid", "span id", "spanid", "transaction id", "transactionid"), "OBJECT"),
)

DEFAULT_ALLOWED_DOMAINS = {
    "microsoft.com", "windows.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
    "azure.com", "windowsupdate.com", "msftncsi.com", "msn.com", "bing.com", "outlook.com", "msedge.net",
    "google.com", "googleapis.com", "gstatic.com",
}


def emit(obj: Dict[str, object]) -> int:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0


def now() -> float:
    return time.perf_counter()


def write_progress(control: Dict[str, object], phase: str, rows: int = -1, rows_total: int = 0, bytes_done: int = -1, bytes_total: int = 0, status: str = "Running", unique: int = -1, findings: int = -1, force: bool = False) -> None:
    return
    path = str(control.get("progressPath") or "")
    if not path:
        return
    last = float(control.setdefault("_lastProgress", 0.0))
    current = now()
    if not force and current - last < 0.5:
        return
    control["_lastProgress"] = current
    obj = {
        "Phase": phase,
        "RowsDone": int(rows),
        "RowsTotal": int(rows_total or control.get("rowsTotal") or 0),
        "BytesDone": int(bytes_done),
        "BytesTotal": int(bytes_total or control.get("bytesTotal") or 0),
        "Status": status,
        "Unique": int(unique),
        "Findings": int(findings),
        "UpdatedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        pass


def normalize_san(value: str) -> str:
    v = value.strip()
    for pattern in (
        r"(?i)principal name\s*=\s*(.+)$",
        r"(?i)rfc822 name\s*=\s*(.+)$",
        r"(?i)upn\s*=\s*(.+)$",
        r"(?i)email\s*=\s*(.+)$",
    ):
        match = re.search(pattern, v)
        if match:
            v = match.group(1)
            break
    v = re.sub(r"(?i)^smtp:", "", v)
    v = re.sub(r"(?i)^mailto:", "", v)
    return v.strip()


def normalize_token_key(value: str) -> str:
    if value is None:
        return ""
    v = normalize_san(str(value))
    if not v.strip():
        return ""
    return re.sub(r"[\r\n]", " ", v.strip()).lower()


def hmac_token(value: str, prefix: str, salt: str, length: int) -> str:
    normalized = normalize_token_key(value)
    if not normalized:
        return ""
    out_len = min(max(int(length), 4), 64)
    digest = hmac.new(salt.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:out_len].upper()
    return f"{prefix}_{digest}"


def salt_fingerprint(salt: str) -> str:
    return hashlib.sha256(salt.encode("utf-8")).hexdigest()[:12].upper()


def is_already_token(value: str) -> bool:
    return bool(value and TOKEN_RE.match(value.strip()))


def is_dotted_decimal(value: str) -> bool:
    return bool(re.match(r"^([0-9]+\.)+[0-9]+$", value.strip()))


def valid_ipv4(value: str) -> bool:
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def preserve_dotted_decimal(value: str) -> bool:
    return is_dotted_decimal(value) and not valid_ipv4(value)


def is_allowed_domain(value: str, allowed_domains: Sequence[str]) -> bool:
    v = value.strip().strip(".,;:)]}'\"").lower()
    if not v:
        return False
    for domain in allowed_domains:
        d = str(domain).strip().lower()
        if d and (v == d or v.endswith("." + d)):
            return True
    return False


def well_known_sid(value: str) -> bool:
    v = value.strip()
    return bool(
        re.match(r"^S-1-0-0$", v)
        or re.match(r"^S-1-1-0$", v)
        or re.match(r"^S-1-[23]-", v)
        or re.match(r"^S-1-5-(18|19|20|113|114)$", v)
        or re.match(r"^S-1-5-(32|80|90|96)-", v)
        or re.match(r"^S-1-15-", v)
        or re.match(r"^S-1-16-", v)
    )


def well_known_principal(value: str) -> bool:
    v = value.strip().strip("\"'.,;:)]}").lower()
    return bool(
        re.match(r"^(system|local service|network service|anonymous logon|guest|defaultaccount|wdagutilityaccount|dwm-\d+|umfd-\d+)$", v)
        or re.match(r"^(nt authority|builtin|workgroup|window manager|font driver host)$", v)
        or re.match(r"^(nt authority|builtin|window manager|font driver host)\\", v)
    )


def preserve_value(value: str, prefix: str, detector: str, allowed_domains: Sequence[str], scrub_policy: str) -> bool:
    v = value.strip().strip("\"'.,;:)]}")
    if not v or is_already_token(v):
        return True
    if scrub_policy.lower() != "strict":
        if prefix in ("IP", "IP6") and v.lower() in ("127.0.0.1", "::1", "localhost"):
            return True
        if prefix == "SID" and well_known_sid(v):
            return True
        if prefix == "PRINCIPAL" and well_known_principal(v):
            return True
    if preserve_dotted_decimal(v):
        return True
    if prefix in ("DNS", "UNMAPPED_UPN") and is_allowed_domain(v, allowed_domains):
        return True
    if detector == "IPv6" and re.match(r"^\d{1,5}(:\d{1,5}){1,7}$", v):
        return True
    if prefix == "BLOB" and not looks_like_base64_blob(v):
        return True
    return False


def looks_like_base64_blob(value: str) -> bool:
    v = value.strip()
    if len(v) < 40:
        return False
    return bool(re.match(r"^[A-Za-z0-9+/]{40,}={0,2}$", v))


def profile_context(control: Dict[str, object]) -> Dict[str, object]:
    profile = control.get("profile") or {}
    if not isinstance(profile, dict):
        profile = {}
    allowed = list(DEFAULT_ALLOWED_DOMAINS)
    for d in profile.get("allowedDomains") or []:
        if d:
            allowed.append(str(d))
    profile["allowedDomainsMerged"] = allowed
    return profile


def compile_optional(pattern: object, flags: int = re.IGNORECASE) -> Optional[re.Pattern]:
    if not pattern:
        return None
    try:
        return re.compile(str(pattern), flags)
    except re.error:
        return None


def should_scan_column(column: str, profile: Dict[str, object], scrub_policy: str) -> bool:
    if scrub_policy.lower() == "strict":
        return True
    schema = profile.get("schemaColumns") or []
    for rule in schema:
        try:
            rx = re.compile(str(rule.get("regex") or ""), re.IGNORECASE)
            if rx.search(column) and str(rule.get("action") or "").lower() == "passthrough":
                return False
        except re.error:
            continue
    pass_rx = compile_optional(profile.get("passThroughRegex"), re.IGNORECASE)
    if pass_rx and pass_rx.search(column):
        return False
    return True


def rule_matches(rule: Dict[str, object], column: str) -> bool:
    try:
        rx = re.compile(str(rule.get("regex") or ""), re.IGNORECASE)
        return bool(rx.search(column))
    except re.error:
        return False


def first_matching_rule(profile: Dict[str, object], name: str, column: str) -> Optional[Dict[str, object]]:
    for rule in profile.get(name) or []:
        if isinstance(rule, dict) and rule_matches(rule, column):
            return rule
    return None


def value_shape_prefix(value: str) -> Optional[str]:
    v = value.strip()
    if not v:
        return None
    if re.match(r"^S-1-\d+(?:-\d+)+$", v):
        return "SID"
    if re.match(r"^[{]?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$", v):
        return "GUID"
    if re.match(r"^[0-9a-fA-F]{32,}$", v):
        return "CERT"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "UNMAPPED_UPN"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v):
        return "IP"
    if "\\" in v and re.match(r"^[^\\\s]+\\[^\\\s]+$", v):
        return "PRINCIPAL"
    if re.match(r"^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+$", v):
        return "DNS"
    return None


def fallback_prefix(column: str, value: str, profile: Dict[str, object]) -> Optional[str]:
    col = (column or "").lower()
    if ";" in value or "|" in value:
        return None
    if not re.search(r"serial|certificate|cert|hash|thumbprint", col) and re.search(r"requestid|date|time|when|disposition|validity|count|number|status|flag|enabled|required|approval|candidate", col):
        return None
    if re.search(r"eku|oid|authcapable|published", col):
        return None
    if re.match(r"^S-1-\d+(?:-\d+)+$", value.strip()):
        return "SID"
    for rule in profile.get("columnPrefix") or []:
        if not isinstance(rule, dict):
            continue
        pattern = str(rule.get("pattern") or "")
        if not pattern:
            continue
        try:
            if not re.search(pattern, col, re.IGNORECASE):
                continue
        except re.error:
            continue
        if bool(rule.get("notOid")) and re.match(r"^([0-9]+\.)+[0-9]+$", value.strip()):
            continue
        if bool(rule.get("dollarComputer")) and value.strip().endswith("$"):
            return "COMPUTER"
        return str(rule.get("prefix") or "OBJECT")
    return value_shape_prefix(value)


def tokenize_whole_value(value: str, prefix: str, split_on: object, control: Dict[str, object], token_by_norm: Dict[str, str]) -> str:
    text = str(value)
    if not text.strip():
        return text
    split_pattern = str(split_on or "")
    if split_pattern:
        try:
            if re.search(split_pattern, text):
                pieces = re.split("(" + split_pattern + ")", text)
                out: List[str] = []
                for piece in pieces:
                    if re.fullmatch(split_pattern, piece):
                        out.append(piece)
                        continue
                    clean = piece.strip()
                    if not clean or is_already_token(clean):
                        out.append(piece)
                    else:
                        out.append(get_token(clean, prefix, control, token_by_norm))
                return "".join(out)
        except re.error:
            pass
    clean = text.strip()
    if is_already_token(clean):
        return clean
    return get_token(clean, prefix, control, token_by_norm)


def token_for_atomic_value(column: str, value: str, profile: Dict[str, object], control: Dict[str, object], token_by_norm: Dict[str, str]) -> str:
    if not str(value).strip():
        return value
    clean = normalize_san(value) if re.search(r"SAN|UPN|Email", column or "", re.IGNORECASE) else str(value).strip()
    if not clean or is_already_token(clean):
        return clean
    norm = normalize_token_key(clean)
    if norm and norm in token_by_norm:
        return token_by_norm[norm]
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")
    if scrub_policy.lower() != "strict" and well_known_principal(clean):
        return clean
    if preserve_dotted_decimal(clean):
        return clean
    if re.match(r"^(true|false)$", clean, re.IGNORECASE):
        return clean
    if re.search(r"date|time|when|notbefore|notafter", column or "", re.IGNORECASE):
        if re.match(r"^\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+\-Z]+)?$", clean):
            return clean
    prefix = fallback_prefix(column, clean, profile)
    if prefix and not preserve_value(clean, prefix, "AtomicValue", profile.get("allowedDomainsMerged") or DEFAULT_ALLOWED_DOMAINS, scrub_policy):
        return hmac_token(clean, prefix, str(control.get("salt") or ""), int(control.get("hmacLength") or 24))
    return clean


def scrub_cell(column: str, value: str, control: Dict[str, object], token_by_norm: Dict[str, str], patterns) -> str:
    text = str(value)
    if not text.strip():
        return text
    profile = profile_context(control)
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")

    whole_rule = first_matching_rule(profile, "wholeColumnRules", column)
    if whole_rule:
        return tokenize_whole_value(text, str(whole_rule.get("prefix") or "OBJECT"), whole_rule.get("splitOn"), control, token_by_norm)

    schema_rule = first_matching_rule(profile, "schemaColumns", column)
    if schema_rule and str(schema_rule.get("action") or "").lower() == "scrub":
        return tokenize_whole_value(text, str(schema_rule.get("prefix") or "OBJECT"), schema_rule.get("splitOn"), control, token_by_norm)
    if schema_rule and str(schema_rule.get("action") or "").lower() == "passthrough":
        return text

    pass_rx = compile_optional(profile.get("passThroughRegex"), re.IGNORECASE)
    if pass_rx and pass_rx.search(column or ""):
        if scrub_policy.lower() != "strict":
            return text
        if re.match(r"^[0-9]+$", text.strip()) or re.match(r"^\d{4}-\d{2}-\d{2}[T ]", text.strip()):
            return text
        return harden_text(text, control, token_by_norm, patterns)

    if ";" in text or "|" in text:
        delimiter = ";" if ";" in text else "|"
        parts = text.split(delimiter)
        rebuilt: List[str] = []
        for part in parts:
            p = part.strip()
            rebuilt.append(harden_text(token_for_atomic_value(column, p, profile, control, token_by_norm), control, token_by_norm, patterns) if p else p)
        return delimiter.join(rebuilt)

    exact = token_for_atomic_value(column, text, profile, control, token_by_norm)
    if exact != text or is_already_token(exact):
        return exact

    free_rx = compile_optional(profile.get("freeTextRegex"), re.IGNORECASE)
    if (schema_rule and str(schema_rule.get("action") or "").lower() == "scan") or bool(profile.get("denyByDefault")) or (free_rx and free_rx.search(column or "")):
        return harden_text(text, control, token_by_norm, patterns)
    return text


def label_rules(control: Dict[str, object]) -> List[Tuple[str, re.Pattern, str]]:
    profile = profile_context(control)
    rules: List[Tuple[str, re.Pattern, str]] = []
    raw_rules = list(DEFAULT_LABEL_RULES)
    for raw in profile.get("labelRules") or []:
        if not isinstance(raw, dict):
            continue
        labels = raw.get("Labels") or raw.get("labels") or raw.get("Label") or raw.get("label") or []
        if isinstance(labels, str):
            labels = [labels]
        prefix = str(raw.get("Prefix") or raw.get("prefix") or "OBJECT")
        name = str(raw.get("Name") or raw.get("name") or "ProfileLabel")
        raw_rules.append((name, tuple(str(x) for x in labels if str(x).strip()), prefix))
    for name, labels, prefix in raw_rules:
        if not labels:
            continue
        label_rx = "|".join(re.escape(x.strip()) for x in labels if str(x).strip())
        if not label_rx:
            continue
        try:
            rx = re.compile(r"(?im)((?<![A-Za-z0-9_])(?:" + label_rx + r")(?![A-Za-z0-9_])\s*(?:[:=])\s*)(\"[^\"\r\n]{1,512}\"|'[^'\r\n]{1,512}'|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|NT AUTHORITY|Window Manager|Font Driver Host|[^,\s;|]{1,512})")
            rules.append((name, rx, prefix))
        except re.error:
            continue
    return rules


def labeled_prefix(label: str, value: str, default_prefix: str) -> str:
    l = label.lower()
    v = value.strip().strip("\"'")
    if default_prefix in ("SECRET", "APIKEY", "CONNSTR", "PEM"):
        return default_prefix
    if re.search(r"(key|secret|token|password|passwd|pwd|auth)", l):
        return "SECRET"
    if re.search(r"(address|addr|ip|x-forwarded)", l):
        return "IP6" if ":" in v else ("IP" if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v) else "DNS")
    if re.search(r"(url|uri|endpoint|callback|redirect)", l):
        return "URI"
    if re.search(r"(host|server|machine|computer|device|workstation|node|pod|container|instance|client name)", l):
        return "DNS"
    if re.search(r"(domain|tenant|organization|org|realm)", l):
        return "X500"
    if v.endswith("$"):
        return "COMPUTER"
    return default_prefix or "OBJECT"


def preserve_labeled_value(value: str, prefix: str, allowed: Sequence[str], scrub_policy: str) -> bool:
    v = value.strip().strip("\"'.,;:)]}")
    if not v or is_already_token(v):
        return True
    if re.match(r"^(?:-|N/A|NULL|\(null\))$", v, re.IGNORECASE):
        return True
    if well_known_principal(v) and scrub_policy.lower() != "strict":
        return True
    return preserve_value(v, prefix, "UniversalLabel", allowed, scrub_policy)


def secret_candidates(text: str, allowed: Sequence[str], scrub_policy: str) -> Iterable[Tuple[str, str, str]]:
    if not SECRET_PREFILTER_RE.search(text):
        return []
    found = []
    for name, rx, group, prefix in SECRET_PATTERNS:
        for match in rx.finditer(text):
            raw = match.group(group) if group else match.group(0)
            raw = raw.strip().strip("\"'")
            if len(raw) < 8 or is_already_token(raw):
                continue
            if re.match(r"(?i)^(true|false|null|none|redacted|masked|password|\*+|x+)$", raw):
                continue
            found.append((raw, prefix, name))
    return found


def identifiers_in_text(text: str, control: Dict[str, object]) -> List[Tuple[str, str, str]]:
    profile = profile_context(control)
    allowed = profile.get("allowedDomainsMerged") or list(DEFAULT_ALLOWED_DOMAINS)
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")
    by_norm: Dict[str, Tuple[str, str, str]] = {}

    def add(raw: str, prefix: str, detector: str) -> None:
        raw = (raw or "").strip().strip("\"'")
        if not raw or is_already_token(raw):
            return
        if preserve_value(raw, prefix, detector, allowed, scrub_policy):
            return
        norm = normalize_token_key(raw)
        if norm and norm not in by_norm:
            by_norm[norm] = (raw, prefix, detector)

    for name, rx, default_prefix in label_rules(control):
        for match in rx.finditer(text):
            prefix_text = match.group(1)
            label = re.sub(r"\s*(?:[:=])\s*$", "", prefix_text).strip()
            raw = match.group(2).strip().strip("\"'")
            prefix = labeled_prefix(label, raw, default_prefix)
            if not preserve_labeled_value(raw, prefix, allowed, scrub_policy):
                add(raw, prefix, name)

    for raw, prefix, detector in secret_candidates(text, allowed, scrub_policy):
        add(raw, prefix, detector)

    for detector, prefix, sentinel, rx in SHAPE_DETECTORS:
        if sentinel and sentinel.lower() not in text.lower():
            continue
        for match in rx.finditer(text):
            raw = match.group(0)
            if detector == "IPv6" and re.match(r"^\d{1,5}(:\d{1,5}){1,7}$", raw):
                continue
            add(raw, prefix, detector)
    return list(by_norm.values())


def token_prefix_for_sensitive_term(term: str) -> str:
    if re.match(r"^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$", term):
        return "DNS"
    return "X500"


def get_token(raw: str, prefix: str, control: Dict[str, object], token_by_norm: Optional[Dict[str, str]] = None) -> str:
    norm = normalize_token_key(raw)
    if token_by_norm and norm in token_by_norm:
        return token_by_norm[norm]
    return hmac_token(raw, prefix, str(control.get("salt") or ""), int(control.get("hmacLength") or 24))


def local_part(raw: str, prefix: str) -> Optional[str]:
    if prefix == "UNMAPPED_UPN" and "@" in raw:
        return raw.split("@", 1)[0].lower()
    if prefix == "PRINCIPAL" and "\\" in raw:
        return raw.rsplit("\\", 1)[-1].rstrip("$").lower()
    return None


class UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, value: str) -> str:
        if value not in self.parent:
            self.parent[value] = value
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, a: str, b: str) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def first_existing(row: Dict[str, str], names: Sequence[str]) -> str:
    lower = {str(k).lower(): k for k in row.keys()}
    for name in names:
        key = lower.get(name.lower())
        if key is not None:
            return row.get(key, "") or ""
    return ""


def read_existing_rows(path: str, control: Dict[str, object]) -> Dict[str, Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}
    if not path or not os.path.exists(path):
        return seen
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            raw = first_existing(row, ("InputValue", "OriginalValue", "Value", "SourceValue"))
            norm = first_existing(row, ("NormalizedValue", "Normalized", "NormalizedKey")) or normalize_token_key(raw)
            token = first_existing(row, ("Token", "ScrubbedValue", "Replacement"))
            if not norm or not token:
                continue
            seen[norm] = {
                "InputValue": raw,
                "NormalizedValue": norm,
                "Token": token,
                "TokenType": row.get("TokenType") or "OBJECT",
                "Source": row.get("Source") or "ExistingMap",
                "SaltFingerprint": row.get("SaltFingerprint") or salt_fingerprint(str(control.get("salt") or "")),
                "HmacLength": str(row.get("HmacLength") or control.get("hmacLength") or 24),
                "FirstSeenSource": row.get("FirstSeenSource") or row.get("Source") or "ExistingMap",
                "LastSeenSource": row.get("LastSeenSource") or row.get("Source") or "ExistingMap",
                "SourcePathHash": row.get("SourcePathHash") or "",
            }
    return seen


def map_row(raw: str, prefix: str, source: str, source_hash: str, control: Dict[str, object]) -> Dict[str, str]:
    token = get_token(raw, prefix, control)
    norm = normalize_token_key(raw)
    return {
        "InputValue": raw,
        "NormalizedValue": norm,
        "Token": token,
        "TokenType": prefix,
        "Source": source,
        "SaltFingerprint": salt_fingerprint(str(control.get("salt") or "")),
        "HmacLength": str(int(control.get("hmacLength") or 24)),
        "FirstSeenSource": source,
        "LastSeenSource": source,
        "SourcePathHash": source_hash or "",
    }


def write_token_map(path: str, rows: Sequence[Dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    headers = ("InputValue", "NormalizedValue", "Token", "TokenType", "Source", "SaltFingerprint", "HmacLength", "FirstSeenSource", "LastSeenSource", "SourcePathHash")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (r.get("Token", ""), r.get("InputValue", ""))):
            writer.writerow(row)
    os.replace(tmp, path)


def discover(control: Dict[str, object]) -> Dict[str, object]:
    output_map = str(control.get("tokenMapCsv") or "")
    if not output_map:
        return {"ok": False, "error": "tokenMapCsv is required"}
    input_paths = control.get("inputPaths") or []
    if isinstance(input_paths, str):
        input_paths = [input_paths]
    if not input_paths:
        return {"ok": False, "error": "inputPaths is required"}

    seen = read_existing_rows(output_map, control) if str(control.get("tokenMapMode") or "Merge").lower() == "merge" else {}
    uf = UnionFind()
    row_by_local: Dict[str, List[str]] = {}
    profile = profile_context(control)
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")
    delimiter = str(control.get("delimiter") or ",")
    fmt = str(control.get("format") or "Text")
    total_rows = 0
    total_bytes = 0
    hits = 0
    started = now()

    for file_index, path_obj in enumerate(input_paths, 1):
        path = str(path_obj)
        name = os.path.basename(path)
        source = f"Discovery:{name}"
        source_hashes = control.get("sourcePathHashes") or {}
        source_hash = str(source_hashes.get(path) or source_hashes.get(name) or "")
        file_bytes_total = 0
        try:
            file_bytes_total = os.path.getsize(path)
        except OSError:
            pass
        write_progress(control, "Python discovery", rows=total_rows, bytes_done=total_bytes, bytes_total=file_bytes_total, unique=len(seen), status=f"Starting {name}", force=True)
        if fmt in ("Csv", "Tsv", "Psv") or path.lower().endswith((".csv", ".tsv", ".psv")):
            delim = delimiter
            if path.lower().endswith(".tsv"):
                delim = "\t"
            elif path.lower().endswith(".psv"):
                delim = "|"
            with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.reader(handle, delimiter=delim)
                try:
                    headers = next(reader)
                except StopIteration:
                    headers = []
                scan_cols = [should_scan_column(h, profile, scrub_policy) for h in headers]
                for record in reader:
                    total_rows += 1
                    row_by_local.clear()
                    for index, cell in enumerate(record):
                        if index < len(scan_cols) and not scan_cols[index]:
                            continue
                        for raw, prefix, _detector in identifiers_in_text(str(cell), control):
                            norm = normalize_token_key(raw)
                            if not norm:
                                continue
                            if norm not in seen:
                                seen[norm] = map_row(raw, prefix, source, source_hash, control)
                                hits += 1
                            else:
                                seen[norm]["LastSeenSource"] = source
                                if not seen[norm].get("SourcePathHash"):
                                    seen[norm]["SourcePathHash"] = source_hash
                            lp = local_part(raw, prefix)
                            if lp and len(lp) >= 3:
                                row_by_local.setdefault(lp, []).append(norm)
                    if not bool(control.get("noCorrelate")):
                        for members in row_by_local.values():
                            if len(members) > 1:
                                for member in members[1:]:
                                    uf.union(members[0], member)
                    if total_rows % 1000 == 0:
                        total_bytes = min(file_bytes_total, total_bytes + sum(len(x.encode("utf-8", errors="ignore")) for x in record))
                        write_progress(control, "Python discovery", rows=total_rows, bytes_done=total_bytes, bytes_total=file_bytes_total, unique=len(seen), status=name)
        else:
            with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                for line in handle:
                    total_rows += 1
                    total_bytes += len(line.encode("utf-8", errors="ignore"))
                    row_by_local.clear()
                    for raw, prefix, _detector in identifiers_in_text(line, control):
                        norm = normalize_token_key(raw)
                        if not norm:
                            continue
                        if norm not in seen:
                            seen[norm] = map_row(raw, prefix, source, source_hash, control)
                            hits += 1
                        else:
                            seen[norm]["LastSeenSource"] = source
                            if not seen[norm].get("SourcePathHash"):
                                seen[norm]["SourcePathHash"] = source_hash
                        lp = local_part(raw, prefix)
                        if lp and len(lp) >= 3:
                            row_by_local.setdefault(lp, []).append(norm)
                    if not bool(control.get("noCorrelate")):
                        for members in row_by_local.values():
                            if len(members) > 1:
                                for member in members[1:]:
                                    uf.union(members[0], member)
                    if total_rows % 1000 == 0:
                        write_progress(control, "Python discovery", rows=total_rows, bytes_done=total_bytes, bytes_total=file_bytes_total, unique=len(seen), status=name)

    for term_obj in control.get("seedTerms") or []:
        term = str(term_obj or "").strip()
        if len(term) < 3:
            continue
        norm = normalize_token_key(term)
        if norm and norm not in seen:
            prefix = token_prefix_for_sensitive_term(term)
            seen[norm] = map_row(term, prefix, "SeedTerm", "", control)

    if not bool(control.get("noCorrelate")) and uf.parent:
        groups: Dict[str, List[str]] = {}
        for norm in list(uf.parent.keys()):
            root = uf.find(norm)
            groups.setdefault(root, []).append(norm)
        for members in groups.values():
            present = [m for m in members if m in seen]
            if len(present) < 2:
                continue
            raws = [seen[m]["InputValue"] for m in present]
            emails = sorted(x for x in raws if "@" in x)
            canonical = emails[0] if emails else sorted(raws)[0]
            shared = hmac_token(canonical, "PRINCIPAL", str(control.get("salt") or ""), int(control.get("hmacLength") or 24))
            for m in present:
                seen[m]["Token"] = shared
                if not seen[m]["Source"].endswith("+corr"):
                    seen[m]["Source"] += "+corr"

    write_token_map(output_map, list(seen.values()))
    elapsed = max(now() - started, 0.000001)
    write_progress(control, "Python discovery", rows=total_rows, bytes_done=total_bytes, unique=len(seen), status="Completed", force=True)
    return {"ok": True, "rows": total_rows, "bytes": total_bytes, "entries": len(seen), "hits": hits, "seconds": elapsed, "rowsPerSecond": total_rows / elapsed, "tokenMapCsv": output_map}


def load_replacements(control: Dict[str, object]) -> Tuple[List[Tuple[str, str]], Dict[str, str]]:
    replacements: Dict[str, Tuple[str, str]] = {}
    token_by_norm: Dict[str, str] = {}
    token_map_csv = str(control.get("tokenMapCsv") or "")
    if token_map_csv:
        with open(token_map_csv, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                raw = first_existing(row, ("InputValue", "OriginalValue", "Value", "SourceValue"))
                norm = first_existing(row, ("NormalizedValue", "Normalized", "NormalizedKey")) or normalize_token_key(raw)
                token = first_existing(row, ("Token", "ScrubbedValue", "Replacement"))
                raw = str(raw or "").strip()
                token = str(token or "").strip()
                if norm and token:
                    token_by_norm[norm] = token
                if len(raw) < 3 or not token or raw == token or is_already_token(raw):
                    continue
                key = raw.casefold()
                current = replacements.get(key)
                if current is None or len(raw) > len(current[0]):
                    replacements[key] = (raw, token)

    for term_obj in control.get("sensitiveTerms") or []:
        term = str(term_obj or "").strip()
        if len(term) < 3:
            continue
        token = hmac_token(term, token_prefix_for_sensitive_term(term), str(control.get("salt") or ""), int(control.get("hmacLength") or 24))
        if token:
            replacements[term.casefold()] = (term, token)
            token_by_norm[normalize_token_key(term)] = token

    return sorted(replacements.values(), key=lambda item: len(item[0]), reverse=True), token_by_norm


def build_patterns(replacements: Sequence[Tuple[str, str]], chunk_size: int = 400):
    chunks = []
    for start in range(0, len(replacements), chunk_size):
        chunk = list(replacements[start : start + chunk_size])
        if not chunk:
            continue
        lookup = {raw.casefold(): token for raw, token in chunk}
        pattern = re.compile("|".join(re.escape(raw) for raw, _ in chunk), re.IGNORECASE)
        chunks.append((pattern, lookup))
    return chunks


def replace_text(text: str, patterns) -> str:
    out = text
    for pattern, lookup in patterns:
        out = pattern.sub(lambda match: lookup.get(match.group(0).casefold(), match.group(0)), out)
    return out


def harden_text(text: str, control: Dict[str, object], token_by_norm: Dict[str, str], patterns) -> str:
    out = replace_text(text, patterns)
    if bool(control.get("mapOnlyScrub")):
        return out
    profile = profile_context(control)
    allowed = profile.get("allowedDomainsMerged") or list(DEFAULT_ALLOWED_DOMAINS)
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")

    for name, rx, default_prefix in label_rules(control):
        def repl_label(match: re.Match) -> str:
            prefix_text = match.group(1)
            label = re.sub(r"\s*(?:[:=])\s*$", "", prefix_text).strip()
            raw = match.group(2).strip().strip("\"'")
            prefix = labeled_prefix(label, raw, default_prefix)
            if preserve_labeled_value(raw, prefix, allowed, scrub_policy):
                return match.group(0)
            return prefix_text + get_token(raw, prefix, control, token_by_norm)
        out = rx.sub(repl_label, out)

    for _name, rx, group, prefix in SECRET_PATTERNS:
        def repl_secret(match: re.Match, group: int = group, prefix: str = prefix) -> str:
            raw = match.group(group) if group else match.group(0)
            raw = raw.strip().strip("\"'")
            if len(raw) < 8 or is_already_token(raw):
                return match.group(0)
            tok = get_token(raw, prefix, control, token_by_norm)
            if group == 0:
                return tok
            rel = match.start(group) - match.start(0)
            return match.group(0)[:rel] + tok + match.group(0)[rel + len(match.group(group)) :]
        out = rx.sub(repl_secret, out)

    for detector, prefix, sentinel, rx in SHAPE_DETECTORS:
        if sentinel and sentinel.lower() not in out.lower():
            continue
        def repl_shape(match: re.Match, detector: str = detector, prefix: str = prefix) -> str:
            raw = match.group(0)
            if preserve_value(raw, prefix, detector, allowed, scrub_policy):
                return raw
            return get_token(raw, prefix, control, token_by_norm)
        out = rx.sub(repl_shape, out)
    return out


def scrub_file(control: Dict[str, object]) -> Dict[str, object]:
    input_path = str(control.get("inputPath") or "")
    output_path = str(control.get("outputPath") or "")
    if not input_path or not output_path:
        return {"ok": False, "error": "inputPath and outputPath are required"}
    replacements, token_by_norm = load_replacements(control)
    patterns = build_patterns(replacements)

    rows = 0
    bytes_in = 0
    started = now()
    total_bytes = 0
    try:
        total_bytes = os.path.getsize(input_path)
    except OSError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_progress(control, "Python scrub", rows=0, bytes_done=0, bytes_total=total_bytes, status="Starting", force=True)
    fmt = str(control.get("format") or "")
    lower_path = input_path.lower()
    if fmt in ("Csv", "Tsv", "Psv") or lower_path.endswith((".csv", ".tsv", ".psv")):
        delim = str(control.get("delimiter") or ",")
        if lower_path.endswith(".tsv"):
            delim = "\t"
        elif lower_path.endswith(".psv"):
            delim = "|"
        with open(input_path, "r", encoding="utf-8-sig", errors="replace", newline="") as reader:
            with open(output_path, "w", encoding="utf-8", newline="") as writer:
                csv_reader = csv.reader(reader, delimiter=delim)
                csv_writer = csv.writer(writer, delimiter=delim, lineterminator="\n")
                try:
                    headers = next(csv_reader)
                except StopIteration:
                    headers = []
                if headers:
                    csv_writer.writerow(headers)
                for record in csv_reader:
                    rows += 1
                    bytes_in = min(total_bytes, bytes_in + sum(len(str(x).encode("utf-8", errors="ignore")) for x in record) + max(len(record) - 1, 0))
                    out_row: List[str] = []
                    for index, header in enumerate(headers):
                        raw = record[index] if index < len(record) else ""
                        out_row.append(scrub_cell(header, raw, control, token_by_norm, patterns))
                    csv_writer.writerow(out_row)
                    if rows % 1000 == 0:
                        write_progress(control, "Python scrub", rows=rows, bytes_done=bytes_in, bytes_total=total_bytes, status="Running")
    else:
        with open(input_path, "r", encoding="utf-8-sig", errors="replace", newline="") as reader:
            with open(output_path, "w", encoding="utf-8", newline="") as writer:
                for line in reader:
                    rows += 1
                    bytes_in += len(line.encode("utf-8", errors="ignore"))
                    writer.write(harden_text(line, control, token_by_norm, patterns))
                    if rows % 1000 == 0:
                        write_progress(control, "Python scrub", rows=rows, bytes_done=bytes_in, bytes_total=total_bytes, status="Running")
    elapsed = max(now() - started, 0.000001)
    write_progress(control, "Python scrub", rows=rows, bytes_done=bytes_in, bytes_total=total_bytes, status="Completed", force=True)
    return {"ok": True, "rows": rows, "bytes": bytes_in, "seconds": elapsed, "replacements": len(replacements), "rowsPerSecond": rows / elapsed}


def leak_findings_for_line(line: str, control: Dict[str, object]) -> List[Tuple[str, str]]:
    findings: List[Tuple[str, str]] = []
    profile = profile_context(control)
    allowed = profile.get("allowedDomainsMerged") or list(DEFAULT_ALLOWED_DOMAINS)
    scrub_policy = str(control.get("scrubPolicy") or "Balanced")
    for term_obj in control.get("sensitiveTerms") or []:
        term = str(term_obj or "").strip()
        if len(term) >= 3 and re.search(re.escape(term), line, re.IGNORECASE):
            findings.append((f"SensitiveTerm '{term}'", term))
    for raw, _prefix, detector in identifiers_in_text(line, control):
        if is_already_token(raw):
            continue
        findings.append((detector, raw))
    for detector, prefix, sentinel, rx in SHAPE_DETECTORS:
        if sentinel and sentinel.lower() not in line.lower():
            continue
        for match in rx.finditer(line):
            raw = match.group(0)
            if not preserve_value(raw, prefix, detector, allowed, scrub_policy):
                findings.append((detector, raw))
    return findings


def leak_check(control: Dict[str, object]) -> Dict[str, object]:
    path = str(control.get("path") or control.get("inputPath") or "")
    if not path:
        return {"ok": False, "error": "path is required"}
    skip_first = bool(control.get("skipFirstLine"))
    rows = 0
    bytes_in = 0
    total_bytes = 0
    try:
        total_bytes = os.path.getsize(path)
    except OSError:
        pass
    started = now()
    buckets: Dict[str, List[str]] = {}
    seen_lines = set()
    write_progress(control, "Python leak check", rows=0, bytes_done=0, bytes_total=total_bytes, findings=0, status="Starting", force=True)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for line in handle:
            rows += 1
            bytes_in += len(line.encode("utf-8", errors="ignore"))
            if skip_first and rows == 1:
                continue
            if line in seen_lines:
                continue
            seen_lines.add(line)
            for kind, sample in leak_findings_for_line(line, control):
                bucket = buckets.setdefault(kind, [])
                if sample not in bucket and len(bucket) < 5:
                    bucket.append(sample)
            if rows % 2000 == 0:
                write_progress(control, "Python leak check", rows=rows, bytes_done=bytes_in, bytes_total=total_bytes, findings=sum(len(v) for v in buckets.values()), status="Running")
    elapsed = max(now() - started, 0.000001)
    findings = [{"Type": kind, "Count": len(samples), "Samples": ", ".join(samples[:5])} for kind, samples in sorted(buckets.items())]
    write_progress(control, "Python leak check", rows=rows, bytes_done=bytes_in, bytes_total=total_bytes, findings=len(findings), status="Completed", force=True)
    return {"ok": True, "clean": len(findings) == 0, "findings": findings, "rows": rows, "bytes": bytes_in, "seconds": elapsed}


def benchmark(control: Dict[str, object]) -> Dict[str, object]:
    operation = str(control.get("operation") or "scrub")
    input_path = str(control.get("inputPath") or "")
    max_bytes = int(control.get("maxBytes") or 1048576)
    max_lines = int(control.get("maxLines") or 2000)
    if not input_path:
        return {"ok": False, "error": "inputPath is required"}
    replacements, token_by_norm = load_replacements(control)
    patterns = build_patterns(replacements)
    sample: List[str] = []
    bytes_in = 0
    with open(input_path, "r", encoding="utf-8-sig", errors="replace", newline="") as reader:
        for line in reader:
            sample.append(line)
            bytes_in += len(line.encode("utf-8", errors="ignore"))
            if len(sample) >= max_lines or bytes_in >= max_bytes:
                break
    started = now()
    changed = 0
    found = 0
    for line in sample:
        if operation == "discover":
            found += len(identifiers_in_text(line, control))
        elif operation == "leak_check":
            found += len(leak_findings_for_line(line, control))
        else:
            replaced = harden_text(line, control, token_by_norm, patterns)
            if replaced != line:
                changed += 1
    elapsed = max(now() - started, 0.000001)
    return {"ok": True, "operation": operation, "rows": len(sample), "bytes": bytes_in, "seconds": elapsed, "changedRows": changed, "findings": found, "replacements": len(replacements), "rowsPerSecond": len(sample) / elapsed}


def capability(_: Dict[str, object]) -> Dict[str, object]:
    return {
        "ok": True,
        "version": platform.python_version(),
        "executable": sys.executable,
        "implementation": platform.python_implementation(),
        "supportedModes": ["capability", "token", "benchmark", "discover", "scrub", "leak_check"],
        "unsupportedModes": [],
    }


def token(control: Dict[str, object]) -> Dict[str, object]:
    return {"ok": True, "token": hmac_token(str(control.get("value") or ""), str(control.get("prefix") or "OBJECT"), str(control.get("salt") or ""), int(control.get("hmacLength") or 24))}


def main() -> int:
    try:
        control = json.loads(sys.stdin.read() or "{}")
        mode = str(control.get("mode") or "capability")
        handlers = {
            "capability": capability,
            "token": token,
            "benchmark": benchmark,
            "discover": discover,
            "scrub": scrub_file,
            "leak_check": leak_check,
        }
        handler = handlers.get(mode)
        if handler is None:
            return emit({"ok": False, "error": f"unknown mode '{mode}'"})
        result = handler(control)
        result.setdefault("mode", mode)
        return emit(result)
    except Exception as exc:  # pragma: no cover - defensive process boundary
        return emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    raise SystemExit(main())
