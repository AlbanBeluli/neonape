from __future__ import annotations

import dns.resolver
import whois


def lookup_whois(domain: str) -> dict[str, str]:
    record = whois.whois(domain)
    return {
        "domain_name": str(record.domain_name),
        "registrar": str(record.registrar),
        "name_servers": str(record.name_servers),
    }


def resolve_a_records(hostname: str) -> list[str]:
    answers = dns.resolver.resolve(hostname, "A")
    return [answer.to_text() for answer in answers]


def build_passive_recon_findings(profile: str, target: str) -> list[dict[str, str]]:
    if profile == "whois_lookup":
        record = lookup_whois(target)
        return [
            {"type": "whois", "host": target, "key": key, "value": value}
            for key, value in record.items()
            if value and value != "None"
        ]
    if profile == "dns_a_records":
        return [
            {"type": "dns_a", "host": target, "key": target, "value": address}
            for address in resolve_a_records(target)
        ]
    raise ValueError(f"Unsupported passive recon profile: {profile}")
