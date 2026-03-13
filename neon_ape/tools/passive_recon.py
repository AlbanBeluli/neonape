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
