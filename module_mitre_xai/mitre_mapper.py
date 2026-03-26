#!/usr/bin/env python3
"""
atelier_d/mitre_mapper.py
Mapping robuste des événements vers MITRE ATT&CK

Correctifs importants:
✅ Spraying (T1110.003) n'est accepté que si indices "multi comptes" / spray
✅ Guessing (T1110.001) est priorisé pour "failed password for invalid user ..."
✅ Toujours anti-faux-positifs (404 seul ne mappe pas)
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    description: str
    patterns: List[str]
    severity: str


@dataclass
class MatchEvidence:
    technique_id: str
    score: float
    matched: List[str]
    reasons: List[str]
    severity: str
    tactic: str


def _now_iso() -> str:
    return datetime.now().isoformat()


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _norm_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _severity_rank(sev: str) -> int:
    sev = (sev or "").lower()
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 1)


class MitreMapper:
    def __init__(self, db_path: Optional[str] = None):
        self.techniques: Dict[str, MitreTechnique] = self._load_mitre_db(db_path)
        self.mapping_history: List[Dict[str, Any]] = []

        self._compiled: Dict[str, List[Tuple[re.Pattern, float, str, bool]]] = {}
        self._compile_patterns()

        self.last_match: Optional[MatchEvidence] = None
        self.last_top: List[MatchEvidence] = []

        print(f"[MITRE_MAPPER] 🗺️  Base chargée: {len(self.techniques)} techniques")

    def _load_mitre_db(self, db_path: Optional[str] = None) -> Dict[str, MitreTechnique]:
        mitre_data = [
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Tentatives répétées d'authentification pour deviner des identifiants.",
                "patterns": [
                    r"\bfailed password\b",
                    r"\bauthentication failure\b",
                    r"\btoo many authentication failures\b",
                    r"\binvalid user\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1110.001",
                "name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "description": "Essais successifs sur un même compte / cible (guessing).",
                "patterns": [
                    r"\bfailed password for\b",
                    r"\bfailed password for invalid user\b",
                    r"\bauthentication failure\b",
                    r"\b(sshd|ssh2)\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1110.003",
                "name": "Brute Force: Password Spraying",
                "tactic": "Credential Access",
                "description": "Essai d'un mot de passe commun sur plusieurs comptes (spraying).",
                "patterns": [
                    r"\bpassword spraying\b",
                    r"\bspray\b",
                    r"\bmultiple users\b",
                    r"\bmany users\b",
                    r"\bseveral accounts\b",
                    r"\bmultiple failed logins\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "tactic": "Discovery",
                "description": "Découverte de services (scan) pour identifier des services réseau.",
                "patterns": [
                    r"\bport scan\b",
                    r"\bnmap\b",
                    r"\bmasscan\b",
                    r"\bconnect scan\b",
                    r"\bsyn scan\b",
                ],
                "severity": "medium",
            },
            {
                "id": "T1595",
                "name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": "Scan actif pour collecter des informations sur une cible.",
                "patterns": [
                    r"\bscan detected\b",
                    r"\breconnaissance\b",
                    r"\bnetwork scanning\b",
                ],
                "severity": "medium",
            },
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Tentatives d’exploitation d’application web exposée.",
                "patterns": [
                    r"\bsql injection\b",
                    r"\bxss\b",
                    r"\bdirectory traversal\b",
                    r"\bpath traversal\b",
                    r"\b\.\./\b",
                    r"(/admin\b|/wp-admin\b|/\.git\b|/config\b)",
                    r"\b(select.+from|union\s+select|drop\s+table)\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Exécution de commandes via un interpréteur.",
                "patterns": [
                    r"\bbash\b",
                    r"\bsh -c\b",
                    r"\bpowershell\b",
                    r"\bcmd\.exe\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Persistence, Privilege Escalation",
                "description": "Utilisation de comptes légitimes compromis.",
                "patterns": [
                    r"\bunusual login\b",
                    r"\babnormal access\b",
                    r"\baccount compromise\b",
                ],
                "severity": "high",
            },
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "tactic": "Impact",
                "description": "Déni de service (flood, épuisement ressources).",
                "patterns": [
                    r"\bddos\b",
                    r"\bdos\b",
                    r"\bflood(ing)?\b",
                    r"\btoo many connections\b",
                    r"\brate limit\b",
                ],
                "severity": "high",
            },
        ]

        techniques: Dict[str, MitreTechnique] = {}
        for data in mitre_data:
            t = MitreTechnique(**data)
            techniques[t.id] = t
        return techniques

    def _compile_patterns(self) -> None:
        for tid, tech in self.techniques.items():
            compiled_list: List[Tuple[re.Pattern, float, str, bool]] = []
            for p in tech.patterns:
                p_str = p.strip()
                label = p_str
                is_strong = False
                weight = 0.25

                # Brute force guessing strong
                if tid == "T1110.001":
                    if "failed password for invalid user" in p_str:
                        weight, is_strong = 0.70, True
                    elif "failed password for" in p_str:
                        weight, is_strong = 0.60, True
                    elif "authentication failure" in p_str:
                        weight, is_strong = 0.45, True
                    elif "(sshd|ssh2)" in p_str:
                        weight, is_strong = 0.35, False

                # Brute force base
                if tid == "T1110":
                    if "failed password" in p_str:
                        weight, is_strong = 0.55, True
                    elif "authentication failure" in p_str:
                        weight, is_strong = 0.45, True
                    elif "invalid user" in p_str:
                        weight, is_strong = 0.30, False

                # Spraying must be explicit multi-account
                if tid == "T1110.003":
                    if "password spraying" in p_str or "\\bspray\\b" in p_str:
                        weight, is_strong = 0.75, True
                    elif "multiple users" in p_str or "many users" in p_str or "several accounts" in p_str:
                        weight, is_strong = 0.65, True
                    elif "multiple failed logins" in p_str:
                        weight, is_strong = 0.45, False

                # Web exploit strong
                if "union\\s+select" in p_str or "drop\\s+table" in p_str or "select.+from" in p_str:
                    weight, is_strong = max(weight, 0.70), True
                if "directory traversal" in p_str or "path traversal" in p_str or "\\.\\./" in p_str:
                    weight, is_strong = max(weight, 0.65), True
                if "(/admin" in p_str or "/wp-admin" in p_str or "/\\.git" in p_str or "/config" in p_str:
                    weight, is_strong = max(weight, 0.45), False

                # Recon/scan
                if "\\bnmap\\b" in p_str or "\\bmasscan\\b" in p_str:
                    weight, is_strong = max(weight, 0.55), True
                if "\\bport scan\\b" in p_str:
                    weight, is_strong = max(weight, 0.50), True

                # DoS
                if "\\bddos\\b" in p_str or "\\bflood" in p_str:
                    weight, is_strong = max(weight, 0.55), True

                try:
                    rgx = re.compile(p_str, re.IGNORECASE)
                except re.error:
                    rgx = re.compile(re.escape(p_str), re.IGNORECASE)

                compiled_list.append((rgx, weight, label, is_strong))

            self._compiled[tid] = compiled_list

    def _event_text_bundle(self, event: Dict) -> str:
        msg = _norm_text(event.get("message", ""))
        src = _norm_text(event.get("source", ""))
        meta = event.get("metadata", {}) or {}
        extracted = meta.get("extracted_info", {}) or {}
        parts = [msg, src]
        for k in ("event_type", "protocol", "user", "path"):
            v = extracted.get(k)
            if v:
                parts.append(_norm_text(str(v)))
        sc = extracted.get("status_code")
        if sc is not None:
            parts.append(str(sc))
        return " | ".join([p for p in parts if p])

    def _score_technique(self, text: str, tid: str) -> Tuple[float, List[str], List[str], bool, int]:
        patterns = self._compiled.get(tid, [])
        if not patterns:
            return 0.0, [], [], False, 0

        matched: List[str] = []
        reasons: List[str] = []
        score_raw = 0.0
        total_possible = 0.0
        has_strong = False
        matched_count = 0

        for rgx, w, label, is_strong in patterns:
            total_possible += w
            if rgx.search(text):
                matched.append(label)
                matched_count += 1
                score_raw += w
                if is_strong:
                    has_strong = True

        if total_possible <= 0.0:
            return 0.0, matched, reasons, has_strong, matched_count

        score = score_raw / total_possible

        if matched_count >= 2:
            score += 0.08
        if matched_count >= 3:
            score += 0.07
        if has_strong:
            score += 0.05

        score = _clamp01(score)

        if matched_count > 0:
            reasons.append(f"{matched_count} pattern(s) matché(s)")
        if has_strong:
            reasons.append("indicateur fort détecté")

        return score, matched, reasons, has_strong, matched_count

    def map_event(self, event: Dict, top_k: int = 3) -> Dict[str, Any]:
        text = self._event_text_bundle(event)

        scored: List[MatchEvidence] = []
        for tid, tech in self.techniques.items():
            score, matched, reasons, has_strong, matched_count = self._score_technique(text, tid)

            # Threshold général
            passes_threshold = (
                score >= 0.42
                or matched_count >= 2
                or (has_strong and score >= 0.30)
            )

            # Gating spécifique spraying: exige indicateurs multi-account/spray
            if tid == "T1110.003":
                multi_account_hint = (
                    "multiple users" in text
                    or "many users" in text
                    or "several accounts" in text
                    or "password spraying" in text
                    or "spray" in text
                )
                if not multi_account_hint:
                    passes_threshold = False

            if not passes_threshold:
                continue

            scored.append(
                MatchEvidence(
                    technique_id=tid,
                    score=score,
                    matched=matched,
                    reasons=reasons,
                    severity=tech.severity,
                    tactic=tech.tactic,
                )
            )

        scored.sort(key=lambda e: (e.score, _severity_rank(e.severity)), reverse=True)

        best = scored[0] if scored else None
        top = scored[: max(1, int(top_k))] if scored else []

        self.last_match = best
        self.last_top = top

        if best:
            self.mapping_history.append({
                "timestamp": _now_iso(),
                "event_id": event.get("event_id", "unknown"),
                "technique_id": best.technique_id,
                "score": best.score,
                "severity": best.severity,
                "tactic": best.tactic,
                "matched": best.matched[:10],
            })

        return {
            "best": None if not best else {
                "id": best.technique_id,
                "score": best.score,
                "severity": best.severity,
                "tactic": best.tactic,
                "matched": best.matched,
                "reasons": best.reasons,
            },
            "top": [
                {
                    "id": e.technique_id,
                    "score": e.score,
                    "severity": e.severity,
                    "tactic": e.tactic,
                    "matched": e.matched,
                    "reasons": e.reasons,
                }
                for e in top
            ],
        }

    def map_to_mitre(self, event: Dict) -> Optional[MitreTechnique]:
        res = self.map_event(event, top_k=3)
        best = res.get("best")
        if not best:
            return None
        return self.techniques.get(best["id"])

    def get_last_match_details(self) -> Optional[Dict[str, Any]]:
        if not self.last_match:
            return None
        tid = self.last_match.technique_id
        tech = self.techniques.get(tid)
        if not tech:
            return None
        return {
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "severity": tech.severity,
            "description": tech.description,
            "score": self.last_match.score,
            "matched": self.last_match.matched,
            "reasons": self.last_match.reasons,
            "top": [
                {
                    "id": e.technique_id,
                    "name": self.techniques[e.technique_id].name if e.technique_id in self.techniques else e.technique_id,
                    "score": e.score,
                    "severity": e.severity,
                    "tactic": e.tactic,
                }
                for e in (self.last_top or [])
            ],
        }

    def generate_coverage_report(self) -> Dict[str, Any]:
        if not self.mapping_history:
            return {
                "total_techniques": len(self.techniques),
                "detected_techniques": 0,
                "coverage": 0.0,
                "total_detections": 0,
                "most_common": []
            }

        counts: Dict[str, int] = {}
        for m in self.mapping_history:
            tid = m["technique_id"]
            counts[tid] = counts.get(tid, 0) + 1

        most_common = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        formatted = [{
            "id": tid,
            "name": self.techniques[tid].name if tid in self.techniques else tid,
            "count": c
        } for tid, c in most_common]

        return {
            "total_techniques": len(self.techniques),
            "detected_techniques": len(counts),
            "coverage": len(counts) / max(1, len(self.techniques)),
            "total_detections": len(self.mapping_history),
            "most_common": formatted
        }


def main():
    print("=" * 60)
    print("TEST MITRE MAPPER (correctif spraying)")
    print("=" * 60)

    mapper = MitreMapper()

    test_events = [
        {"event_id": "evt_001", "message": "Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2"},
        {"event_id": "evt_spray", "message": "password spraying detected: multiple users failed logins from 10.0.0.5"},
    ]

    for ev in test_events:
        tech = mapper.map_to_mitre(ev)
        details = mapper.get_last_match_details()
        print("\n---")
        print(f"Event: {ev['event_id']} | {ev['message']}")
        if tech:
            print(f"Mapped: {tech.id} - {tech.name} [{tech.severity}]")
            print(json.dumps(details, indent=2, ensure_ascii=False))
        else:
            print("Mapped: None")


if __name__ == "__main__":
    main()
