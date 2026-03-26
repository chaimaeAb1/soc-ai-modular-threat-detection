#!/usr/bin/env python3
"""
core/analyzer.py
Agent d'analyse fusionnant heuristiques + IA

Améliorations:
✅ Support optionnel "mitre_match" dans event.metadata:
   - augmente la confiance selon sévérité/score MITRE
   - peut escalader action (monitor -> alert -> block) si indicateurs forts
"""

import json
import time
from datetime import datetime
from typing import Dict, Optional
from dataclasses import dataclass, asdict


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _severity_rank(sev: str) -> int:
    sev = (sev or "").lower()
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 1)


def _escalate_action(current: str, target: str) -> str:
    order = ["ignore", "monitor", "alert", "block"]
    try:
        c = order.index(current)
    except ValueError:
        c = 1
    try:
        t = order.index(target)
    except ValueError:
        t = 1
    return order[max(c, t)]


@dataclass
class AnalysisResult:
    event_id: str
    timestamp: str
    threat_detected: bool
    confidence: float
    threat_type: Optional[str] = None
    threat_level: str = "low"
    recommended_action: str = "monitor"
    heuristic_score: float = 0.0
    llm_score: float = 0.0
    reasoning: str = ""

    calibrated_confidence: Optional[float] = None  # Atelier A
    anomaly_score: Optional[float] = None          # Atelier C
    mitre_technique: Optional[str] = None          # Atelier D
    explanation: Optional[str] = None              # Atelier D

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)


class Analyzer:
    def __init__(self, lm_client=None):
        self.lm_client = lm_client
        self.rules = self._load_detection_rules()
        self.analysis_count = 0
        self.threat_history = []

    def _load_detection_rules(self) -> Dict:
        return {
            "ssh_bruteforce": {
                "patterns": ["failed password", "authentication failure", "invalid user"],
                "severity": "high",
                "action": "block",
                "confidence": 0.9,
                "description": "Tentative de brute force SSH détectée"
            },
            "port_scan": {
                "patterns": ["port scan", "nmap", "scanning", "syn flood"],
                "severity": "medium",
                "action": "alert",
                "confidence": 0.85,
                "description": "Scan de ports réseau détecté"
            },
            "web_fuzzing": {
                "patterns": ["gobuster", "dirbuster", "/admin", "/wp-admin", "/.git"],
                "severity": "medium",
                "action": "monitor",
                "confidence": 0.75,
                "description": "Énumération web (fuzzing) détectée"
            },
            "sql_injection": {
                "patterns": ["' or '1'='1", "union select", "drop table", "' or 1=1"],
                "severity": "critical",
                "action": "block",
                "confidence": 0.95,
                "description": "Tentative d'injection SQL"
            },
            "xss_attack": {
                "patterns": ["<script>", "javascript:", "onerror=", "<img src=x"],
                "severity": "high",
                "action": "block",
                "confidence": 0.9,
                "description": "Tentative de XSS détectée"
            }
        }

    async def analyze(self, event: dict) -> AnalysisResult:
        self.analysis_count += 1
        print(f"\n[ANALYZER] 🔬 Analyse #{self.analysis_count}")

        heuristic_result = self._heuristic_analysis(event)
        print(f"[ANALYZER]   → Heuristique: score={heuristic_result['score']:.2f}")

        llm_result = {"score": 0.0, "threat_type": None, "action": "monitor"}
        if self.lm_client:
            llm_result = await self._llm_analysis(event)
            print(f"[ANALYZER]   → LLM: score={llm_result['score']:.2f}")

        final_result = self._fusion_decision(event, heuristic_result, llm_result)

        analysis = AnalysisResult(
            event_id=event.get("event_id", f"evt_{int(time.time())}"),
            timestamp=datetime.now().isoformat(),
            threat_detected=final_result["threat_detected"],
            confidence=final_result["confidence"],
            threat_type=final_result["threat_type"],
            threat_level=final_result["threat_level"],
            recommended_action=final_result["action"],
            heuristic_score=heuristic_result["score"],
            llm_score=llm_result["score"],
            reasoning=final_result["reasoning"]
        )

        self.threat_history.append({
            "timestamp": analysis.timestamp,
            "threat_detected": analysis.threat_detected,
            "confidence": analysis.confidence
        })

        print(f"[ANALYZER] ✓ Décision: {analysis.recommended_action.upper()} (confiance: {analysis.confidence:.2f})")
        return analysis

    def _heuristic_analysis(self, event: dict) -> Dict:
        message = (event.get("message", "") or "").lower()
        max_score = 0.0
        matched_rule = None

        for rule_name, rule in self.rules.items():
            for pattern in rule["patterns"]:
                if pattern.lower() in message:
                    score = rule["confidence"]
                    if score > max_score:
                        max_score = score
                        matched_rule = rule_name

        if matched_rule:
            rule = self.rules[matched_rule]
            return {
                "score": max_score,
                "threat_detected": True,
                "rule": matched_rule,
                "severity": rule["severity"],
                "action": rule["action"],
                "description": rule["description"]
            }

        return {
            "score": 0.1,
            "threat_detected": False,
            "rule": None,
            "severity": "low",
            "action": "monitor",
            "description": "Aucune règle correspondante"
        }

    async def _llm_analysis(self, event: dict) -> Dict:
        if not self.lm_client:
            return {"score": 0.0, "threat_type": None, "action": "monitor"}

        try:
            result = await self.lm_client.analyze(event)
            return {
                "score": result.get("confidence", 0.0),
                "threat_type": result.get("threat_type"),
                "action": result.get("recommended_action", "monitor")
            }
        except Exception as e:
            print(f"[ANALYZER] ⚠️  Erreur LLM: {e}")
            return {"score": 0.0, "threat_type": None, "action": "monitor"}

    def _mitre_signal_from_event(self, event: dict) -> Optional[dict]:
        """
        Attend event["metadata"]["mitre_match"] = {
          "id","name","severity","score","matched","tactic"
        }
        """
        meta = event.get("metadata") or {}
        mm = meta.get("mitre_match")
        if isinstance(mm, dict) and mm.get("id"):
            return mm
        return None

    def _fusion_decision(self, event: dict, heuristic: Dict, llm: Dict) -> Dict:
        heuristic_score = float(heuristic["score"])
        llm_score = float(llm["score"])

        if heuristic_score >= llm_score:
            final_confidence = heuristic_score
            final_action = heuristic["action"]
            final_threat_type = heuristic.get("rule")
            reasoning = f"Règle heuristique: {heuristic.get('description', 'N/A')}"
        else:
            final_confidence = llm_score
            final_action = llm["action"]
            final_threat_type = llm.get("threat_type")
            reasoning = "Décision IA via LLM"

        # ---- Atelier D (optionnel) : boost via MITRE si présent dans event.metadata
        mitre = self._mitre_signal_from_event(event)
        if mitre:
            sev = (mitre.get("severity") or "low").lower()
            mscore = float(mitre.get("score", 0.0) or 0.0)
            matched = mitre.get("matched") or []
            matched_count = len(matched) if isinstance(matched, list) else 0

            # boost confidence selon severité + score
            boost = 0.0
            if sev == "critical":
                boost += 0.12
            elif sev == "high":
                boost += 0.08
            elif sev == "medium":
                boost += 0.04

            # bonus si mapping solide
            if mscore >= 0.75:
                boost += 0.06
            elif mscore >= 0.55:
                boost += 0.03

            if matched_count >= 2:
                boost += 0.03

            final_confidence = _clamp01(final_confidence + boost)
            reasoning += f" | MITRE boost: id={mitre.get('id')} sev={sev} score={mscore:.2f} (+{boost:.2f})"

            # escalade action si indicateurs forts
            # - si critical/high + score solide => au minimum ALERT
            # - si critical/high + très solide => BLOCK
            if _severity_rank(sev) >= 3 and mscore >= 0.55:
                final_action = _escalate_action(final_action, "alert")
            if _severity_rank(sev) >= 3 and mscore >= 0.75 and matched_count >= 2:
                final_action = _escalate_action(final_action, "block")

        # threat level
        if final_confidence >= 0.9:
            threat_level = "critical"
        elif final_confidence >= 0.7:
            threat_level = "high"
        elif final_confidence >= 0.5:
            threat_level = "medium"
        else:
            threat_level = "low"

        return {
            "threat_detected": final_confidence >= 0.5,
            "confidence": final_confidence,
            "threat_type": final_threat_type,
            "threat_level": threat_level,
            "action": final_action,
            "reasoning": reasoning
        }

    def get_stats(self) -> Dict:
        threats_detected = sum(1 for h in self.threat_history if h["threat_detected"])
        return {
            "total_analyzed": self.analysis_count,
            "threats_detected": threats_detected,
            "detection_rate": threats_detected / self.analysis_count if self.analysis_count > 0 else 0,
            "avg_confidence": sum(h["confidence"] for h in self.threat_history) / len(self.threat_history) if self.threat_history else 0
        }
