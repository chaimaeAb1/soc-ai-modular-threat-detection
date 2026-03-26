#!/usr/bin/env python3
"""
atelier_d/xai_explainer.py
Module d'explicabilité (XAI - Explainable AI)

Améliorations:
✅ Preuves MITRE lisibles (nettoyage regex \b, \\, etc.)
✅ Supporte un mitre_technique enrichi avec {id,name,tactic,severity,score,matched}
✅ Explication détaillée plus "rapport SOC" (actionnable, traçable)
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Any
from datetime import datetime


class XAIExplainer:
    def __init__(self, lm_client=None, use_llm: bool = True):
        self.lm_client = lm_client
        self.use_llm = use_llm
        self.explanation_history: List[Dict[str, Any]] = []
        self.templates = self._load_templates()
        print(f"[XAI_EXPLAINER] 💡 Initialisation (mode: {'LLM' if use_llm else 'Template'})")

    # -----------------------------
    # Templates
    # -----------------------------
    def _load_templates(self) -> Dict[str, Any]:
        return {
            "summary": {
                "confirmed": "Menace confirmée ({threat_type}) — Action: {action}",
                "potential": "Menace potentielle ({threat_type}) — Action: {action}",
                "suspect": "Comportement suspect ({threat_type}) — Action: {action}",
                "normal": "Événement normal — aucune action requise",
            },
            "anomaly": {
                "high": "Score d'anomalie élevé ({score:.2f}/1.0): comportement très inhabituel.",
                "medium": "Score d'anomalie modéré ({score:.2f}/1.0): déviations partielles.",
                "low": "Score d'anomalie faible ({score:.2f}/1.0): proche du comportement normal.",
            },
        }

    # -----------------------------
    # Utils (clean proofs)
    # -----------------------------
    def _clean_regex_pattern(self, p: str) -> str:
        """
        Transforme une regex de détection en "preuve" lisible.
        Ex:
          \\bfailed password for\\b -> failed password for
          (/admin\\b|/wp-admin\\b|/\\.git\\b|/config\\b) -> /admin | /wp-admin | /.git | /config
        """
        if not p:
            return ""

        s = str(p)

        # enlever bornes word boundary
        s = s.replace(r"\b", "")
        # enlever escapes inutiles
        s = s.replace(r"\/", "/")
        s = s.replace(r"\.", ".")
        s = s.replace(r"\\", "\\")  # normalise double backslashes
        # enlever parenthèses d'alternatives (a|b|c)
        # si pattern est "(...|...|...)" => on split
        alt = None
        m = re.fullmatch(r"\((.+)\)", s.strip())
        if m and "|" in m.group(1):
            alt = m.group(1)

        if alt:
            parts = [x.strip() for x in alt.split("|")]
            parts = [re.sub(r"\\+", "", x) for x in parts]
            parts = [x.replace("^", "").replace("$", "") for x in parts]
            parts = [re.sub(r"\s+", " ", x).strip() for x in parts if x.strip()]
            return " | ".join(parts)

        # enlever ancres ^ $
        s = s.replace("^", "").replace("$", "")

        # retirer certains tokens regex fréquents
        s = re.sub(r"\(\?:", "(", s)
        s = re.sub(r"\(\?i\)", "", s)
        s = re.sub(r"\s+", " ", s).strip()

        # si ça reste trop “regex”, on simplifie encore
        s = s.replace(r"(sshd|ssh2)", "sshd | ssh2")
        s = s.replace(r"(ing)?", "ing?")

        return s.strip()

    def _format_mitre_proofs(self, mitre_technique: Optional[Dict[str, Any]]) -> str:
        if not mitre_technique:
            return ""

        matched = mitre_technique.get("matched") or []
        if not matched:
            return ""

        cleaned = []
        for p in matched:
            c = self._clean_regex_pattern(p)
            if c and c not in cleaned:
                cleaned.append(c)

        if not cleaned:
            return ""

        # limiter pour éviter pavés
        cleaned = cleaned[:6]
        return ", ".join(cleaned)

    def _confidence_label(self, conf: float) -> str:
        if conf >= 0.8:
            return "confirmed"
        if conf >= 0.5:
            return "potential"
        return "suspect"

    # -----------------------------
    # Main API
    # -----------------------------
    async def explain(
        self,
        event: Dict[str, Any],
        analysis: Dict[str, Any],
        mitre_technique: Optional[Dict[str, Any]] = None,
        anomaly_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        explanation: Dict[str, Any] = {
            "event_id": event.get("event_id", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "summary": "",
            "detailed_explanation": "",
            "decision_factors": [],
            "recommended_next_steps": [],
            "confidence_explanation": "",
            "risk_assessment": "",
        }

        explanation["summary"] = self._generate_summary(analysis)
        explanation["detailed_explanation"] = self._template_explain(event, analysis, mitre_technique, anomaly_score)
        explanation["decision_factors"] = self._extract_decision_factors(analysis, mitre_technique, anomaly_score)
        explanation["recommended_next_steps"] = self._recommend_next_steps(analysis)
        explanation["confidence_explanation"] = self._explain_confidence(analysis)
        explanation["risk_assessment"] = self._assess_risk(analysis, anomaly_score)

        self.explanation_history.append(explanation)
        return explanation

    # -----------------------------
    # Builders
    # -----------------------------
    def _generate_summary(self, analysis: Dict[str, Any]) -> str:
        threat = bool(analysis.get("threat_detected", False))
        conf = float(analysis.get("confidence", 0.0) or 0.0)
        action = str(analysis.get("recommended_action", "monitor")).upper()
        threat_type = analysis.get("threat_type", "unknown")

        if not threat:
            return self.templates["summary"]["normal"]

        key = self._confidence_label(conf)
        return self.templates["summary"][key].format(threat_type=threat_type, action=action)

    def _template_explain(
        self,
        event: Dict[str, Any],
        analysis: Dict[str, Any],
        mitre_technique: Optional[Dict[str, Any]],
        anomaly_score: Optional[float],
    ) -> str:
        parts: List[str] = []

        threat = bool(analysis.get("threat_detected", False))
        conf = float(analysis.get("confidence", 0.0) or 0.0)
        threat_type = analysis.get("threat_type", "unknown")
        action = str(analysis.get("recommended_action", "monitor")).upper()

        ip = event.get("ip_source", "unknown")
        src = event.get("source", "unknown")

        # 1) Threat
        if threat:
            parts.append(f"Menace détectée ({threat_type}) avec confiance {conf:.0%}.")
        else:
            parts.append("Aucune menace détectée (événement considéré normal).")

        # 2) MITRE mapping
        if mitre_technique:
            mid = mitre_technique.get("id", "N/A")
            mname = mitre_technique.get("name", "N/A")
            tactic = mitre_technique.get("tactic", "N/A")
            sev = mitre_technique.get("severity", "N/A")
            mscore = mitre_technique.get("score", None)

            if mscore is not None:
                parts.append(f"Mapping MITRE: {mid} ({mname}) | Tactique: {tactic} | Sévérité: {sev} | Score: {float(mscore):.2f}.")
            else:
                parts.append(f"Mapping MITRE: {mid} ({mname}) | Tactique: {tactic} | Sévérité: {sev}.")

            proofs = self._format_mitre_proofs(mitre_technique)
            if proofs:
                parts.append(f"Preuves MITRE: {proofs}.")

        # 3) Anomaly
        if anomaly_score is not None:
            s = float(anomaly_score)
            if s >= 0.7:
                parts.append(self.templates["anomaly"]["high"].format(score=s))
            elif s >= 0.4:
                parts.append(self.templates["anomaly"]["medium"].format(score=s))
            else:
                parts.append(self.templates["anomaly"]["low"].format(score=s))

        # 4) Action justification (courte et utile)
        reason = self._get_action_reason(analysis)
        parts.append(f"Action: {action} — {reason}.")

        # 5) Context minimal
        parts.append(f"Contexte: source={src}, ip={ip}.")

        return " ".join(parts)

    def _get_action_reason(self, analysis: Dict[str, Any]) -> str:
        action = str(analysis.get("recommended_action", "monitor")).lower()
        conf = float(analysis.get("confidence", 0.0) or 0.0)
        threat_type = analysis.get("threat_type", "menace")

        if action == "block":
            return f"risque immédiat (confiance {conf:.0%}) / indicateurs forts ({threat_type})"
        if action == "alert":
            return f"validation humaine recommandée (confiance {conf:.0%})"
        if action == "monitor":
            return f"incertitude (confiance {conf:.0%}) — surveillance requise"
        if action == "ignore":
            return "aucun indicateur significatif"
        return "décision par défaut"

    def _extract_decision_factors(
        self,
        analysis: Dict[str, Any],
        mitre_technique: Optional[Dict[str, Any]],
        anomaly_score: Optional[float],
    ) -> List[Dict[str, Any]]:
        factors: List[Dict[str, Any]] = []

        if "heuristic_score" in analysis:
            factors.append({
                "factor": "Heuristique",
                "value": analysis.get("heuristic_score"),
                "weight": 0.4,
                "description": "Règles / patterns de détection",
            })

        if "llm_score" in analysis:
            factors.append({
                "factor": "LLM",
                "value": analysis.get("llm_score"),
                "weight": 0.4,
                "description": "Analyse du modèle de langage (si actif)",
            })

        if anomaly_score is not None:
            factors.append({
                "factor": "Anomalie",
                "value": float(anomaly_score),
                "weight": 0.2,
                "description": "Déviation par rapport au comportement normal",
            })

        if mitre_technique:
            factors.append({
                "factor": "MITRE",
                "value": mitre_technique.get("id"),
                "weight": "N/A",
                "description": f"{mitre_technique.get('name')} | {mitre_technique.get('tactic')} | sev={mitre_technique.get('severity')}"
                               + (f" | score={float(mitre_technique.get('score')):.2f}" if mitre_technique.get("score") is not None else ""),
            })

            proofs = self._format_mitre_proofs(mitre_technique)
            if proofs:
                factors.append({
                    "factor": "Preuves MITRE",
                    "value": proofs,
                    "weight": "N/A",
                    "description": "Patterns ayant déclenché le mapping (format lisible)",
                })

        return factors

    def _recommend_next_steps(self, analysis: Dict[str, Any]) -> List[str]:
        action = str(analysis.get("recommended_action", "monitor")).lower()

        if action == "block":
            return [
                "Vérifier la règle firewall (UFW/iptables) et confirmer le blocage",
                "Rechercher d'autres événements liés à la même IP (corrélation)",
                "Identifier le compte ciblé (si SSH) et vérifier les tentatives",
                "Documenter l'incident (horodatage, preuves, action)",
            ]
        if action == "alert":
            return [
                "Analyser l'historique de l'IP source",
                "Corréler avec d'autres événements similaires",
                "Décider si un blocage est nécessaire",
            ]
        if action == "monitor":
            return [
                "Surveiller l'IP et le pattern pendant 24–48h",
                "Augmenter le niveau si répétition / escalade",
                "Ajouter des règles si faux positifs fréquents",
            ]
        return ["Aucune action requise"]

    def _explain_confidence(self, analysis: Dict[str, Any]) -> str:
        conf = float(analysis.get("confidence", 0.0) or 0.0)
        cal = analysis.get("calibrated_confidence", None)
        if cal is not None:
            try:
                cal = float(cal)
                return f"Confiance brute: {conf:.0%} | Confiance calibrée: {cal:.0%} (Atelier A)."
            except Exception:
                pass
        return f"Confiance estimée: {conf:.0%}."

    def _assess_risk(self, analysis: Dict[str, Any], anomaly_score: Optional[float]) -> str:
        threat = bool(analysis.get("threat_detected", False))
        conf = float(analysis.get("confidence", 0.0) or 0.0)

        if not threat:
            return "Risque: FAIBLE — aucun indicateur de menace."

        risk = conf
        if anomaly_score is not None and float(anomaly_score) > 0.7:
            risk += 0.1

        if risk >= 0.8:
            return "Risque: CRITIQUE — action immédiate."
        if risk >= 0.6:
            return "Risque: ÉLEVÉ — traitement prioritaire."
        if risk >= 0.4:
            return "Risque: MOYEN — surveillance accrue."
        return "Risque: FAIBLE — surveillance standard."

    # -----------------------------
    # Human report
    # -----------------------------
    def generate_human_report(self, explanation: Dict[str, Any]) -> str:
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║              RAPPORT D'EXPLICATION - SOC IA                  ║
╚══════════════════════════════════════════════════════════════╝

📋 Événement: {explanation['event_id']}
🕐 Timestamp: {explanation['timestamp']}

═══════════════════════════════════════════════════════════════

📊 RÉSUMÉ:
{explanation['summary']}

═══════════════════════════════════════════════════════════════

📝 EXPLICATION DÉTAILLÉE:
{explanation['detailed_explanation']}

═══════════════════════════════════════════════════════════════

🎯 FACTEURS DE DÉCISION:
"""
        for i, factor in enumerate(explanation.get("decision_factors", []), 1):
            report += f"\n{i}. {factor.get('factor')}"
            report += f"\n   Valeur: {factor.get('value')}"
            report += f"\n   Poids: {factor.get('weight')}"
            report += f"\n   {factor.get('description')}\n"

        report += f"""
═══════════════════════════════════════════════════════════════

💡 CONFIANCE:
{explanation['confidence_explanation']}

⚠️  ÉVALUATION DU RISQUE:
{explanation['risk_assessment']}

═══════════════════════════════════════════════════════════════

✅ PROCHAINES ÉTAPES RECOMMANDÉES:
"""
        for i, step in enumerate(explanation.get("recommended_next_steps", []), 1):
            report += f"\n{i}. {step}"

        report += "\n\n═══════════════════════════════════════════════════════════════\n"
        return report


# -----------------------------
# Standalone test
# -----------------------------
async def main():
    explainer = XAIExplainer(use_llm=False)

    event = {
        "event_id": "evt_123",
        "message": "Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2",
        "ip_source": "192.168.1.100",
        "source": "/var/log/auth.log",
        "severity": "high",
    }

    analysis = {
        "threat_detected": True,
        "confidence": 0.92,
        "calibrated_confidence": 0.88,
        "threat_type": "ssh_bruteforce",
        "recommended_action": "block",
        "heuristic_score": 0.9,
        "llm_score": 0.0,
    }

    # mitre_technique enrichie (comme ton nouveau mapper peut fournir)
    mitre_technique = {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "severity": "high",
        "score": 0.86,
        "matched": [r"\bfailed password for\b", r"\binvalid user\b", r"\b(sshd|ssh2)\b"],
    }

    anomaly_score = 0.82

    explanation = await explainer.explain(event, analysis, mitre_technique, anomaly_score)
    print(explainer.generate_human_report(explanation))


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
