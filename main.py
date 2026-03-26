#!/usr/bin/env python3
"""
main.py
Orchestrateur principal du SOC IA modulaire

Intègre les 4 ateliers:
- Atelier A: Trust & Calibration
- Atelier B: Distribution & Résilience
- Atelier C: Détection d'anomalies
- Atelier D: MITRE & XAI
"""

import asyncio
import json
import time
import argparse
from datetime import datetime
from typing import Dict, List

# Imports des agents core
from core.log_tailer import LogTailer
from core.collector import Collector
from core.analyzer import Analyzer
from core.lm_client import LMClient
from core.responder import Responder

# Imports Atelier A
from module_trust_calibration.trust_agent import TrustAgent

# Imports Atelier B
from module_distributed_soc.supervisor import Supervisor

# Imports Atelier C
from module_anomaly_detection.anomaly_detector import AnomalyDetector

# Imports Atelier D
from module_mitre_xai.mitre_mapper import MitreMapper
from module_mitre_xai.xai_explainer import XAIExplainer


class SOCOrchestrator:
    """
    Orchestrateur principal intégrant les 4 ateliers
    Architecture:
    log_tailer → collector → [anomaly_detector] → analyzer →
    [trust_agent] → [mitre_mapper] → [xai_explainer] → responder+ supervisor (monitoring continu)
    """
    
    def __init__(
        self,
        enable_trust: bool = True,
        enable_supervisor: bool = True,
        enable_anomaly: bool = True,
        enable_mitre: bool = True,
        enable_xai: bool = True
    ):
        """
        Args:
            enable_trust: Activer Atelier A (calibration)
            enable_supervisor: Activer Atelier B (monitoring)
            enable_anomaly: Activer Atelier C (anomalies)
            enable_mitre: Activer Atelier D (MITRE)
            enable_xai: Activer Atelier D (XAI)
        """

        
        # Core agents (toujours actifs)
        print("[INIT]  Initialisation des agents core...")
        self.log_tailer = LogTailer([
            "/var/log/auth.log",
            "/var/log/nginx/access.log"
        ])
        self.collector = Collector()
        self.lm_client = LMClient()
        self.analyzer = Analyzer(self.lm_client)
        self.responder = Responder(enable_blocking=True, enable_alerts=True)
        
        # Atelier A - Trust & Calibration
        self.enable_trust = enable_trust
        if enable_trust:
            print("[INIT]  Activation Atelier A: Trust & Calibration")
            self.trust_agent = TrustAgent(method="platt")
        else:
            self.trust_agent = None
        
        # Atelier B - Supervision & Résilience
        self.enable_supervisor = enable_supervisor
        if enable_supervisor:
            print("[INIT]  Activation Atelier B: Supervisor")
            self.supervisor = Supervisor()
        else:
            self.supervisor = None
        
        # Atelier C - Détection d'anomalies
        self.enable_anomaly = enable_anomaly
        if enable_anomaly:
            print("[INIT]  Activation Atelier C: Anomaly Detection")
            self.anomaly_detector = AnomalyDetector(threshold=0.7)
        else:
            self.anomaly_detector = None
        
        # Atelier D - MITRE & XAI
        self.enable_mitre = enable_mitre
        self.enable_xai = enable_xai
        if enable_mitre:
            print("[INIT]   Activation Atelier D: MITRE Mapper")
            self.mitre_mapper = MitreMapper()
        else:
            self.mitre_mapper = None
        
        if enable_xai:
            print("[INIT]  Activation Atelier D: XAI Explainer")
            self.xai_explainer = XAIExplainer(self.lm_client, use_llm=False)
        else:
            self.xai_explainer = None
        
        # Statistiques globales
        self.stats = {
            "events_processed": 0,
            "threats_detected": 0,
            "actions_taken": 0,
            "start_time": None,
            "end_time": None
        }
        
        print("\n[INIT]  Initialisation terminée\n")
    
    async def process_event(self, event: Dict) -> Dict:
        """
        Pipeline complet de traitement d'un événement
        
        Returns:
            Résultat complet du traitement
        """
        start_time = time.time() if self.supervisor else None
        
        try:
            # 1. COLLECTION
            event = await self.collector.process(event)
            
            # 2. DÉTECTION D'ANOMALIES (Atelier C)
            anomaly_result = None
            if self.anomaly_detector:
                anomaly_result = self.anomaly_detector.analyze(event)
                event["anomaly_score"] = anomaly_result["anomaly_score"]
            
            # 3. ANALYSE PRINCIPALE (Core + heuristiques + LLM)
            analysis = await self.analyzer.analyze(event)
            
            # Enrichissement avec score d'anomalie
            if anomaly_result:
                analysis.anomaly_score = anomaly_result["anomaly_score"]
            
            # 4. CALIBRATION DE CONFIANCE (Atelier A)
            if self.trust_agent and self.trust_agent.is_calibrated:
                original_confidence = analysis.confidence
                analysis.calibrated_confidence = self.trust_agent.adjust_confidence(
                    analysis.confidence
                )
                analysis.confidence = analysis.calibrated_confidence
            
            # 5. MAPPING MITRE (Atelier D)
            mitre_technique = None
            if self.mitre_mapper:
                mitre_technique_obj = self.mitre_mapper.map_to_mitre(event)
                if mitre_technique_obj:
                    mitre_technique = {
                        "id": mitre_technique_obj.id,
                        "name": mitre_technique_obj.name,
                        "tactic": mitre_technique_obj.tactic,
                        "description": mitre_technique_obj.description
                    }
                    analysis.mitre_technique = mitre_technique_obj.id
            
            # 6. EXPLICATION XAI (Atelier D)
            explanation = None
            if self.xai_explainer:
                # Conversion de l'analysis en dict
                analysis_dict = {
                    "event_id": analysis.event_id,
                    "threat_detected": analysis.threat_detected,
                    "confidence": analysis.confidence,
                    "calibrated_confidence": analysis.calibrated_confidence,
                    "threat_type": analysis.threat_type,
                    "recommended_action": analysis.recommended_action,
                    "heuristic_score": analysis.heuristic_score,
                    "llm_score": analysis.llm_score
                }
                
                explanation = await self.xai_explainer.explain(
                    event,
                    analysis_dict,
                    mitre_technique,
                    anomaly_result["anomaly_score"] if anomaly_result else None
                )
                analysis.explanation = explanation["summary"]
            
            # 7. ACTION (Responder)
            action = await self.responder.respond({
                "event_id": analysis.event_id,
                "ip_source": event.get("ip_source"),
                "threat_detected": analysis.threat_detected,
                "confidence": analysis.confidence,
                "threat_type": analysis.threat_type,
                "recommended_action": analysis.recommended_action
            })
            
            # 8. MÉTRIQUES (Atelier B)
            if self.supervisor:
                latency_ms = (time.time() - start_time) * 1000
                self.supervisor.record_latency(latency_ms)
            
            # Statistiques globales
            self.stats["events_processed"] += 1
            if analysis.threat_detected:
                self.stats["threats_detected"] += 1
            if action.success:
                self.stats["actions_taken"] += 1
            
            # Affichage du résultat
            self._display_result(event, analysis, mitre_technique, anomaly_result, explanation)
            
            return {
                "event": event,
                "analysis": analysis,
                "mitre_technique": mitre_technique,
                "anomaly_result": anomaly_result,
                "explanation": explanation,
                "action": action
            }
            
        except Exception as e:
            print(f"[ERROR]  Erreur traitement: {e}")
            if self.supervisor:
                self.supervisor.record_error("processing_error", str(e))
            return None
    
    def _display_result(
        self,
        event: Dict,
        analysis,
        mitre_technique: Dict,
        anomaly_result: Dict,
        explanation: Dict
    ):
        """Affiche le résultat du traitement"""
        print(f"\n{'='*70}")
        print(f" ÉVÉNEMENT: {analysis.event_id}")
        print(f"{'='*70}")
        
        print(f"\n📨 Source: {event.get('source')}")
        print(f" IP: {event.get('ip_source')}")
        print(f" Message: {event.get('message')[:80]}...")
        
        print(f"\n ANALYSE:")
        print(f"   Menace: {' OUI' if analysis.threat_detected else '🟢 NON'}")
        print(f"   Type: {analysis.threat_type or 'N/A'}")
        print(f"   Confiance: {analysis.confidence:.2%}", end="")
        if analysis.calibrated_confidence:
            print(f" (calibrée: {analysis.calibrated_confidence:.2%})")
        else:
            print()
        
        if anomaly_result:
            print(f"   Anomalie: {anomaly_result['anomaly_score']:.3f}/1.0")
        
        if mitre_technique:
            print(f"   MITRE: {mitre_technique['id']} - {mitre_technique['name']}")
        
        print(f"\n ACTION: {analysis.recommended_action.upper()}")
        
        if explanation:
            print(f"\n EXPLICATION:")
            print(f"   {explanation['summary']}")
        
        print(f"\n{'='*70}\n")
    
    async def calibrate_trust_agent(self, calibration_events: List[Dict]):
        """
        Calibre le Trust Agent (Atelier A)
        
        Args:
            calibration_events: Liste d'événements avec labels
                                Format: {event: {...}, label: True/False}
        """
        if not self.trust_agent:
            print("[CALIBRATION]   Trust Agent désactivé")
            return
        
        print("\n[CALIBRATION]  Calibration du Trust Agent...")
        
        # Extraction scores et labels
        scores = []
        labels = []
        
        for item in calibration_events:
            event = item["event"]
            label = item["label"]
            
            # Analyse pour obtenir le score
            analysis = await self.analyzer.analyze(event)
            scores.append(analysis.confidence)
            labels.append(label)
        
        # Calibration
        self.trust_agent.calibrate(scores, labels)
        
        print("[CALIBRATION]  Trust Agent calibré\n")
    
    async def train_anomaly_detector(self, training_events: List[Dict]):
        """
        Entraîne le détecteur d'anomalies (Atelier C)
        
        Args:
            training_events: Liste d'événements pour entraînement
        """
        if not self.anomaly_detector:
            print("[TRAINING]   Anomaly Detector désactivé")
            return
        
        print("\n[TRAINING]  Entraînement du détecteur d'anomalies...")
        
        self.anomaly_detector.train(training_events)
        
        print("[TRAINING]  Détecteur entraîné\n")
    
    async def run(self, duration_seconds: int = 60):
        """
        Lance le SOC pour une durée donnée
        
        Args:
            duration_seconds: Durée d'exécution (0 = infini)
        """
        print(f"\n{'='*70}")
        print(f" DÉMARRAGE DU SOC IA")
        print(f"{'='*70}")
        print(f"Durée: {duration_seconds}s" if duration_seconds > 0 else "Durée: ∞ (CTRL+C pour arrêter)")
        print(f"Modules actifs:")
        print(f"  • Core: ✓")
        print(f"  • Trust & Calibration (A): {'✓' if self.enable_trust else '✗'}")
        print(f"  • Supervision (B): {'✓' if self.enable_supervisor else '✗'}")
        print(f"  • Anomaly Detection (C): {'✓' if self.enable_anomaly else '✗'}")
        print(f"  • MITRE + XAI (D): {'✓' if self.enable_mitre and self.enable_xai else '✗'}")
        print(f"{'='*70}\n")
        
        self.stats["start_time"] = datetime.now().isoformat()
        
        start_time = time.time()
        event_count = 0
        
        try:
            async for event in self.log_tailer.start():
                await self.process_event(event)
                event_count += 1
                
                # Vérification durée
                if duration_seconds > 0 and time.time() - start_time > duration_seconds:
                    break
                
                # Délai entre événements
                await asyncio.sleep(2)
                
        except KeyboardInterrupt:
            print("\n\n[SOC]   Arrêt demandé par l'utilisateur...")
        
        finally:
            self.stats["end_time"] = datetime.now().isoformat()
            self.log_tailer.stop()
            self._print_final_report()
    
    def _print_final_report(self):
        """Affiche le rapport final"""
        print(f"\n\n{'='*70}")
        print(f" RAPPORT FINAL - SOC IA")
        print(f"{'='*70}\n")
        
        # Statistiques globales
        print(" STATISTIQUES GLOBALES:")
        print(f"   Événements traités: {self.stats['events_processed']}")
        print(f"   Menaces détectées: {self.stats['threats_detected']}")
        print(f"   Actions exécutées: {self.stats['actions_taken']}")
        print(f"   Taux de détection: {self.stats['threats_detected'] / self.stats['events_processed']:.1%}" 
              if self.stats['events_processed'] > 0 else "   Taux de détection: N/A")
        
        # Stats par module
        if self.supervisor:
            print(f"\n PERFORMANCE (Atelier B):")
            stats = self.supervisor.get_current_stats()
            print(f"   Latence moyenne: {stats['latency']['avg_ms']:.2f}ms")
            print(f"   Latence P95: {stats['latency']['p95_ms']:.2f}ms")
            print(f"   Throughput: {stats['throughput']['avg_eps']:.1f} events/sec")
        
        if self.anomaly_detector:
            print(f"\n ANOMALIES (Atelier C):")
            stats = self.anomaly_detector.get_stats()
            print(f"   Anomalies détectées: {stats['anomalies_detected']}")
            print(f"   Taux d'anomalie: {stats['anomaly_rate']:.1%}")
        
        if self.mitre_mapper:
            print(f"\n MITRE ATT&CK (Atelier D):")
            coverage = self.mitre_mapper.generate_coverage_report()
            print(f"   Techniques détectées: {coverage['detected_techniques']}/{coverage['total_techniques']}")
            print(f"   Couverture: {coverage['coverage']:.1%}")
            if coverage['most_common']:
                print(f"   Top technique: {coverage['most_common'][0]['name']} ({coverage['most_common'][0]['count']} fois)")
        
        print(f"\n{'='*70}\n")


async def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description="SOC IA Modulaire")
    parser.add_argument("--duration", type=int, default=30, help="Durée d'exécution (secondes)")
    parser.add_argument("--no-trust", action="store_true", help="Désactiver Atelier A")
    parser.add_argument("--no-supervisor", action="store_true", help="Désactiver Atelier B")
    parser.add_argument("--no-anomaly", action="store_true", help="Désactiver Atelier C")
    parser.add_argument("--no-mitre", action="store_true", help="Désactiver MITRE (Atelier D)")
    parser.add_argument("--no-xai", action="store_true", help="Désactiver XAI (Atelier D)")
    
    args = parser.parse_args()
    
    # Création de l'orchestrateur
    soc = SOCOrchestrator(
        enable_trust=not args.no_trust,
        enable_supervisor=not args.no_supervisor,
        enable_anomaly=not args.no_anomaly,
        enable_mitre=not args.no_mitre,
        enable_xai=not args.no_xai
    )
    
    # Calibration (Atelier A)
    if not args.no_trust:
        calibration_data = [
            {"event": {"message": "Failed password for admin", "ip_source": "1.1.1.1", "event_id": "cal_1"}, "label": True},
            {"event": {"message": "User login successful", "ip_source": "2.2.2.2", "event_id": "cal_2"}, "label": False},
            {"event": {"message": "nmap scan detected", "ip_source": "3.3.3.3", "event_id": "cal_3"}, "label": True},
            {"event": {"message": "Normal activity", "ip_source": "4.4.4.4", "event_id": "cal_4"}, "label": False},
        ]
        await soc.calibrate_trust_agent(calibration_data)
    
    # Entraînement anomaly detector (Atelier C)
    if not args.no_anomaly:
        training_data = [
            {"message": f"Normal log entry {i}", "ip_source": f"10.0.0.{i}", "event_id": f"train_{i}"}
            for i in range(20)
        ]
        await soc.train_anomaly_detector(training_data)
    
    # Lancement du SOC
    await soc.run(duration_seconds=args.duration)


if __name__ == "__main__":
    asyncio.run(main())
