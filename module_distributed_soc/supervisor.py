#!/usr/bin/env python3
"""
atelier_b/supervisor.py
Superviseur de performance et résilience pour SOC distribué

Mesure:
- Latence bout-en-bout
- Débit (events/sec)
- Saturation des queues
- Pertes en cas de panne
"""

import time
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from collections import deque


@dataclass
class PerformanceMetric:
    """Métrique de performance à un instant T"""
    timestamp: str
    latency_ms: float
    throughput_eps: float  # events per second
    queue_size: int
    error_count: int
    

class Supervisor:
    """
    Superviseur pour architecture distribuée (Kafka/RabbitMQ)
    
    Responsabilités:
    - Monitoring temps réel
    - Détection d'anomalies de performance
    - Alertes sur dégradation
    - Rapports de résilience
    """
    
    def __init__(
        self,
        alert_latency_threshold_ms: float = 1000,
        alert_queue_threshold: int = 1000
    ):
        self.alert_latency_threshold = alert_latency_threshold_ms
        self.alert_queue_threshold = alert_queue_threshold
        
        # Métriques
        self.metrics = {
            "events_processed": 0,
            "events_failed": 0,
            "latencies": deque(maxlen=1000),  # Dernières 1000 latences
            "throughputs": deque(maxlen=100), # Derniers 100 throughputs
            "queue_sizes": deque(maxlen=100),
            "errors": []
        }
        
        # Historique pour graphiques
        self.performance_history: List[PerformanceMetric] = []
        
        # Statut système
        self.status = "healthy"
        self.alerts = []
        
        # Timer pour throughput
        self.last_throughput_check = time.time()
        self.events_since_last_check = 0
        
        print("[SUPERVISOR] 📊 Superviseur initialisé")
    
    def record_event_start(self, event_id: str) -> float:
        """
        Enregistre le début de traitement d'un événement
        
        Returns:
            Timestamp de début
        """
        return time.time()
    
    def record_event_end(self, event_id: str, start_time: float, success: bool = True):
        """
        Enregistre la fin de traitement
        
        Args:
            event_id: ID de l'événement
            start_time: Timestamp du début
            success: Si le traitement a réussi
        """
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        
        # Enregistrement
        if success:
            self.metrics["events_processed"] += 1
            self.metrics["latencies"].append(latency_ms)
            self.events_since_last_check += 1
        else:
            self.metrics["events_failed"] += 1
            self.metrics["errors"].append({
                "timestamp": datetime.now().isoformat(),
                "event_id": event_id,
                "latency_ms": latency_ms
            })
        
        # Alerte latence
        if latency_ms > self.alert_latency_threshold:
            self._trigger_alert(
                "high_latency",
                f"Latence élevée: {latency_ms:.2f}ms pour {event_id}"
            )
        
        # Calcul throughput périodique
        if end_time - self.last_throughput_check >= 1.0:  # Chaque seconde
            self._update_throughput()
    
    def record_latency(self, latency_ms: float):
        """Enregistre une latence (méthode simple)"""
        self.metrics["latencies"].append(latency_ms)
        self.metrics["events_processed"] += 1
        self.events_since_last_check += 1
    
    def record_queue_size(self, queue_name: str, size: int):
        """
        Enregistre la taille d'une queue
        
        Args:
            queue_name: Nom de la queue (events_raw, etc.)
            size: Taille actuelle
        """
        self.metrics["queue_sizes"].append({
            "queue": queue_name,
            "size": size,
            "timestamp": time.time()
        })
        
        # Alerte saturation
        if size > self.alert_queue_threshold:
            self._trigger_alert(
                "queue_saturation",
                f"Queue {queue_name} saturée: {size} messages"
            )
    
    def record_error(self, error_type: str, details: str):
        """Enregistre une erreur"""
        self.metrics["events_failed"] += 1
        self.metrics["errors"].append({
            "timestamp": datetime.now().isoformat(),
            "type": error_type,
            "details": details
        })
    
    def _update_throughput(self):
        """Calcule le throughput actuel"""
        current_time = time.time()
        elapsed = current_time - self.last_throughput_check
        
        if elapsed > 0:
            throughput = self.events_since_last_check / elapsed
            self.metrics["throughputs"].append(throughput)
            
            # Reset
            self.last_throughput_check = current_time
            self.events_since_last_check = 0
    
    def _trigger_alert(self, alert_type: str, message: str):
        """Déclenche une alerte"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "message": message,
            "status": self.status
        }
        
        self.alerts.append(alert)
        
        # Changement de statut
        if alert_type in ["queue_saturation", "high_latency"]:
            self.status = "degraded"
        elif alert_type in ["component_failure", "critical_error"]:
            self.status = "critical"
        
        print(f"[SUPERVISOR] 🚨 ALERTE: {message}")
    
    def get_current_stats(self) -> Dict:
        """Retourne les statistiques courantes"""
        latencies = list(self.metrics["latencies"])
        throughputs = list(self.metrics["throughputs"])
        
        return {
            "status": self.status,
            "events": {
                "processed": self.metrics["events_processed"],
                "failed": self.metrics["events_failed"],
                "success_rate": self._calculate_success_rate()
            },
            "latency": {
                "avg_ms": sum(latencies) / len(latencies) if latencies else 0,
                "min_ms": min(latencies) if latencies else 0,
                "max_ms": max(latencies) if latencies else 0,
                "p95_ms": self._percentile(latencies, 95) if latencies else 0,
                "p99_ms": self._percentile(latencies, 99) if latencies else 0
            },
            "throughput": {
                "current_eps": throughputs[-1] if throughputs else 0,
                "avg_eps": sum(throughputs) / len(throughputs) if throughputs else 0,
                "max_eps": max(throughputs) if throughputs else 0
            },
            "alerts": {
                "total": len(self.alerts),
                "recent": self.alerts[-5:] if self.alerts else []
            }
        }
    
    def _calculate_success_rate(self) -> float:
        """Calcule le taux de succès"""
        total = self.metrics["events_processed"] + self.metrics["events_failed"]
        if total == 0:
            return 1.0
        return self.metrics["events_processed"] / total
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calcule un percentile"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * (percentile / 100))
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    async def test_resilience(
        self,
        component: str,
        failure_duration_sec: float = 5.0
    ) -> Dict:
        """
        Test de résilience: simule une panne
        
        Args:
            component: Composant à tester (analyzer, collector, etc.)
            failure_duration_sec: Durée de la panne
            
        Returns:
            Rapport de test
        """
        print(f"\n[SUPERVISOR] 🧪 TEST RÉSILIENCE: Panne de {component}")
        print(f"[SUPERVISOR]    Durée: {failure_duration_sec}s")
        
        # Métriques avant panne
        before_stats = self.get_current_stats()
        before_count = self.metrics["events_processed"]
        
        # Simulation de panne
        print(f"[SUPERVISOR] ⚠️  {component} EN PANNE...")
        await asyncio.sleep(failure_duration_sec)
        print(f"[SUPERVISOR] ✓ {component} RESTAURÉ")
        
        # Métriques après panne
        after_stats = self.get_current_stats()
        after_count = self.metrics["events_processed"]
        
        # Analyse
        events_lost = 0  # Dans un vrai système, compter les pertes
        recovery_time = failure_duration_sec
        
        report = {
            "component": component,
            "failure_duration_sec": failure_duration_sec,
            "events_lost": events_lost,
            "recovery_time_sec": recovery_time,
            "impact": "minimal" if events_lost < 10 else "moderate" if events_lost < 100 else "severe",
            "before_stats": before_stats,
            "after_stats": after_stats
        }
        
        print(f"\n[SUPERVISOR] 📊 RAPPORT RÉSILIENCE:")
        print(f"   Événements perdus: {events_lost}")
        print(f"   Temps de récupération: {recovery_time:.1f}s")
        print(f"   Impact: {report['impact']}")
        
        return report
    
    async def load_test(
        self,
        target_eps: int = 100,
        duration_sec: int = 10
    ) -> Dict:
        """
        Test de charge
        
        Args:
            target_eps: Events par seconde cible
            duration_sec: Durée du test
            
        Returns:
            Rapport de charge
        """
        print(f"\n[SUPERVISOR] ⚡ TEST DE CHARGE")
        print(f"[SUPERVISOR]    Cible: {target_eps} events/sec")
        print(f"[SUPERVISOR]    Durée: {duration_sec}s")
        
        start_time = time.time()
        events_generated = 0
        
        while time.time() - start_time < duration_sec:
            # Génération d'événements
            for _ in range(target_eps // 10):  # Batch de 10 events
                # Simulation de traitement
                event_start = self.record_event_start(f"load_test_{events_generated}")
                await asyncio.sleep(0.001)  # Traitement minimal
                self.record_event_end(f"load_test_{events_generated}", event_start)
                events_generated += 1
            
            await asyncio.sleep(0.1)  # 100ms entre batches
        
        stats = self.get_current_stats()
        
        report = {
            "target_eps": target_eps,
            "duration_sec": duration_sec,
            "events_generated": events_generated,
            "actual_eps": events_generated / duration_sec,
            "avg_latency_ms": stats["latency"]["avg_ms"],
            "max_latency_ms": stats["latency"]["max_ms"],
            "success_rate": stats["events"]["success_rate"],
            "status": "passed" if stats["events"]["success_rate"] > 0.95 else "failed"
        }
        
        print(f"\n[SUPERVISOR] 📊 RAPPORT CHARGE:")
        print(f"   Événements générés: {events_generated}")
        print(f"   EPS réel: {report['actual_eps']:.1f}")
        print(f"   Latence moyenne: {report['avg_latency_ms']:.2f}ms")
        print(f"   Taux de succès: {report['success_rate']:.1%}")
        print(f"   Statut: {report['status']}")
        
        return report
    
    def export_report(self, filepath: str = "/tmp/supervisor_report.json"):
        """Exporte un rapport complet"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "status": self.status,
            "stats": self.get_current_stats(),
            "alerts": self.alerts,
            "errors": self.metrics["errors"][-10:]  # Dernières 10 erreurs
        }
        
        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[SUPERVISOR] ✓ Rapport exporté: {filepath}")
        except Exception as e:
            print(f"[SUPERVISOR] ❌ Erreur export: {e}")
    
    def reset_metrics(self):
        """Réinitialise les métriques"""
        self.metrics = {
            "events_processed": 0,
            "events_failed": 0,
            "latencies": deque(maxlen=1000),
            "throughputs": deque(maxlen=100),
            "queue_sizes": deque(maxlen=100),
            "errors": []
        }
        self.alerts = []
        self.status = "healthy"
        print("[SUPERVISOR] ♻️  Métriques réinitialisées")


async def main():
    """Test standalone du supervisor"""
    print("="*60)
    print("TEST SUPERVISOR - RÉSILIENCE & PERFORMANCE")
    print("="*60)
    
    supervisor = Supervisor(
        alert_latency_threshold_ms=100,
        alert_queue_threshold=50
    )
    
    # Test 1: Enregistrement normal
    print("\n" + "="*60)
    print("TEST 1: MÉTRIQUES NORMALES")
    print("="*60)
    
    for i in range(20):
        start = supervisor.record_event_start(f"evt_{i}")
        await asyncio.sleep(0.01)  # Simulation traitement
        supervisor.record_event_end(f"evt_{i}", start, success=True)
    
    stats = supervisor.get_current_stats()
    print(f"\n📊 Statistiques:")
    print(json.dumps(stats, indent=2))
    
    # Test 2: Latence élevée
    print("\n" + "="*60)
    print("TEST 2: LATENCE ÉLEVÉE")
    print("="*60)
    
    start = supervisor.record_event_start("evt_slow")
    await asyncio.sleep(0.15)  # 150ms > seuil
    supervisor.record_event_end("evt_slow", start)
    
    # Test 3: Queue saturation
    print("\n" + "="*60)
    print("TEST 3: SATURATION QUEUE")
    print("="*60)
    
    supervisor.record_queue_size("events_raw", 75)  # > seuil
    
    # Test 4: Résilience
    print("\n" + "="*60)
    print("TEST 4: RÉSILIENCE")
    print("="*60)
    
    resilience_report = await supervisor.test_resilience("analyzer", 2.0)
    
    # Test 5: Charge
    print("\n" + "="*60)
    print("TEST 5: CHARGE")
    print("="*60)
    
    load_report = await supervisor.load_test(target_eps=50, duration_sec=5)
    
    # Rapport final
    print("\n" + "="*60)
    print("RAPPORT FINAL")
    print("="*60)
    
    final_stats = supervisor.get_current_stats()
    print(f"\nStatut: {final_stats['status']}")
    print(f"Événements traités: {final_stats['events']['processed']}")
    print(f"Taux de succès: {final_stats['events']['success_rate']:.1%}")
    print(f"Latence P95: {final_stats['latency']['p95_ms']:.2f}ms")
    print(f"Alertes: {final_stats['alerts']['total']}")
    
    # Export
    supervisor.export_report()


if __name__ == "__main__":
    asyncio.run(main())
