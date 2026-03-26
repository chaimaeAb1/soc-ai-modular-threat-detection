#!/usr/bin/env python3
"""
atelier_c/anomaly_detector.py
Détection d'anomalies non supervisée (Isolation Forest + One-Class SVM)

Objectif: Détecter des menaces inconnues (zero-day) sans labels
"""

import json
import numpy as np
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from collections import Counter


class AnomalyDetector:
    """
    Détecteur d'anomalies basé sur Isolation Forest
    
    Principe: Les anomalies sont "faciles à isoler" dans l'arbre
    - Point normal: beaucoup de splits pour l'isoler
    - Point anormal: peu de splits pour l'isoler
    
    Score d'anomalie ∈ [0, 1]:
    - 0.0-0.4: Normal
    - 0.4-0.6: Suspect
    - 0.6-0.8: Anormal
    - 0.8-1.0: Très anormal
    """
    
    def __init__(
        self,
        threshold: float = 0.7,
        contamination: float = 0.1,
        n_trees: int = 100
    ):
        """
        Args:
            threshold: Seuil de détection (0-1)
            contamination: Proportion estimée d'anomalies
            n_trees: Nombre d'arbres dans la forêt
        """
        self.threshold = threshold
        self.contamination = contamination
        self.n_trees = n_trees
        
        # Modèle (simulation - en production: sklearn)
        self.model_trained = False
        self.feature_stats = None  # Statistiques pour normalisation
        
        # Historique
        self.detection_history = []
        self.feature_importance = {}
        
        print(f"[ANOMALY_DETECTOR] 🌳 Initialisation (seuil: {threshold})")
    
    def extract_features(self, event: Dict) -> np.ndarray:
        """
        Extrait les features numériques d'un événement
        
        Features extraites:
        1. Longueur du message
        2. Nombre de mots-clés suspects
        3. Fréquence IP (hash)
        4. Sévérité numér

ique
        5. Heure du jour (cyclique)
        6. Nombre de tentatives (contexte)
        """
        message = event.get("message", "")
        ip_source = event.get("ip_source", "unknown")
        severity = event.get("severity", "low")
        timestamp = event.get("timestamp", datetime.now().isoformat())
        
        # Feature 1: Longueur message
        f1 = len(message)
        
        # Feature 2: Mots-clés suspects
        suspicious_keywords = [
            "failed", "error", "denied", "refused", "invalid",
            "unauthorized", "forbidden", "attack", "breach"
        ]
        f2 = sum(1 for kw in suspicious_keywords if kw in message.lower())
        
        # Feature 3: Hash IP (pour détecter IPs récurrentes)
        f3 = hash(ip_source) % 1000 / 1000.0
        
        # Feature 4: Sévérité numérique
        severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        f4 = severity_map.get(severity, 0.25)
        
        # Feature 5: Heure du jour (cyclique sin/cos)
        try:
            hour = datetime.fromisoformat(timestamp).hour
            f5 = np.sin(2 * np.pi * hour / 24)
            f6 = np.cos(2 * np.pi * hour / 24)
        except:
            f5, f6 = 0.0, 1.0
        
        # Feature 7: Codes HTTP (si présent)
        f7 = 0.0
        if "404" in message or "403" in message:
            f7 = 0.8
        elif "500" in message or "503" in message:
            f7 = 1.0
        elif "200" in message:
            f7 = 0.1
        
        # Feature 8: Patterns d'attaque
        attack_patterns = ["nmap", "scan", "brute", "inject", "exploit"]
        f8 = sum(0.2 for pat in attack_patterns if pat in message.lower())
        
        features = np.array([f1, f2, f3, f4, f5, f6, f7, f8])
        
        return features
    
    def train(self, events: List[Dict]):
        """
        Entraîne le modèle sur un dataset (non supervisé)
        
        Args:
            events: Liste d'événements pour entraînement
        """
        print(f"\n[ANOMALY_DETECTOR] 🎓 Entraînement sur {len(events)} événements")
        
        if len(events) < 10:
            print("[ANOMALY_DETECTOR] ⚠️  Dataset trop petit (<10 événements)")
            return
        
        # Extraction des features
        X = np.array([self.extract_features(e) for e in events])
        
        # Calcul des statistiques (pour normalisation)
        self.feature_stats = {
            "mean": np.mean(X, axis=0),
            "std": np.std(X, axis=0) + 1e-6  # Éviter division par 0
        }
        
        # Simulation d'Isolation Forest
        # En production: from sklearn.ensemble import IsolationForest
        # self.model = IsolationForest(contamination=self.contamination, n_estimators=self.n_trees)
        # self.model.fit(X)
        
        self.model_trained = True
        
        print(f"[ANOMALY_DETECTOR] ✓ Modèle entraîné")
        print(f"[ANOMALY_DETECTOR]    Features: {X.shape[1]}")
        print(f"[ANOMALY_DETECTOR]    Contamination: {self.contamination:.1%}")
    
    def compute_anomaly_score(self, event: Dict) -> float:
        """
        Calcule le score d'anomalie pour un événement
        
        Returns:
            Score ∈ [0, 1] (1 = très anormal)
        """
        # Extraction features
        features = self.extract_features(event)
        
        if not self.model_trained or self.feature_stats is None:
            # Mode heuristique simple sans entraînement
            return self._heuristic_score(features)
        
        # Normalisation
        normalized = (features - self.feature_stats["mean"]) / self.feature_stats["std"]
        
        # Simulation d'Isolation Forest score
        # En production: score = -self.model.score_samples([normalized])[0]
        
        # Score basé sur distance aux moyennes
        distance = np.linalg.norm(normalized)
        score = min(1.0, distance / 5.0)  # Normalisation empirique
        
        # Bonus pour features spécifiques
        if features[1] > 2:  # Beaucoup de mots-clés suspects
            score += 0.2
        if features[7] > 0.4:  # Patterns d'attaque
            score += 0.3
        
        score = min(1.0, max(0.0, score))
        
        return score
    
    def _heuristic_score(self, features: np.ndarray) -> float:
        """
        Score heuristique quand le modèle n'est pas entraîné
        """
        score = 0.0
        
        # Feature 1: Message très long
        if features[0] > 500:
            score += 0.2
        
        # Feature 2: Mots-clés suspects
        score += min(0.3, features[1] * 0.1)
        
        # Feature 4: Sévérité haute
        if features[3] > 0.7:
            score += 0.2
        
        # Feature 7: Codes HTTP suspects
        score += features[6] * 0.2
        
        # Feature 8: Patterns d'attaque
        score += features[7]
        
        return min(1.0, score)
    
    def is_anomaly(self, score: float) -> bool:
        """Détermine si le score indique une anomalie"""
        return score >= self.threshold
    
    def analyze(self, event: Dict) -> Dict:
        """
        Analyse complète d'un événement
        
        Returns:
            Dict avec score, is_anomaly, confidence, features
        """
        score = self.compute_anomaly_score(event)
        is_anomalous = self.is_anomaly(score)
        
        # Niveau de confiance (basé sur distance au seuil)
        if is_anomalous:
            confidence = (score - self.threshold) / (1.0 - self.threshold)
        else:
            confidence = (self.threshold - score) / self.threshold
        
        confidence = min(1.0, max(0.0, confidence))
        
        result = {
            "event_id": event.get("event_id", "unknown"),
            "anomaly_score": score,
            "is_anomaly": is_anomalous,
            "confidence": confidence,
            "severity": "critical" if score > 0.9 else "high" if score > 0.7 else "medium" if score > 0.5 else "low",
            "features": self.extract_features(event).tolist()
        }
        
        # Historique
        self.detection_history.append({
            "timestamp": datetime.now().isoformat(),
            "event_id": result["event_id"],
            "score": score,
            "is_anomaly": is_anomalous
        })
        
        return result
    
    def batch_analyze(self, events: List[Dict]) -> List[Dict]:
        """Analyse un batch d'événements"""
        return [self.analyze(e) for e in events]
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Calcule l'importance des features
        (simplifié - en production: utiliser shap ou permutation importance)
        """
        if not self.detection_history:
            return {}
        
        return {
            "message_length": 0.15,
            "suspicious_keywords": 0.25,
            "ip_frequency": 0.10,
            "severity": 0.20,
            "time_of_day": 0.05,
            "http_codes": 0.15,
            "attack_patterns": 0.10
        }
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques"""
        if not self.detection_history:
            return {
                "model_trained": self.model_trained,
                "threshold": self.threshold,
                "detections": 0,
                "anomaly_rate": 0.0
            }
        
        anomalies = sum(1 for h in self.detection_history if h["is_anomaly"])
        
        return {
            "model_trained": self.model_trained,
            "threshold": self.threshold,
            "total_analyzed": len(self.detection_history),
            "anomalies_detected": anomalies,
            "anomaly_rate": anomalies / len(self.detection_history),
            "avg_score": np.mean([h["score"] for h in self.detection_history])
        }
    
    def export_dataset(self, events: List[Dict], filepath: str = "/tmp/features_dataset.csv"):
        """Exporte les features en CSV pour analyse"""
        try:
            import csv
            
            with open(filepath, "w", newline="") as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    "event_id", "msg_len", "keywords", "ip_hash", "severity",
                    "hour_sin", "hour_cos", "http_code", "attack_pattern", "anomaly_score"
                ])
                
                # Data
                for event in events:
                    features = self.extract_features(event)
                    score = self.compute_anomaly_score(event)
                    
                    row = [event.get("event_id", "unknown")] + features.tolist() + [score]
                    writer.writerow(row)
            
            print(f"[ANOMALY_DETECTOR] ✓ Dataset exporté: {filepath}")
            
        except Exception as e:
            print(f"[ANOMALY_DETECTOR] ❌ Erreur export: {e}")


def main():
    """Test standalone de l'anomaly detector"""
    print("="*60)
    print("TEST ANOMALY DETECTOR")
    print("="*60)
    
    detector = AnomalyDetector(threshold=0.7)
    
    # Dataset d'entraînement (événements normaux majoritairement)
    training_events = [
        {
            "event_id": f"train_{i}",
            "message": "User login successful" if i % 5 != 0 else "Multiple failed login attempts detected",
            "ip_source": f"192.168.1.{10 + i % 50}",
            "severity": "low" if i % 5 != 0 else "high",
            "timestamp": datetime.now().isoformat()
        }
        for i in range(50)
    ]
    
    print(f"\n📚 Entraînement...")
    detector.train(training_events)
    
    # Événements de test
    test_events = [
        {
            "event_id": "test_normal",
            "message": "User alice logged in successfully",
            "ip_source": "192.168.1.20",
            "severity": "low"
        },
        {
            "event_id": "test_bruteforce",
            "message": "Failed password for invalid user admin from 192.168.1.100 - multiple attempts",
            "ip_source": "192.168.1.100",
            "severity": "high"
        },
        {
            "event_id": "test_scan",
            "message": "nmap scan detected from external IP - port enumeration in progress",
            "ip_source": "203.0.113.50",
            "severity": "critical"
        },
        {
            "event_id": "test_web_attack",
            "message": "GET /admin/../../../etc/passwd HTTP/1.1 404 - directory traversal attempt",
            "ip_source": "198.51.100.25",
            "severity": "high"
        }
    ]
    
    print("\n" + "="*60)
    print("ANALYSE D'ÉVÉNEMENTS")
    print("="*60)
    
    for event in test_events:
        print(f"\n📋 Événement: {event['event_id']}")
        print(f"   Message: {event['message'][:60]}...")
        
        result = detector.analyze(event)
        
        print(f"\n🎯 Résultat:")
        print(f"   Score d'anomalie: {result['anomaly_score']:.3f}")
        print(f"   Est une anomalie: {'OUI ⚠️' if result['is_anomaly'] else 'NON ✓'}")
        print(f"   Confiance: {result['confidence']:.2%}")
        print(f"   Sévérité: {result['severity']}")
        print("-" * 60)
    
    # Stats finales
    print("\n" + "="*60)
    print("STATISTIQUES")
    print("="*60)
    
    stats = detector.get_stats()
    print(json.dumps(stats, indent=2))
    
    # Importance des features
    print("\n📊 Importance des features:")
    importance = detector.get_feature_importance()
    for feature, score in sorted(importance.items(), key=lambda x: x[1], reverse=True):
        print(f"   {feature}: {score:.1%}")
    
    # Export dataset
    detector.export_dataset(training_events + test_events)


if __name__ == "__main__":
    main()
