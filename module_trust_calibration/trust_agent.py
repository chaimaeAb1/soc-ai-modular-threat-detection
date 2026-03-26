#!/usr/bin/env python3
"""
atelier_a/trust_agent.py
Module de calibration de confiance (Trust & Calibration)

Méthodes implémentées:
- Platt Scaling
- Temperature Scaling
- Brier Score
"""

import json
import math
import numpy as np
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CalibrationMetrics:
    """Métriques de calibration"""
    brier_score: float
    expected_calibration_error: float  # ECE
    max_calibration_error: float       # MCE
    accuracy: float
    

class TrustAgent:
    """
    Agent de calibration de confiance
    
    Problème: Les scores de confiance des LLMs sont souvent mal calibrés
    Solution: Appliquer Platt Scaling ou Temperature Scaling
    
    Objectif: Réduire les faux positifs/négatifs en ajustant les probabilités
    """
    
    def __init__(self, method: str = "platt"):
        """
        Args:
            method: 'platt', 'temperature', ou 'isotonic'
        """
        self.method = method
        self.is_calibrated = False
        
        # Paramètres Platt Scaling (logistique)
        self.platt_A = 1.0
        self.platt_B = 0.0
        
        # Paramètre Temperature Scaling
        self.temperature = 1.0
        
        # Historique
        self.calibration_history = []
        self.predictions = []
        
        print(f"[TRUST_AGENT] 🎯 Initialisation (méthode: {method})")
    
    def calibrate(
        self,
        scores: List[float],
        labels: List[bool],
        method: Optional[str] = None
    ):
        """
        Calibre le modèle avec un dataset d'entraînement
        
        Args:
            scores: Scores de confiance bruts (0-1)
            labels: Vraies étiquettes (True/False)
            method: Override de la méthode
        """
        if method:
            self.method = method
        
        print(f"\n[TRUST_AGENT] 🔧 Calibration en cours ({self.method})...")
        print(f"[TRUST_AGENT]    Dataset: {len(scores)} exemples")
        
        # Validation
        if len(scores) != len(labels):
            raise ValueError("scores et labels doivent avoir la même longueur")
        
        if len(scores) < 10:
            print("[TRUST_AGENT] ⚠️  Dataset petit (<10), calibration risquée")
        
        # Dispatch vers la méthode appropriée
        if self.method == "platt":
            self._calibrate_platt(scores, labels)
        elif self.method == "temperature":
            self._calibrate_temperature(scores, labels)
        else:
            raise ValueError(f"Méthode inconnue: {self.method}")
        
        self.is_calibrated = True
        
        # Calcul des métriques
        calibrated_scores = [self.adjust_confidence(s) for s in scores]
        metrics = self.compute_metrics(calibrated_scores, labels)
        
        print(f"[TRUST_AGENT] ✓ Calibration terminée")
        print(f"[TRUST_AGENT]    Brier Score: {metrics.brier_score:.4f}")
        print(f"[TRUST_AGENT]    ECE: {metrics.expected_calibration_error:.4f}")
        print(f"[TRUST_AGENT]    Accuracy: {metrics.accuracy:.2%}")
        
        # Sauvegarde
        self.calibration_history.append({
            "timestamp": datetime.now().isoformat(),
            "method": self.method,
            "dataset_size": len(scores),
            "metrics": metrics
        })
    
    def _calibrate_platt(self, scores: List[float], labels: List[bool]):
        """
        Platt Scaling: P_calibrated = sigmoid(A * logit(p) + B)
        
        On optimise A et B par maximum de vraisemblance
        """
        # Conversion en logits
        logits = []
        for score in scores:
            # Éviter log(0) et log(1)
            score = max(0.001, min(0.999, score))
            logit = math.log(score / (1 - score))
            logits.append(logit)
        
        # Optimisation simplifiée (en production: scipy.optimize)
        # Ici: méthode des moindres carrés
        
        X = np.array(logits).reshape(-1, 1)
        X = np.hstack([X, np.ones((len(X), 1))])  # Ajoute colonne de 1
        y = np.array(labels, dtype=float)
        
        try:
            # Régression logistique: (X^T X)^-1 X^T y
            params = np.linalg.lstsq(X, y, rcond=None)[0]
            self.platt_A = params[0]
            self.platt_B = params[1]
            
            print(f"[TRUST_AGENT]    Paramètres Platt: A={self.platt_A:.3f}, B={self.platt_B:.3f}")
        except:
            print("[TRUST_AGENT] ⚠️  Erreur optimisation, paramètres par défaut")
            self.platt_A = 1.0
            self.platt_B = 0.0
    
    def _calibrate_temperature(self, scores: List[float], labels: List[bool]):
        """
        Temperature Scaling: P_calibrated = softmax(logit / T)
        
        On optimise T pour minimiser la cross-entropy
        """
        # Recherche du meilleur T par grid search
        best_t = 1.0
        best_loss = float('inf')
        
        for T in np.arange(0.5, 3.0, 0.1):
            loss = 0
            for score, label in zip(scores, labels):
                # Éviter divisions par 0
                score = max(0.001, min(0.999, score))
                
                # Logit puis temperature
                logit = math.log(score / (1 - score))
                calibrated_logit = logit / T
                calibrated_prob = 1 / (1 + math.exp(-calibrated_logit))
                
                # Cross-entropy
                if label:
                    loss -= math.log(calibrated_prob + 1e-10)
                else:
                    loss -= math.log(1 - calibrated_prob + 1e-10)
            
            if loss < best_loss:
                best_loss = loss
                best_t = T
        
        self.temperature = best_t
        print(f"[TRUST_AGENT]    Température optimale: T={self.temperature:.3f}")
    
    def adjust_confidence(self, confidence: float) -> float:
        """
        Ajuste un score de confiance avec la méthode calibrée
        
        Args:
            confidence: Score brut (0-1)
            
        Returns:
            Score calibré (0-1)
        """
        if not self.is_calibrated:
            # Pas encore calibré, retourne tel quel
            return confidence
        
        # Éviter les valeurs limites
        confidence = max(0.001, min(0.999, confidence))
        
        # Application de la calibration
        if self.method == "platt":
            # Logit
            logit = math.log(confidence / (1 - confidence))
            
            # Application A et B
            adjusted_logit = self.platt_A * logit + self.platt_B
            
            # Retour à probabilité (sigmoid)
            calibrated = 1 / (1 + math.exp(-adjusted_logit))
            
        elif self.method == "temperature":
            # Logit
            logit = math.log(confidence / (1 - confidence))
            
            # Application température
            adjusted_logit = logit / self.temperature
            
            # Sigmoid
            calibrated = 1 / (1 + math.exp(-adjusted_logit))
        
        else:
            calibrated = confidence
        
        return max(0.0, min(1.0, calibrated))
    
    def compute_brier_score(
        self,
        predictions: List[float],
        labels: List[bool]
    ) -> float:
        """
        Calcule le Brier Score
        
        BS = (1/N) * Σ(prediction - label)²
        
        Plus bas = meilleur (0 = parfait, 1 = pire)
        """
        if not predictions or len(predictions) != len(labels):
            return 1.0
        
        brier = sum((p - int(l))**2 for p, l in zip(predictions, labels))
        brier /= len(predictions)
        
        return brier
    
    def compute_ece(
        self,
        predictions: List[float],
        labels: List[bool],
        n_bins: int = 10
    ) -> float:
        """
        Calcule Expected Calibration Error (ECE)
        
        Mesure l'écart entre confiance prédite et accuracy réelle
        """
        bins = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        
        for i in range(n_bins):
            # Événements dans ce bin
            in_bin = [
                (p, l) for p, l in zip(predictions, labels)
                if bins[i] <= p < bins[i+1]
            ]
            
            if not in_bin:
                continue
            
            # Confiance moyenne et accuracy dans ce bin
            avg_confidence = sum(p for p, _ in in_bin) / len(in_bin)
            avg_accuracy = sum(int(l) for _, l in in_bin) / len(in_bin)
            
            # ECE = moyenne pondérée des écarts
            ece += (len(in_bin) / len(predictions)) * abs(avg_confidence - avg_accuracy)
        
        return ece
    
    def compute_metrics(
        self,
        predictions: List[float],
        labels: List[bool]
    ) -> CalibrationMetrics:
        """
        Calcule toutes les métriques de calibration
        """
        # Brier Score
        brier = self.compute_brier_score(predictions, labels)
        
        # ECE
        ece = self.compute_ece(predictions, labels)
        
        # MCE (Maximum Calibration Error)
        # Calcul similaire à ECE mais prend le max au lieu de la moyenne
        bins = np.linspace(0, 1, 11)
        max_error = 0.0
        for i in range(10):
            in_bin = [
                (p, l) for p, l in zip(predictions, labels)
                if bins[i] <= p < bins[i+1]
            ]
            if in_bin:
                avg_conf = sum(p for p, _ in in_bin) / len(in_bin)
                avg_acc = sum(int(l) for _, l in in_bin) / len(in_bin)
                max_error = max(max_error, abs(avg_conf - avg_acc))
        
        # Accuracy (seuil 0.5)
        correct = sum(1 for p, l in zip(predictions, labels) if (p >= 0.5) == l)
        accuracy = correct / len(predictions) if predictions else 0.0
        
        return CalibrationMetrics(
            brier_score=brier,
            expected_calibration_error=ece,
            max_calibration_error=max_error,
            accuracy=accuracy
        )
    
    def plot_reliability_diagram(
        self,
        predictions: List[float],
        labels: List[bool],
        filepath: str = "/tmp/reliability_diagram.png"
    ):
        """
        Génère un diagramme de fiabilité
        
        X = confiance prédite
        Y = accuracy réelle
        Idéal: courbe y=x
        """
        try:
            import matplotlib.pyplot as plt
            
            bins = np.linspace(0, 1, 11)
            bin_confidences = []
            bin_accuracies = []
            
            for i in range(10):
                in_bin = [
                    (p, l) for p, l in zip(predictions, labels)
                    if bins[i] <= p < bins[i+1]
                ]
                if in_bin:
                    avg_conf = sum(p for p, _ in in_bin) / len(in_bin)
                    avg_acc = sum(int(l) for _, l in in_bin) / len(in_bin)
                    bin_confidences.append(avg_conf)
                    bin_accuracies.append(avg_acc)
            
            plt.figure(figsize=(8, 6))
            plt.plot([0, 1], [0, 1], 'k--', label='Parfait calibré')
            plt.plot(bin_confidences, bin_accuracies, 'ro-', label='Modèle')
            plt.xlabel('Confiance prédite')
            plt.ylabel('Accuracy réelle')
            plt.title('Diagramme de fiabilité')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            
            print(f"[TRUST_AGENT] ✓ Diagramme sauvegardé: {filepath}")
            
        except ImportError:
            print("[TRUST_AGENT] ⚠️  matplotlib non disponible")
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques"""
        return {
            "is_calibrated": self.is_calibrated,
            "method": self.method,
            "platt_params": {"A": self.platt_A, "B": self.platt_B},
            "temperature": self.temperature,
            "calibration_count": len(self.calibration_history)
        }


def main():
    """Test standalone du trust_agent"""
    print("="*60)
    print("TEST TRUST AGENT - CALIBRATION")
    print("="*60)
    
    # Dataset d'entraînement simulé
    # (score_confiance, vraie_étiquette)
    training_data = [
        (0.95, True),   # Haute confiance, vrai positif
        (0.90, True),
        (0.85, True),
        (0.80, False),  # Haute confiance, faux positif !
        (0.75, True),
        (0.70, False),
        (0.65, True),
        (0.60, False),
        (0.55, False),
        (0.50, False),
        (0.45, False),
        (0.40, False),
        (0.35, False),
        (0.30, True),   # Basse confiance, vrai positif (rare)
        (0.25, False),
        (0.20, False),
        (0.15, False),
        (0.10, False),
    ]
    
    scores = [s for s, _ in training_data]
    labels = [l for _, l in training_data]
    
    print(f"\n📊 Dataset: {len(training_data)} exemples")
    print(f"   Vrais positifs: {sum(labels)}")
    print(f"   Vrais négatifs: {len(labels) - sum(labels)}")
    
    # Test Platt Scaling
    print("\n" + "="*60)
    print("TEST 1: PLATT SCALING")
    print("="*60)
    
    trust_platt = TrustAgent(method="platt")
    trust_platt.calibrate(scores, labels)
    
    # Comparaison avant/après
    print("\n📈 Comparaison scores:")
    print(f"{'Score brut':<15} {'Calibré':<15} {'Label':<10}")
    print("-" * 40)
    for i in [0, 3, 6, 9, 13]:  # Quelques exemples
        original = scores[i]
        calibrated = trust_platt.adjust_confidence(original)
        label = "MENACE" if labels[i] else "NORMAL"
        print(f"{original:<15.3f} {calibrated:<15.3f} {label:<10}")
    
    # Métriques
    calibrated_scores = [trust_platt.adjust_confidence(s) for s in scores]
    metrics = trust_platt.compute_metrics(calibrated_scores, labels)
    
    print(f"\n📊 Métriques finales:")
    print(f"   Brier Score: {metrics.brier_score:.4f}")
    print(f"   ECE: {metrics.expected_calibration_error:.4f}")
    print(f"   Accuracy: {metrics.accuracy:.1%}")
    
    # Test Temperature Scaling
    print("\n" + "="*60)
    print("TEST 2: TEMPERATURE SCALING")
    print("="*60)
    
    trust_temp = TrustAgent(method="temperature")
    trust_temp.calibrate(scores, labels)
    
    print("\n" + "="*60)
    print("COMPARAISON DES MÉTHODES")
    print("="*60)
    
    # Brier Score comparaison
    brier_uncalibrated = trust_platt.compute_brier_score(scores, labels)
    brier_platt = trust_platt.compute_brier_score(
        [trust_platt.adjust_confidence(s) for s in scores],
        labels
    )
    brier_temp = trust_temp.compute_brier_score(
        [trust_temp.adjust_confidence(s) for s in scores],
        labels
    )
    
    print(f"\nBrier Score:")
    print(f"  Non calibré:     {brier_uncalibrated:.4f}")
    print(f"  Platt Scaling:   {brier_platt:.4f}")
    print(f"  Temperature:     {brier_temp:.4f}")
    
    best = min(brier_uncalibrated, brier_platt, brier_temp)
    print(f"\n✓ Meilleur: {best:.4f}")


if __name__ == "__main__":
    main()
