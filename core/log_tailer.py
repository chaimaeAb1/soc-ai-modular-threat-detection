#!/usr/bin/env python3
"""
core/log_tailer.py - Version réelle
Lit les fichiers de logs en temps réel et publie dans Kafka topic events_raw
"""

import asyncio
import json
import os
import re
import time
from datetime import datetime
from typing import AsyncGenerator, Dict

from kafka import KafkaProducer
import tailer  # pip install tailer kafka-python


class LogTailer:
    """
    Tailer asynchrone réel qui lit les fichiers de logs système
    et publie chaque nouvelle ligne dans Kafka (topic events_raw)
    """

    def __init__(
        self,
        log_paths: list[str],
        kafka_bootstrap: str = "localhost:9093",  # Port exposé sur l'hôte
        topic: str = "events_raw",
    ):
        self.log_paths = [p for p in log_paths if os.path.exists(p)]
        self.topic = topic
        self.running = False

        # Producteur Kafka
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            api_version=(0, 10, 1),  # Évite certains warnings
        )

        if not self.log_paths:
            print("[LOG_TAILER] ⚠️ Aucun fichier log valide trouvé parmi ceux fournis.")
        else:
            print(f"[LOG_TAILER] 🔍 Prêt à surveiller {len(self.log_paths)} fichier(s) réel(s) :")
            for p in self.log_paths:
                print(f"   → {p}")

    async def start(self) -> AsyncGenerator[Dict, None]:
        """Démarre la surveillance en temps réel et yield chaque événement"""
        self.running = True
        print("[LOG_TAILER] 🚀 Démarrage du tailing réel...")

        # Ouvrir les fichiers et se positionner à la fin
        files = {}
        for path in self.log_paths:
            try:
                f = open(path, "r", encoding="utf-8", errors="ignore")
                f.seek(0, os.SEEK_END)  # Aller à la fin
                files[path] = f
                print(f"[LOG_TAILER] Ouverture réussie : {path}")
            except Exception as e:
                print(f"[LOG_TAILER] ❌ Impossible d'ouvrir {path} : {e}")

        try:
            while self.running:
                has_new_line = False
                for path, f in list(files.items()):
                    for line in tailer.follow(f):
                        has_new_line = True
                        line = line.rstrip("\n")

                        # Construction de l'événement
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "source": path,
                            "message": line,
                            "raw_log": line,
                        }

                        # Extraction d'IP si présente
                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        event["ip_source"] = ip_match.group(0) if ip_match else "unknown"

                        # Publication dans Kafka
                        try:
                            self.producer.send(self.topic, event)
                            self.producer.flush()
                        except Exception as e:
                            print(f"[LOG_TAILER] ❌ Erreur envoi Kafka : {e}")

                        # Yield pour le consommateur
                        yield event

                        print(f"[LOG_TAILER] Log réel envoyé → {line[:80]}{'...' if len(line) > 80 else ''}")

                if not has_new_line:
                    await asyncio.sleep(0.1)  # Petit repos si rien de nouveau

        except Exception as e:
            print(f"[LOG_TAILER] ❌ Erreur fatale dans le tailing : {e}")
        finally:
            # Nettoyage
            for f in files.values():
                f.close()
            print("[LOG_TAILER] ⏹️ Arrêt du tailing réel")

    def stop(self):
        """Arrête proprement la surveillance"""
        self.running = False
        print("[LOG_TAILER] ⏹️ Demande d'arrêt reçue")


# =============================================================================
# Test standalone
# =============================================================================
async def main():
    """Test simple du tailer (affichage en console)"""
    tailer = LogTailer(
        log_paths=[
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/nginx/access.log",  # Ajoute si tu as Nginx
        ]
    )

    try:
        async for event in tailer.start():
            print("\n" + "=" * 60)
            print("NOUVEL ÉVÉNEMENT RÉEL")
            print("=" * 60)
            print(json.dumps(event, indent=2, ensure_ascii=False))
            print("=" * 60)

            # Option : arrêter avec Ctrl+C ou après X événements
    except KeyboardInterrupt:
        print("\n[LOG_TAILER] Interruption utilisateur")
    finally:
        tailer.stop()


if __name__ == "__main__":
    asyncio.run(main())
