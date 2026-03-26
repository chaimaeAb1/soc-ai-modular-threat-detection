#!/usr/bin/env python3
"""
core/collector.py
Agent de collecte et normalisation des événements
"""

import json
import re
from datetime import datetime
from typing import Dict, Optional

class Collector:
    """
    Agent responsable de:
    - Collecter les événements bruts
    - Normaliser le format
    - Enrichir avec métadonnées
    - Faire une première classification
    """
    
    def __init__(self, collector_id: str = "collector_001"):
        self.collector_id = collector_id
        self.event_buffer = []
        self.processed_count = 0
        
        # Règles de détection basique
        self.severity_rules = {
            "critical": ["kernel panic", "out of memory", "system failure"],
            "high": ["failed password", "authentication failure", "port scan", "sql injection"],
            "medium": ["invalid user", "404", "connection refused", "timeout"],
            "low": ["info", "debug", "notice"]
        }
    
    async def process(self, raw_event: dict) -> dict:
        """
        Traite et normalise un événement brut
        
        Args:
            raw_event: Événement brut du log_tailer
            
        Returns:
            Événement normalisé et enrichi
        """
        print(f"[COLLECTOR] 📥 Traitement événement #{self.processed_count + 1}")
        
        # Normalisation
        normalized_event = {
            "event_id": f"evt_{int(datetime.now().timestamp() * 1000)}",
            "timestamp": raw_event.get("timestamp", datetime.now().isoformat()),
            "source": raw_event.get("source", "unknown"),
            "ip_source": raw_event.get("ip_source", "unknown"),
            "message": raw_event.get("message", ""),
            "severity": raw_event.get("severity", "low"),
            "metadata": raw_event.get("metadata", {})
        }
        
        # Enrichissement
        normalized_event["metadata"]["collected_at"] = datetime.now().isoformat()
        normalized_event["metadata"]["collector_id"] = self.collector_id
        normalized_event["metadata"]["collector_version"] = "1.0.0"
        
        # Classification de sévérité
        normalized_event["severity"] = self._classify_severity(normalized_event["message"])
        
        # Extraction d'informations
        normalized_event["metadata"]["extracted_info"] = self._extract_info(normalized_event)
        
        # Mise en buffer
        self.event_buffer.append(normalized_event)
        self.processed_count += 1
        
        print(f"[COLLECTOR] ✓ Événement normalisé (sévérité: {normalized_event['severity']})")
        
        return normalized_event
    
    def _classify_severity(self, message: str) -> str:
        """
        Classifie la sévérité d'un message
        """
        message_lower = message.lower()
        
        # Ordre de priorité: critical > high > medium > low
        for severity, keywords in self.severity_rules.items():
            for keyword in keywords:
                if keyword in message_lower:
                    return severity
        
        return "low"
    
    def _extract_info(self, event: dict) -> dict:
        """
        Extrait des informations structurées du message
        """
        info = {
            "event_type": "unknown",
            "protocol": None,
            "port": None,
            "user": None,
            "status_code": None
        }
        
        message = event["message"]
        
        # Détection SSH
        if "sshd" in message or "ssh" in message.lower():
            info["event_type"] = "ssh_auth"
            info["protocol"] = "ssh"
            info["port"] = 22
            
            # Extraction utilisateur
            user_match = re.search(r'for (?:invalid user )?(\w+)', message)
            if user_match:
                info["user"] = user_match.group(1)
        
        # Détection HTTP/Nginx
        if "GET" in message or "POST" in message or "HTTP" in message:
            info["event_type"] = "http_request"
            info["protocol"] = "http"
            
            # Extraction status code
            status_match = re.search(r'HTTP/\d\.\d" (\d{3})', message)
            if status_match:
                info["status_code"] = int(status_match.group(1))
            
            # Extraction path
            path_match = re.search(r'"[A-Z]+ ([^\s]+) HTTP', message)
            if path_match:
                info["path"] = path_match.group(1)
        
        # Détection scan
        if "nmap" in message.lower() or "port scan" in message.lower():
            info["event_type"] = "port_scan"
        
        # Détection brute force
        if "failed password" in message.lower() or "authentication failure" in message.lower():
            info["event_type"] = "brute_force"
        
        return info
    
    def get_buffer(self) -> list:
        """Retourne le buffer d'événements"""
        return self.event_buffer.copy()
    
    def clear_buffer(self):
        """Vide le buffer"""
        self.event_buffer.clear()
    
    def get_stats(self) -> dict:
        """Retourne les statistiques"""
        return {
            "processed_count": self.processed_count,
            "buffer_size": len(self.event_buffer),
            "collector_id": self.collector_id
        }


async def main():
    """Test standalone du collector"""
    print("="*60)
    print("TEST COLLECTOR")
    print("="*60)
    
    collector = Collector()
    
    # Événements de test
    test_events = [
        {
            "timestamp": datetime.now().isoformat(),
            "source": "/var/log/auth.log",
            "ip_source": "192.168.1.100",
            "message": "Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source": "/var/log/nginx/access.log",
            "ip_source": "192.168.1.50",
            "message": '192.168.1.50 - - [25/Dec/2025:10:15:40 +0000] "GET /admin HTTP/1.1" 404 162'
        }
    ]
    
    for raw_event in test_events:
        print(f"\n📨 Événement brut:")
        print(json.dumps(raw_event, indent=2))
        
        normalized = await collector.process(raw_event)
        
        print(f"\n✨ Événement normalisé:")
        print(json.dumps(normalized, indent=2))
        print("-"*60)
    
    print("\n" + "="*60)
    print("STATS:", collector.get_stats())
    print("="*60)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
