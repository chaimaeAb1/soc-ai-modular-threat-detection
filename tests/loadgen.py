#!/usr/bin/env python3
"""
tests/loadgen.py
Générateur de charge pour tester les performances du SOC

Génère des événements synthétiques à un taux configurable
"""

import asyncio
import json
import random
import time
import argparse
from datetime import datetime
from typing import List, Dict


class LoadGenerator:
    """
    Générateur de charge pour tests de performance
    
    Simule des événements réalistes:
    - 70% normaux
    - 20% suspects
    - 10% malveillants
    """
    
    def __init__(self, rate_eps: int = 10, duration: int = 60):
        """
        Args:
            rate_eps: Events par seconde
            duration: Durée du test en secondes
        """
        self.rate_eps = rate_eps
        self.duration = duration
        self.events_generated = 0
        self.start_time = None
        
        # Templates d'événements
        self.normal_templates = [
            "User {user} logged in successfully from {ip}",
            "GET /index.html HTTP/1.1 200",
            "Connection established from {ip}",
            "User {user} logged out",
            "Routine system check completed"
        ]
        
        self.suspicious_templates = [
            "Multiple login attempts from {ip}",
            "GET /admin HTTP/1.1 404",
            "Unusual access pattern detected for user {user}",
            "Connection attempt to closed port from {ip}",
            "GET /.git/config HTTP/1.1 404"
        ]
        
        self.malicious_templates = [
            "Failed password for invalid user {user} from {ip} port 52341 ssh2",
            "nmap SYN scan detected from {ip}",
            "SQL injection attempt: ' OR '1'='1 from {ip}",
            "GET /../../../etc/passwd HTTP/1.1 403",
            "Brute force attack detected from {ip}",
            "DDoS flooding from {ip}",
            "Malware signature detected in upload from {ip}"
        ]
        
        self.users = ["alice", "bob", "charlie", "admin", "root", "guest", "operator"]
        self.ips = [
            f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)
        ] + [
            f"192.168.1.{random.randint(50,200)}" for _ in range(10)
        ] + [
            f"203.0.113.{random.randint(1,254)}" for _ in range(5)  # IPs suspectes
        ]
    
    def generate_event(self, event_type: str = None) -> Dict:
        """
        Génère un événement synthétique
        
        Args:
            event_type: 'normal', 'suspicious', 'malicious' ou None (aléatoire)
        """
        if event_type is None:
            # Distribution: 70% normal, 20% suspect, 10% malveillant
            rand = random.random()
            if rand < 0.7:
                event_type = "normal"
            elif rand < 0.9:
                event_type = "suspicious"
            else:
                event_type = "malicious"
        
        # Sélection du template
        if event_type == "normal":
            template = random.choice(self.normal_templates)
            severity = "low"
            source = "/var/log/auth.log" if "login" in template else "/var/log/nginx/access.log"
        elif event_type == "suspicious":
            template = random.choice(self.suspicious_templates)
            severity = "medium"
            source = random.choice(["/var/log/auth.log", "/var/log/nginx/access.log"])
        else:  # malicious
            template = random.choice(self.malicious_templates)
            severity = "high"
            source = "/var/log/auth.log" if "ssh" in template or "password" in template else "/var/log/nginx/access.log"
        
        # Remplissage du template
        message = template.format(
            user=random.choice(self.users),
            ip=random.choice(self.ips)
        )
        
        # Extraction IP depuis le message
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        ip_source = ip_match.group(0) if ip_match else random.choice(self.ips)
        
        return {
            "event_id": f"loadtest_{self.events_generated}",
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "ip_source": ip_source,
            "message": message,
            "severity": severity,
            "metadata": {
                "generated_by": "loadgen",
                "event_type": event_type
            }
        }
    
    async def run(self):
        """
        Lance le générateur de charge
        """
        print("="*70)
        print("⚡ GÉNÉRATEUR DE CHARGE - SOC IA")
        print("="*70)
        print(f"Taux: {self.rate_eps} events/sec")
        print(f"Durée: {self.duration}s")
        print(f"Total prévu: {self.rate_eps * self.duration} événements")
        print("="*70 + "\n")
        
        self.start_time = time.time()
        batch_size = max(1, self.rate_eps // 10)  # 10 batches par seconde
        delay_between_batches = 1.0 / 10
        
        try:
            while time.time() - self.start_time < self.duration:
                batch_start = time.time()
                
                # Génération d'un batch
                for _ in range(batch_size):
                    event = self.generate_event()
                    self.events_generated += 1
                    
                    # Affichage périodique
                    if self.events_generated % 50 == 0:
                        elapsed = time.time() - self.start_time
                        actual_rate = self.events_generated / elapsed if elapsed > 0 else 0
                        print(f"[LOADGEN] Événements générés: {self.events_generated} "
                              f"(taux réel: {actual_rate:.1f} eps)")
                    
                    # Ici, dans un vrai système, on enverrait l'événement au SOC
                    # Par exemple: await send_to_soc(event)
                
                # Attendre pour maintenir le taux
                batch_duration = time.time() - batch_start
                if batch_duration < delay_between_batches:
                    await asyncio.sleep(delay_between_batches - batch_duration)
        
        except KeyboardInterrupt:
            print("\n[LOADGEN] Arrêt demandé par l'utilisateur")
        
        finally:
            self._print_statistics()
    
    def _print_statistics(self):
        """Affiche les statistiques finales"""
        elapsed = time.time() - self.start_time
        actual_rate = self.events_generated / elapsed if elapsed > 0 else 0
        
        print("\n" + "="*70)
        print("📊 STATISTIQUES DU TEST DE CHARGE")
        print("="*70)
        print(f"Durée totale: {elapsed:.2f}s")
        print(f"Événements générés: {self.events_generated}")
        print(f"Taux cible: {self.rate_eps} eps")
        print(f"Taux réel: {actual_rate:.2f} eps")
        print(f"Écart: {abs(actual_rate - self.rate_eps):.2f} eps "
              f"({abs(actual_rate - self.rate_eps) / self.rate_eps * 100:.1f}%)")
        print("="*70 + "\n")
    
    def export_events(self, filepath: str = "/tmp/loadgen_events.json"):
        """Exporte les événements générés"""
        print(f"[LOADGEN] Génération et export de {self.rate_eps * self.duration} événements...")
        
        events = [self.generate_event() for _ in range(self.rate_eps * self.duration)]
        
        try:
            with open(filepath, "w") as f:
                json.dump(events, f, indent=2)
            print(f"[LOADGEN] ✓ Événements exportés vers {filepath}")
        except Exception as e:
            print(f"[LOADGEN] ❌ Erreur export: {e}")


class AttackScenario:
    """
    Scénarios d'attaque prédéfinis pour tests
    """
    
    @staticmethod
    def scenario_ssh_bruteforce(duration: int = 30) -> List[Dict]:
        """Scénario: Attaque brute force SSH prolongée"""
        events = []
        attacker_ip = "203.0.113.100"
        
        for i in range(duration * 2):  # 2 tentatives/sec
            events.append({
                "event_id": f"bruteforce_{i}",
                "timestamp": datetime.now().isoformat(),
                "source": "/var/log/auth.log",
                "ip_source": attacker_ip,
                "message": f"Failed password for {random.choice(['admin', 'root', 'user'])} from {attacker_ip} port {50000 + i} ssh2",
                "severity": "high",
                "metadata": {"scenario": "ssh_bruteforce"}
            })
        
        return events
    
    @staticmethod
    def scenario_port_scan(num_ports: int = 100) -> List[Dict]:
        """Scénario: Scan de ports"""
        events = []
        scanner_ip = "198.51.100.50"
        
        for port in range(1, num_ports + 1):
            events.append({
                "event_id": f"portscan_{port}",
                "timestamp": datetime.now().isoformat(),
                "source": "/var/log/syslog",
                "ip_source": scanner_ip,
                "message": f"SYN packet to port {port} from {scanner_ip}",
                "severity": "medium",
                "metadata": {"scenario": "port_scan", "port": port}
            })
        
        return events
    
    @staticmethod
    def scenario_web_enumeration(num_paths: int = 50) -> List[Dict]:
        """Scénario: Énumération web"""
        events = []
        attacker_ip = "192.0.2.75"
        paths = ["/admin", "/config", "/backup", "/.git", "/wp-admin", "/phpmyadmin",
                 "/api", "/test", "/dev", "/uploads"]
        
        for i in range(num_paths):
            path = random.choice(paths)
            events.append({
                "event_id": f"webenum_{i}",
                "timestamp": datetime.now().isoformat(),
                "source": "/var/log/nginx/access.log",
                "ip_source": attacker_ip,
                "message": f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" 404 162',
                "severity": "medium",
                "metadata": {"scenario": "web_enumeration"}
            })
        
        return events


async def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description="Générateur de charge pour SOC IA")
    parser.add_argument("--rate", type=int, default=10, help="Events par seconde (default: 10)")
    parser.add_argument("--duration", type=int, default=60, help="Durée en secondes (default: 60)")
    parser.add_argument("--scenario", choices=["random", "bruteforce", "portscan", "webenum"],
                       default="random", help="Scénario à exécuter")
    parser.add_argument("--export", type=str, help="Exporter les événements vers un fichier JSON")
    
    args = parser.parse_args()
    
    if args.scenario == "random":
        # Mode générateur continu
        generator = LoadGenerator(rate_eps=args.rate, duration=args.duration)
        
        if args.export:
            generator.export_events(args.export)
        else:
            await generator.run()
    
    else:
        # Mode scénario prédéfini
        print(f"\n🎬 Exécution du scénario: {args.scenario}\n")
        
        if args.scenario == "bruteforce":
            events = AttackScenario.scenario_ssh_bruteforce(args.duration)
        elif args.scenario == "portscan":
            events = AttackScenario.scenario_port_scan(args.rate * args.duration)
        elif args.scenario == "webenum":
            events = AttackScenario.scenario_web_enumeration(args.rate * args.duration)
        
        print(f"✓ {len(events)} événements générés pour le scénario '{args.scenario}'")
        
        if args.export:
            with open(args.export, "w") as f:
                json.dump(events, f, indent=2)
            print(f"✓ Événements exportés vers {args.export}")
        else:
            # Afficher quelques exemples
            print("\n📋 Exemples d'événements générés:\n")
            for event in events[:5]:
                print(f"  • {event['message'][:70]}...")
            print(f"\n  ... et {len(events) - 5} autres événements")


if __name__ == "__main__":
    asyncio.run(main())
