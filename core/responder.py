#!/usr/bin/env python3
"""
core/responder.py
Responder SOC IA (version corrigée) — Blocage RÉEL fiable + dashboard-friendly

 Bloque via UFW (recommandé si UFW est actif, ce qui est ton cas)
 Utilise `ufw insert 1 deny from <ip> to any` pour passer AVANT le "allow 22"
 Supporte les champs de décision:
   - action: "block" / "block_ip" / "deny" / "drop"
   - ip: analysis["ip_source"] ou analysis["target"] ou extracted depuis message
 Sync des IP réellement bloquées via `ufw status` (parsing)
 Déblocage réel via `ufw delete deny from <ip>`
 Logs d’actions + stats

 IMPORTANT:
- Pour bloquer vraiment, il faut exécuter le processus SOC avec sudo/root.
- Ton iptables montre UFW => on évite d'écrire dans INPUT directement.
"""

import asyncio
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional

# -----------------------------
# Config
# -----------------------------
DEFAULT_BACKEND = os.environ.get("SOC_BLOCKING_BACKEND", "ufw").lower()  # ufw | iptables
DRY_RUN = os.environ.get("SOC_DRY_RUN", "0") in ("1", "true", "yes", "on")
RULE_TAG = os.environ.get("SOC_RULE_TAG", "SOC_IA")  # utilisé si iptables backend
WHITELIST = set(filter(None, os.environ.get("SOC_WHITELIST_IPS", "").split(",")))

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Action:
    action_id: str
    timestamp: str
    event_id: str
    action_type: str
    target: str
    success: bool
    details: str


def _now_iso() -> str:
    return datetime.now().isoformat()


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _run(cmd: List[str], timeout: int = 8) -> subprocess.CompletedProcess:
    """
    Exécute une commande. Si pas root, tente sudo -n (non-interactif).
    -> Si sudo demande un mot de passe, ça échouera clairement.
    """
    if not cmd:
        raise ValueError("Empty command")

    if _is_root():
        final = cmd
    else:
        # sudo non-interactif (-n) pour éviter le blocage
        final = ["sudo", "-n"] + cmd

    return subprocess.run(
        final,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _valid_ipv4(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip):
        return False
    # contrôle 0-255
    try:
        parts = [int(x) for x in ip.split(".")]
        return all(0 <= p <= 255 for p in parts) and len(parts) == 4
    except Exception:
        return False


def _extract_ip(text: str) -> str:
    m = IPV4_RE.search(text or "")
    return m.group(0) if m else "unknown"


def _normalize_action_name(action: str) -> str:
    a = (action or "").strip().lower()
    if a in ("block", "block_ip", "deny", "drop"):
        return "block"
    if a in ("alert", "notify"):
        return "alert"
    if a in ("ignore",):
        return "ignore"
    return "monitor"


# -----------------------------
# UFW helpers
# -----------------------------
def _ufw_rule_exists(ip: str) -> bool:
    """
    Cherche si l'IP est déjà bloquée via UFW.
    On parse `ufw status` (pas parfait mais robuste dans ton contexte).
    """
    p = _run(["ufw", "status"], timeout=12)
    if p.returncode != 0:
        return False
    # Formats possibles:
    # "Anywhere                   DENY IN    <ip>"
    # ou "22/tcp                   DENY IN    <ip>"
    return ip in p.stdout and "DENY" in p.stdout


def _ufw_block_ip(ip: str) -> subprocess.CompletedProcess:
    """
    Insert 1 => met la règle en haut, avant allow ssh.
    """
    return _run(["ufw", "insert", "1", "deny", "from", ip, "to", "any"], timeout=12)


def _ufw_unblock_ip(ip: str) -> subprocess.CompletedProcess:
    """
    Supprime la règle deny correspondante.
    NB: ufw delete deny from <ip> suffit dans la plupart des cas.
    """
    return _run(["ufw", "delete", "deny", "from", ip], timeout=12)


def get_blocked_ips_ufw() -> List[str]:
    """
    Retourne la liste des IPs réellement bloquées via UFW.
    """
    p = _run(["ufw", "status"], timeout=12)
    if p.returncode != 0:
        return []

    ips = set()
    # Regex sur IPv4 présentes dans les lignes DENY
    for line in p.stdout.splitlines():
        if "DENY" not in line:
            continue
        m = IPV4_RE.search(line)
        if m:
            ip = m.group(0)
            if _valid_ipv4(ip) and ip not in WHITELIST:
                ips.add(ip)

    return sorted(ips)


# -----------------------------
# IPTABLES helpers (fallback)
# -----------------------------
def _iptables_rule_exists(ip: str) -> bool:
    # -C retourne 0 si existe
    p = _run(["iptables", "-C", "ufw-user-input", "-s", ip, "-j", "DROP"], timeout=8)
    if p.returncode == 0:
        return True

    # fallback INPUT (si pas UFW)
    p2 = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], timeout=8)
    return p2.returncode == 0


def _iptables_block_ip(ip: str) -> subprocess.CompletedProcess:
    """
    IMPORTANT: Chez toi, UFW est actif -> si on doit faire iptables,
    on met la règle DANS ufw-user-input en tête, pas dans INPUT.
    """
    # insert en haut de ufw-user-input
    return _run(["iptables", "-I", "ufw-user-input", "1", "-s", ip, "-j", "DROP"], timeout=8)


def _iptables_unblock_ip(ip: str) -> subprocess.CompletedProcess:
    # supprime une occurrence (si multiple, répéter)
    # on tente ufw-user-input d'abord
    p = _run(["iptables", "-D", "ufw-user-input", "-s", ip, "-j", "DROP"], timeout=8)
    if p.returncode == 0:
        return p
    return _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], timeout=8)


def get_blocked_ips_iptables() -> List[str]:
    ips = set()
    # ufw-user-input
    p = _run(["iptables", "-S", "ufw-user-input"], timeout=10)
    if p.returncode == 0:
        for line in p.stdout.splitlines():
            if "-j DROP" not in line:
                continue
            m = re.search(r"-s\s+([0-9\.]+)/?\d*", line)
            if m:
                ip = m.group(1)
                if _valid_ipv4(ip) and ip not in WHITELIST:
                    ips.add(ip)

    # INPUT fallback
    p2 = _run(["iptables", "-S", "INPUT"], timeout=10)
    if p2.returncode == 0:
        for line in p2.stdout.splitlines():
            if "-j DROP" not in line:
                continue
            m = re.search(r"-s\s+([0-9\.]+)/?\d*", line)
            if m:
                ip = m.group(1)
                if _valid_ipv4(ip) and ip not in WHITELIST:
                    ips.add(ip)

    return sorted(ips)


# -----------------------------
# Responder class
# -----------------------------
class Responder:
    def __init__(self, enable_blocking: bool = True, enable_alerts: bool = True, backend: str = DEFAULT_BACKEND):
        self.enable_blocking = enable_blocking
        self.enable_alerts = enable_alerts
        self.backend = (backend or "ufw").lower()
        self.actions_log: List[Action] = []
        self.action_count = 0

    async def respond(self, analysis: Dict) -> Action:
        """
        Exécute l'action recommandée.
        Compatibilité: analysis peut contenir:
          - recommended_action: block/alert/monitor/ignore
          - ip_source OU target
          - message (pour extraire IP si besoin)
        """
        self.action_count += 1

        recommended = analysis.get("recommended_action") or analysis.get("action") or analysis.get("decision")
        action_type = _normalize_action_name(str(recommended or "monitor"))

        ip = (
            analysis.get("ip_source")
            or analysis.get("target")
            or analysis.get("ip")
            or _extract_ip(analysis.get("message", ""))
            or "unknown"
        )
        ip = str(ip)

        event_id = str(analysis.get("event_id", "unknown"))

        action = Action(
            action_id=f"action_{int(datetime.now().timestamp()*1000)}",
            timestamp=_now_iso(),
            event_id=event_id,
            action_type=action_type,
            target=ip,
            success=False,
            details="",
        )

        print(f"\n[RESPONDER] ⚡ Action #{self.action_count}: {action_type.upper()} target={ip} backend={self.backend} dry_run={DRY_RUN}")

        if action_type == "block":
            action = await self._block_ip(action, ip, analysis)
        elif action_type == "alert":
            action = await self._send_alert(action, analysis)
        elif action_type == "ignore":
            action.success = True
            action.details = f"Événement {event_id} ignoré"
        else:
            action.success = True
            action.details = f"Événement {event_id} en surveillance (monitor)"

        self.actions_log.append(action)
        print(f"[RESPONDER] ✓ {action.details}")
        return action

    async def _block_ip(self, action: Action, ip: str, analysis: Dict) -> Action:
        if not self.enable_blocking:
            action.success = True
            action.details = f"[DRY] Blocage désactivé — décision=block pour {ip}"
            return action

        if ip in WHITELIST:
            action.success = False
            action.details = f"IP {ip} whitelistée — blocage annulé"
            return action

        if not _valid_ipv4(ip):
            action.success = False
            action.details = f"IP invalide/unknown — blocage impossible ({ip})"
            return action

        if DRY_RUN:
            action.success = True
            action.details = f"[DRY-RUN] IP {ip} serait bloquée ({self.backend})"
            return action

        try:
            # Backend ufw (recommandé chez toi)
            if self.backend == "ufw":
                if _ufw_rule_exists(ip):
                    action.success = True
                    action.details = f"IP {ip} déjà bloquée (UFW)"
                    return action

                p = _ufw_block_ip(ip)
                if p.returncode == 0:
                    # petite pause pour laisser ufw appliquer
                    await asyncio.sleep(0.05)
                    action.success = True
                    action.details = f" IP {ip} bloquée réellement (UFW: insert 1 deny from {ip})"
                else:
                    action.success = False
                    action.details = f" Échec blocage UFW {ip}: {p.stderr.strip() or p.stdout.strip()}"
                return action

            # Backend iptables (fallback)
            if self.backend == "iptables":
                if _iptables_rule_exists(ip):
                    action.success = True
                    action.details = f"IP {ip} déjà bloquée (iptables)"
                    return action

                p = _iptables_block_ip(ip)
                if p.returncode == 0:
                    action.success = True
                    action.details = f" IP {ip} bloquée réellement (iptables -I ufw-user-input 1 -s {ip} -j DROP)"
                else:
                    action.success = False
                    action.details = f" Échec blocage iptables {ip}: {p.stderr.strip() or p.stdout.strip()}"
                return action

            action.success = False
            action.details = f"Backend blocage inconnu: {self.backend}"
            return action

        except subprocess.TimeoutExpired:
            action.success = False
            action.details = f" Timeout lors du blocage de {ip}"
            return action
        except Exception as e:
            action.success = False
            action.details = f" Exception blocage {ip}: {e}"
            return action

    async def _send_alert(self, action: Action, analysis: Dict) -> Action:
        if not self.enable_alerts:
            action.success = True
            action.details = "Alertes désactivées"
            return action

        threat_type = analysis.get("threat_type", "unknown")
        conf = float(analysis.get("confidence", 0.0) or 0.0)
        await asyncio.sleep(0.01)
        action.success = True
        action.details = f"Alerte envoyée: {threat_type} (confidence {conf:.1%})"
        return action

    def unblock_ip(self, ip: str) -> bool:
        ip = str(ip)
        if not _valid_ipv4(ip):
            print(f"[RESPONDER] IP invalide: {ip}")
            return False

        if DRY_RUN:
            print(f"[RESPONDER] [DRY-RUN] Déblocage simulé: {ip}")
            return True

        try:
            if self.backend == "ufw":
                p = _ufw_unblock_ip(ip)
                ok = (p.returncode == 0)
                print(f"[RESPONDER] {'✅' if ok else '⚠️'} UFW unblock {ip}: {p.stdout.strip() or p.stderr.strip()}")
                return ok

            if self.backend == "iptables":
                p = _iptables_unblock_ip(ip)
                ok = (p.returncode == 0)
                print(f"[RESPONDER] {'✅' if ok else '⚠️'} iptables unblock {ip}: {p.stdout.strip() or p.stderr.strip()}")
                return ok

            print(f"[RESPONDER]  Backend inconnu: {self.backend}")
            return False

        except Exception as e:
            print(f"[RESPONDER]  Exception unblock {ip}: {e}")
            return False

    def get_blocked_ips(self) -> List[str]:
        try:
            if self.backend == "ufw":
                return get_blocked_ips_ufw()
            if self.backend == "iptables":
                return get_blocked_ips_iptables()
        except Exception:
            pass
        # fallback safe
        return []

    def get_stats(self) -> Dict:
        action_types: Dict[str, int] = {}
        for a in self.actions_log:
            action_types[a.action_type] = action_types.get(a.action_type, 0) + 1

        success_rate = (sum(1 for a in self.actions_log if a.success) / len(self.actions_log)) if self.actions_log else 0.0
        blocked = self.get_blocked_ips()

        return {
            "total_actions": self.action_count,
            "action_types": action_types,
            "blocked_ips_count": len(blocked),
            "blocked_ips": blocked,
            "success_rate": success_rate,
            "blocking_enabled": self.enable_blocking,
            "alerts_enabled": self.enable_alerts,
            "backend": self.backend,
            "dry_run": DRY_RUN,
        }

    def export_actions_log(self, filepath: str):
        try:
            with open(filepath, "w") as f:
                json.dump([asdict(a) for a in self.actions_log], f, indent=2, ensure_ascii=False)
            print(f"[RESPONDER] ✓ Export actions -> {filepath}")
        except Exception as e:
            print(f"[RESPONDER]  Export error: {e}")


# -----------------------------
# Standalone test
# -----------------------------
async def main():
    r = Responder(enable_blocking=True, enable_alerts=True, backend=DEFAULT_BACKEND)

    test = {
        "event_id": "evt_test_001",
        "recommended_action": "block",
        "ip_source": "192.168.253.130",
        "threat_type": "ssh_bruteforce",
        "confidence": 0.95,
        "message": "Failed password for invalid user admin from 192.168.253.130 port 52954 ssh2",
    }

    print(json.dumps(r.get_stats(), indent=2, ensure_ascii=False))
    await r.respond(test)
    print("\nBlocked IPs (réel):", r.get_blocked_ips())
    print(json.dumps(r.get_stats(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
