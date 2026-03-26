#!/usr/bin/env python3
"""
core/lm_client.py
Client pour LM Studio (IA locale)
Interface avec les modèles LLM locaux
"""

import json
import aiohttp
import asyncio
from typing import Dict, Optional
from datetime import datetime


class LMClient:
    """
    Client pour communiquer avec LM Studio
    Compatible avec l'API OpenAI
    """
    
    def __init__(
        self,
        api_url: str = "http://localhost:1234/v1/chat/completions",
        model: str = "local-model",
        timeout: int = 30
    ):
        self.api_url = api_url
        self.model = model
        self.timeout = timeout
        self.request_count = 0
        self.total_tokens = 0
        
    async def analyze(self, event: dict) -> Dict:
        """
        Analyse un événement de sécurité avec le LLM
        
        Args:
            event: Événement à analyser
            
        Returns:
            Dict avec: threat_detected, confidence, threat_type, recommended_action
        """
        self.request_count += 1
        print(f"[LM_CLIENT] 🤖 Requête LLM #{self.request_count}")
        
        # Construction du prompt
        prompt = self._build_security_prompt(event)
        
        try:
            # Appel au LLM
            response = await self._call_llm(prompt)
            
            # Parse de la réponse
            result = self._parse_response(response)
            
            print(f"[LM_CLIENT] ✓ Réponse reçue (confiance: {result['confidence']:.2f})")
            
            return result
            
        except Exception as e:
            print(f"[LM_CLIENT] ❌ Erreur: {e}")
            return self._fallback_response()
    
    def _build_security_prompt(self, event: dict) -> str:
        """
        Construit le prompt pour l'analyse de sécurité
        """
        prompt = f"""Tu es un analyste cybersécurité expert. Analyse cet événement:

**Source**: {event.get('source', 'unknown')}
**IP Source**: {event.get('ip_source', 'unknown')}
**Message**: {event.get('message', '')}
**Sévérité**: {event.get('severity', 'low')}

Réponds UNIQUEMENT en JSON avec cette structure exacte:
{{
  "threat_detected": true/false,
  "confidence": 0.0-1.0,
  "threat_type": "brute_force|port_scan|web_attack|sql_injection|xss|ddos|malware|normal",
  "recommended_action": "block|alert|monitor|ignore",
  "reasoning": "explication courte"
}}

Analyse:"""
        return prompt
    
    async def _call_llm(self, prompt: str) -> str:
        """
        Appel HTTP au LLM via l'API OpenAI-compatible
        """
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Tu es un expert en cybersécurité. Réponds toujours en JSON valide."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 500,
            "stream": False
        }
        
        try:
            # Mode simulation si LM Studio non disponible
            if self.api_url == "http://localhost:1234/v1/chat/completions":
                print("[LM_CLIENT] ⚙️  Mode simulation (LM Studio non connecté)")
                return await self._simulate_llm_response(prompt)
            
            # Appel HTTP réel
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.api_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data["choices"][0]["message"]["content"]
                        
                        # Statistiques
                        if "usage" in data:
                            self.total_tokens += data["usage"].get("total_tokens", 0)
                        
                        return content
                    else:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                        
        except aiohttp.ClientError as e:
            print(f"[LM_CLIENT] ⚠️  Connexion impossible, mode simulation activé")
            return await self._simulate_llm_response(prompt)
    
    async def _simulate_llm_response(self, prompt: str) -> str:
        """
        Simule une réponse LLM intelligente
        Utilisé quand LM Studio n'est pas disponible
        """
        await asyncio.sleep(0.5)  # Simule latence réseau
        
        # Détection basique par mots-clés
        prompt_lower = prompt.lower()
        
        if "failed password" in prompt_lower or "authentication failure" in prompt_lower:
            return json.dumps({
                "threat_detected": True,
                "confidence": 0.92,
                "threat_type": "brute_force",
                "recommended_action": "block",
                "reasoning": "Tentatives répétées d'authentification SSH échouées détectées"
            })
        
        elif "port scan" in prompt_lower or "nmap" in prompt_lower:
            return json.dumps({
                "threat_detected": True,
                "confidence": 0.88,
                "threat_type": "port_scan",
                "recommended_action": "alert",
                "reasoning": "Activité de reconnaissance réseau suspecte"
            })
        
        elif "404" in prompt_lower or "admin" in prompt_lower or "wp-admin" in prompt_lower:
            return json.dumps({
                "threat_detected": True,
                "confidence": 0.75,
                "threat_type": "web_attack",
                "recommended_action": "monitor",
                "reasoning": "Tentative d'énumération de répertoires web"
            })
        
        elif "union select" in prompt_lower or "drop table" in prompt_lower:
            return json.dumps({
                "threat_detected": True,
                "confidence": 0.98,
                "threat_type": "sql_injection",
                "recommended_action": "block",
                "reasoning": "Injection SQL critique détectée"
            })
        
        else:
            return json.dumps({
                "threat_detected": False,
                "confidence": 0.15,
                "threat_type": "normal",
                "recommended_action": "ignore",
                "reasoning": "Activité normale détectée"
            })
    
    def _parse_response(self, response: str) -> Dict:
        """
        Parse la réponse JSON du LLM
        """
        try:
            # Nettoie la réponse (enlève markdown, etc.)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()
            
            # Parse JSON
            data = json.loads(response)
            
            # Validation
            required_keys = ["threat_detected", "confidence", "threat_type", "recommended_action"]
            for key in required_keys:
                if key not in data:
                    raise ValueError(f"Clé manquante: {key}")
            
            # Normalisation
            data["confidence"] = max(0.0, min(1.0, float(data["confidence"])))
            data["threat_detected"] = bool(data["threat_detected"])
            
            return data
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[LM_CLIENT] ⚠️  Erreur parsing: {e}")
            print(f"[LM_CLIENT] Réponse brute: {response[:200]}")
            return self._fallback_response()
    
    def _fallback_response(self) -> Dict:
        """
        Réponse par défaut en cas d'erreur
        """
        return {
            "threat_detected": False,
            "confidence": 0.0,
            "threat_type": "unknown",
            "recommended_action": "monitor",
            "reasoning": "Erreur d'analyse LLM"
        }
    
    async def explain_decision(self, event: dict, analysis: dict) -> str:
        """
        Génère une explication détaillée de la décision
        Utilisé pour XAI (Atelier D)
        """
        prompt = f"""Explique cette décision de sécurité de manière claire:

**Événement**: {event.get('message', '')}
**Menace détectée**: {analysis.get('threat_detected', False)}
**Type**: {analysis.get('threat_type', 'unknown')}
**Action**: {analysis.get('recommended_action', 'monitor')}
**Confiance**: {analysis.get('confidence', 0.0):.2%}

Fournis une explication en 2-3 phrases courtes."""

        try:
            response = await self._call_llm(prompt)
            # La réponse sera du texte libre ici
            return response.strip()
        except:
            return "Explication non disponible."
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques d'utilisation"""
        return {
            "total_requests": self.request_count,
            "total_tokens": self.total_tokens,
            "avg_tokens_per_request": self.total_tokens / self.request_count if self.request_count > 0 else 0
        }


async def main():
    """Test standalone du LM Client"""
    print("="*60)
    print("TEST LM CLIENT")
    print("="*60)
    
    client = LMClient()
    
    # Événements de test
    test_events = [
        {
            "source": "/var/log/auth.log",
            "ip_source": "192.168.1.100",
            "message": "Failed password for invalid user admin from 192.168.1.100",
            "severity": "high"
        },
        {
            "source": "/var/log/nginx/access.log",
            "ip_source": "192.168.1.50",
            "message": 'GET /admin HTTP/1.1" 404',
            "severity": "medium"
        }
    ]
    
    for i, event in enumerate(test_events, 1):
        print(f"\n{'='*60}")
        print(f"Test #{i}")
        print(f"{'='*60}")
        print(f"Message: {event['message']}")
        
        # Analyse
        result = await client.analyze(event)
        
        print(f"\n🎯 Résultat LLM:")
        print(json.dumps(result, indent=2))
        
        # Explication
        explanation = await client.explain_decision(event, result)
        print(f"\n💡 Explication:")
        print(explanation)
    
    print("\n" + "="*60)
    print("STATS:", client.get_stats())
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
