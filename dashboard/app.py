#!/usr/bin/env python3
"""
dashboard/app.py
Backend Flask pour le Dashboard SOC IA

- Sert dashboard.html
- Expose /api/*
- Consomme Kafka topic events_raw
- Enrichit via Collector/Analyzer + Ateliers A/C/D
- ✅ Exécute Responder (iptables réel)
- ✅ Affiche IPs bloquées réellement
- ✅ Utilise LM Studio si LMClient est dispo (core/lm_client.py) et SOC_USE_LM=1
- ✅ (MODIF) Ajout XAI + propagation anomaly_score + category/event_type
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import time
import threading
import traceback
import re
import json
from datetime import datetime
from pathlib import Path
import sys
import os
import asyncio

# -----------------------------------------------------------------------------#
# Helpers
# -----------------------------------------------------------------------------#

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def to_jsonable(obj):
    """Convertit numpy/pandas types en types JSON sérialisables (récursif)."""
    try:
        import numpy as np
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.bool_):
            return bool(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
    except Exception:
        pass

    try:
        import pandas as pd
        if isinstance(obj, pd.Timestamp):
            return obj.isoformat()
    except Exception:
        pass

    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]

    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()

    return obj


def now_iso():
    return datetime.now().isoformat()


def extract_ip_from_text(text: str) -> str:
    m = IP_RE.search(text or "")
    return m.group(0) if m else "unknown"


def normalize_kafka_event(msg_value: dict) -> dict:
    """
    Normalise un event venant de Kafka.
    - Filebeat: {"message": "...", "log": {"file":{"path":"..."}} , "@timestamp": ...}
    - LogTailer custom: {"timestamp": "...", "source": "...", "message": "...", "raw_log": "...", "ip_source": "..."}
    """
    if not isinstance(msg_value, dict):
        return {
            "event_id": f"evt_{int(time.time()*1000)}",
            "timestamp": now_iso(),
            "source": "kafka",
            "ip_source": "unknown",
            "message": str(msg_value),
            "severity": "low",
            "metadata": {"ingested_from": "kafka"},
        }

    # custom log_tailer
    if "source" in msg_value and "message" in msg_value and "timestamp" in msg_value:
        ip = msg_value.get("ip_source") or extract_ip_from_text(msg_value.get("message", ""))
        return {
            "event_id": msg_value.get("event_id") or f"evt_{int(time.time()*1000)}",
            "timestamp": msg_value.get("timestamp") or now_iso(),
            "source": msg_value.get("source") or "unknown",
            "ip_source": ip,
            "message": msg_value.get("message") or "",
            "severity": msg_value.get("severity") or "low",
            "metadata": {
                "raw": msg_value.get("raw_log") or msg_value.get("message"),
                "ingested_from": "kafka_custom",
            },
        }

    # filebeat
    message = msg_value.get("message", "")
    src = None
    try:
        src = msg_value.get("log", {}).get("file", {}).get("path")
    except Exception:
        src = None

    ts = msg_value.get("@timestamp") or msg_value.get("timestamp") or now_iso()
    ip = msg_value.get("ip_source") or extract_ip_from_text(message)

    return {
        "event_id": f"evt_{int(time.time()*1000)}",
        "timestamp": ts,
        "source": src or "filebeat",
        "ip_source": ip,
        "message": message,
        "severity": "low",  # recalculé par Collector
        "metadata": {
            "ingested_from": "filebeat",
            "filebeat": {
                "host": (msg_value.get("host") or {}).get("name"),
                "agent": (msg_value.get("agent") or {}).get("version"),
            },
        },
    }


# -----------------------------------------------------------------------------#
# Imports projet (SOC)
# -----------------------------------------------------------------------------#

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.collector import Collector
    from core.analyzer import Analyzer
    from core.responder import Responder
    from atelier_a.trust_agent import TrustAgent
    from atelier_b.supervisor import Supervisor
    from atelier_c.anomaly_detector import AnomalyDetector
    from atelier_d.mitre_mapper import MitreMapper
    from atelier_d.xai_explainer import XAIExplainer
except ImportError as e:
    print(f"[DASHBOARD] Warning: Could not import SOC modules: {e}")
    Collector = Analyzer = Responder = TrustAgent = Supervisor = AnomalyDetector = MitreMapper = XAIExplainer = None

# LM client (LM Studio) - optionnel
try:
    from core.lm_client import LMClient
except Exception:
    LMClient = None

# Kafka consumer (kafka-python)
try:
    from kafka import KafkaConsumer
except ImportError:
    KafkaConsumer = None


# -----------------------------------------------------------------------------#
# Flask / SocketIO init
# -----------------------------------------------------------------------------#

app = Flask(__name__)
app.config["SECRET_KEY"] = "soc-ia-dashboard-secret-2025"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")


# -----------------------------------------------------------------------------#
# Global state
# -----------------------------------------------------------------------------#

dashboard_state = {
    "stats": {
        "events_processed": 0,
        "threats_detected": 0,
        "blocked_ips": 0,          # ✅ sera mis à jour depuis iptables réel
        "avg_latency": 0.0,
        "active_connections": 0,
        "system_status": "operational",
        "start_time": now_iso(),
    },
    "recent_events": [],
    "mitre_stats": {},
    "performance": {"cpu": 0, "memory": 0, "network": 0, "disk": 0},
    "ateliers": {
        "A": {"status": "inactive", "metrics": {}},
        "B": {"status": "inactive", "metrics": {}},
        "C": {"status": "inactive", "metrics": {}},
        "D": {"status": "inactive", "metrics": {}},
    },
}

soc_agents = {
    "collector": None,
    "analyzer": None,
    "responder": None,           # ✅ AJOUT
    "trust_agent": None,
    "supervisor": None,
    "anomaly_detector": None,
    "mitre_mapper": None,
    "xai_explainer": None,
}

RUNNING = True


# -----------------------------------------------------------------------------#
# Routes
# -----------------------------------------------------------------------------#

@app.route("/")
def index():
    return send_from_directory("static", "dashboard.html")


@app.route("/api/stats")
def get_stats():
    return jsonify(to_jsonable(dashboard_state["stats"]))


@app.route("/api/events")
def get_events():
    return jsonify(to_jsonable(dashboard_state["recent_events"]))


@app.route("/api/mitre")
def get_mitre():
    return jsonify(to_jsonable(dashboard_state["mitre_stats"]))


@app.route("/api/performance")
def get_performance():
    return jsonify(to_jsonable(dashboard_state["performance"]))


@app.route("/api/ateliers")
def get_ateliers():
    return jsonify(to_jsonable(dashboard_state["ateliers"]))


@app.route("/api/blocked")
def api_blocked():
    """✅ Liste des IP réellement bloquées."""
    responder = soc_agents.get("responder")
    blocked = []
    if responder is not None:
        try:
            blocked = responder.get_blocked_ips()
        except Exception:
            blocked = []
    return jsonify({"count": len(blocked), "blocked_ips": blocked})


@app.route("/api/health")
def health():
    uptime = (datetime.now() - datetime.fromisoformat(dashboard_state["stats"]["start_time"])).total_seconds()
    return jsonify({"status": "healthy", "timestamp": now_iso(), "uptime": uptime})


# -----------------------------------------------------------------------------#
# WebSocket events
# -----------------------------------------------------------------------------#

@socketio.on("connect")
def handle_connect(auth=None):
    dashboard_state["stats"]["active_connections"] = int(dashboard_state["stats"]["active_connections"]) + 1
    print("[DASHBOARD] Client connecté")
    emit("connection_response", {"data": "Connected to SOC IA Dashboard"})
    emit("state_update", to_jsonable(dashboard_state))


@socketio.on("disconnect")
def handle_disconnect():
    dashboard_state["stats"]["active_connections"] = max(0, int(dashboard_state["stats"]["active_connections"]) - 1)
    print("[DASHBOARD] Client déconnecté")


@socketio.on("request_update")
def handle_request_update(data=None):
    emit("state_update", to_jsonable(dashboard_state))


# -----------------------------------------------------------------------------#
# SOC init
# -----------------------------------------------------------------------------#

def init_soc_agents():
    print("[DASHBOARD] Initialisation SOC agents...")

    # LM Studio (optionnel)
    lm_client = None
    use_lm = os.environ.get("SOC_USE_LM", "0").strip() == "1"
    if use_lm:
        if LMClient is None:
            print("[DASHBOARD] ⚠️ SOC_USE_LM=1 mais LMClient indisponible (core/lm_client.py import fail)")
        else:
            try:
                lm_client = LMClient()
                print("[DASHBOARD] ✓ LMClient actif (LM Studio)")
            except Exception as e:
                print(f"[DASHBOARD] ⚠️ LMClient init fail: {e}")
                lm_client = None

    # Core: Collector + Analyzer
    try:
        if Collector is None or Analyzer is None:
            raise RuntimeError("Collector/Analyzer non importés")
        soc_agents["collector"] = Collector()
        soc_agents["analyzer"] = Analyzer(lm_client=lm_client)  # ✅ LLM si dispo
        print("  ✓ Core: Collector + Analyzer")
    except Exception as e:
        print(f"  ✗ Core init: {e}")

    # ✅ Responder réel (iptables)
    try:
        if Responder is None:
            raise RuntimeError("Responder non importé")
        soc_agents["responder"] = Responder(enable_blocking=True, enable_alerts=True)
        print("  ✓ Core: Responder (iptables réel)")
    except Exception as e:
        print(f"  ✗ Responder init: {e}")

    # Atelier A
    try:
        if TrustAgent is None:
            raise RuntimeError("TrustAgent non importé")
        soc_agents["trust_agent"] = TrustAgent(method="platt")
        dashboard_state["ateliers"]["A"]["status"] = "active"
        print("  ✓ Atelier A: Trust Agent")
    except Exception as e:
        print(f"  ✗ Atelier A: {e}")
        dashboard_state["ateliers"]["A"]["status"] = "error"

    # Atelier B
    try:
        if Supervisor is None:
            raise RuntimeError("Supervisor non importé")
        soc_agents["supervisor"] = Supervisor()
        dashboard_state["ateliers"]["B"]["status"] = "active"
        print("  ✓ Atelier B: Supervisor")
    except Exception as e:
        print(f"  ✗ Atelier B: {e}")
        dashboard_state["ateliers"]["B"]["status"] = "error"

    # Atelier C
    try:
        if AnomalyDetector is None:
            raise RuntimeError("AnomalyDetector non importé")
        soc_agents["anomaly_detector"] = AnomalyDetector(threshold=0.7)
        dashboard_state["ateliers"]["C"]["status"] = "active"
        print("  ✓ Atelier C: Anomaly Detector")
    except Exception as e:
        print(f"  ✗ Atelier C: {e}")
        dashboard_state["ateliers"]["C"]["status"] = "error"

    # Atelier D
    try:
        if MitreMapper is None:
            raise RuntimeError("MitreMapper non importé")
        soc_agents["mitre_mapper"] = MitreMapper()
        dashboard_state["ateliers"]["D"]["status"] = "active"
        print("  ✓ Atelier D: MITRE Mapper")
    except Exception as e:
        print(f"  ✗ Atelier D: {e}")
        dashboard_state["ateliers"]["D"]["status"] = "error"

    # XAI optionnel
    try:
        if XAIExplainer is not None:
            soc_agents["xai_explainer"] = XAIExplainer(lm_client=None, use_llm=False)
            print("  ✓ Atelier D: XAI Explainer")
    except Exception as e:
        print(f"  ⚠️ XAI non dispo: {e}")

    print("[DASHBOARD] ✓ Agents prêts")


def update_atelier_metrics():
    try:
        ta = soc_agents.get("trust_agent")
        if ta is not None:
            dashboard_state["ateliers"]["A"]["metrics"] = {
                "method": getattr(ta, "method", "unknown"),
                "calibrated": bool(getattr(ta, "is_calibrated", False)),
            }

        sup = soc_agents.get("supervisor")
        if sup is not None:
            stats = sup.get_current_stats()
            dashboard_state["ateliers"]["B"]["metrics"] = {
                "throughput": f"{float(stats['throughput']['avg_eps']):.1f} eps",
                "latency": f"{float(stats['latency']['avg_ms']):.1f} ms",
                "alerts": int(stats["alerts"]["total"]),
                "status": stats["status"],
            }
            dashboard_state["stats"]["system_status"] = "operational" if stats["status"] == "healthy" else "alert"

        ad = soc_agents.get("anomaly_detector")
        if ad is not None and hasattr(ad, "get_stats"):
            cstats = ad.get_stats()
            dashboard_state["ateliers"]["C"]["metrics"] = {
                "threshold": float(getattr(ad, "threshold", 0.7)),
                "anomalies": int(cstats.get("anomalies_detected", 0)),
                "anomaly_rate": float(cstats.get("anomaly_rate", 0.0)),
            }

        mm = soc_agents.get("mitre_mapper")
        if mm is not None and hasattr(mm, "generate_coverage_report"):
            coverage = mm.generate_coverage_report()
            dashboard_state["ateliers"]["D"]["metrics"] = {
                "coverage": f"{float(coverage.get('coverage', 0.0)) * 100:.0f}%",
                "techniques": coverage.get("detected_techniques", 0),
            }
            dashboard_state["mitre_stats"] = to_jsonable(coverage)

        # ✅ blocked ips (réel) - refresh régulier
        responder = soc_agents.get("responder")
        if responder is not None:
            try:
                blocked = responder.get_blocked_ips()
                dashboard_state["stats"]["blocked_ips"] = int(len(blocked))
            except Exception:
                pass

    except Exception:
        traceback.print_exc()


def add_event(event_payload: dict):
    event_payload = to_jsonable(event_payload)
    dashboard_state["recent_events"].insert(0, event_payload)
    dashboard_state["recent_events"] = dashboard_state["recent_events"][:50]

    dashboard_state["stats"]["events_processed"] = int(dashboard_state["stats"]["events_processed"]) + 1
    if event_payload.get("threat_detected"):
        dashboard_state["stats"]["threats_detected"] = int(dashboard_state["stats"]["threats_detected"]) + 1

    socketio.emit("new_event", event_payload)
    socketio.emit("stats_update", to_jsonable(dashboard_state["stats"]))


# -----------------------------------------------------------------------------#
# Kafka consumer loop -> SOC pipeline -> WebSocket
# -----------------------------------------------------------------------------#

def kafka_consumer_loop():
    if KafkaConsumer is None:
        print("[DASHBOARD] ❌ kafka-python non installé. Fais: pip install kafka-python")
        return

    bootstrap = os.environ.get("SOC_KAFKA_BOOTSTRAP", "localhost:9093")
    topic = os.environ.get("SOC_KAFKA_TOPIC", "events_raw")
    group_id = os.environ.get("SOC_KAFKA_GROUP", "soc_dashboard")

    print(f"[DASHBOARD] 🔌 Kafka consumer: bootstrap={bootstrap} topic={topic} group={group_id}")

    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=bootstrap,
        group_id=group_id,
        enable_auto_commit=True,
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8", errors="ignore")),
        consumer_timeout_ms=1000,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while RUNNING:
        try:
            for msg in consumer:
                raw = msg.value
                event = normalize_kafka_event(raw)

                start = time.time()
                collector = soc_agents.get("collector")
                analyzer = soc_agents.get("analyzer")
                anomaly = soc_agents.get("anomaly_detector")
                trust = soc_agents.get("trust_agent")
                mitre = soc_agents.get("mitre_mapper")
                responder = soc_agents.get("responder")
                sup = soc_agents.get("supervisor")
                explainer = soc_agents.get("xai_explainer")

                if collector is None or analyzer is None:
                    out = {
                        "type": "raw_event",
                        "timestamp": event["timestamp"],
                        "ip_source": event["ip_source"],
                        "confidence": 0.0,
                        "action": "monitor",
                        "threat_detected": False,
                        "message": event["message"],
                    }
                    add_event(out)
                    continue

                # 1) Collector (async)
                normalized = loop.run_until_complete(collector.process(event))

                # 2) Anomaly
                anomaly_score = None
                if anomaly is not None:
                    ares = anomaly.analyze(normalized)
                    anomaly_score = ares.get("anomaly_score")
                    normalized["anomaly_score"] = anomaly_score

                # 3) Analyzer (async)
                analysis = loop.run_until_complete(analyzer.analyze(normalized))

                # ✅ (MODIF) Propager anomaly_score dans analysis (utile XAI/UI)
                try:
                    analysis.anomaly_score = anomaly_score
                except Exception:
                    pass

                # 4) Trust calibration
                if trust is not None and getattr(trust, "is_calibrated", False):
                    try:
                        analysis.calibrated_confidence = trust.adjust_confidence(analysis.confidence)
                        analysis.confidence = analysis.calibrated_confidence
                    except Exception:
                        pass

                # 5) MITRE
                mitre_dict = None
                if mitre is not None:
                    try:
                        mitre_obj = mitre.map_to_mitre(normalized)
                        if mitre_obj:
                            mitre_dict = {
                                "id": mitre_obj.id,
                                "name": mitre_obj.name,
                                "tactic": mitre_obj.tactic,
                            }
                            analysis.mitre_technique = mitre_obj.id
                    except Exception:
                        mitre_dict = None

                # 5.5) ✅ (MODIF) XAI
                xai_summary = None
                xai_details = None
                if explainer is not None:
                    try:
                        analysis_for_xai = {
                            "threat_detected": bool(getattr(analysis, "threat_detected", False)),
                            "confidence": float(getattr(analysis, "confidence", 0.0)),
                            "calibrated_confidence": float(
                                getattr(analysis, "calibrated_confidence", getattr(analysis, "confidence", 0.0))
                            ),
                            "threat_type": getattr(analysis, "threat_type", None),
                            "recommended_action": getattr(analysis, "recommended_action", "monitor"),
                            "heuristic_score": float(getattr(analysis, "heuristic_score", 0.0)),
                            "llm_score": float(getattr(analysis, "llm_score", 0.0)),
                        }
                        xai_obj = loop.run_until_complete(
                            explainer.explain(normalized, analysis_for_xai, mitre_dict, anomaly_score)
                        )
                        xai_summary = xai_obj.get("summary")
                        xai_details = xai_obj.get("detailed_explanation")
                    except Exception:
                        xai_summary = None
                        xai_details = None

                # 6) ✅ Responder réel (iptables)
                action_obj = None
                if responder is not None:
                    try:
                        analysis_dict = {
                            "event_id": getattr(analysis, "event_id", normalized.get("event_id", "unknown")),
                            "ip_source": normalized.get("ip_source"),
                            "threat_detected": bool(getattr(analysis, "threat_detected", False)),
                            "confidence": float(getattr(analysis, "confidence", 0.0)),
                            "threat_type": getattr(analysis, "threat_type", None),
                            "recommended_action": getattr(analysis, "recommended_action", "monitor"),
                        }
                        action_obj = loop.run_until_complete(responder.respond(analysis_dict))
                    except Exception:
                        traceback.print_exc()
                        action_obj = None

                # 7) Supervisor latency
                if sup is not None:
                    try:
                        sup.record_latency((time.time() - start) * 1000)
                        dashboard_state["stats"]["avg_latency"] = float(sup.get_current_stats()["latency"]["avg_ms"])
                    except Exception:
                        pass

                # 8) ✅ blocked ips compteur réel
                if responder is not None:
                    try:
                        blocked = responder.get_blocked_ips()
                        dashboard_state["stats"]["blocked_ips"] = int(len(blocked))
                    except Exception:
                        pass

                # event_type pour UI
                try:
                    event_type = normalized.get("metadata", {}).get("extracted_info", {}).get("event_type")
                except Exception:
                    event_type = None

                # ✅ (MODIF) category pour UI
                try:
                    category = normalized.get("metadata", {}).get("category")
                except Exception:
                    category = None

                payload = {
                    "type": getattr(analysis, "threat_type", None) or event_type or "event",
                    "timestamp": normalized.get("timestamp"),
                    "ip_source": normalized.get("ip_source"),
                    "confidence": float(getattr(analysis, "confidence", 0.0)),
                    "action": getattr(analysis, "recommended_action", "monitor"),
                    "threat_detected": bool(getattr(analysis, "threat_detected", False)),
                    "severity": normalized.get("severity", "low"),
                    "message": normalized.get("message", ""),
                    "anomaly_score": float(anomaly_score) if anomaly_score is not None else None,
                    "mitre": mitre_dict,

                    # ✅ (MODIF) category/event_type (réduit unknown côté UI)
                    "category": category,
                    "event_type": event_type,

                    # ✅ (MODIF) XAI
                    "xai": {"summary": xai_summary, "details": xai_details},

                    "responder": {
                        "success": bool(getattr(action_obj, "success", False)) if action_obj else None,
                        "details": getattr(action_obj, "details", None) if action_obj else None,
                    },
                }

                add_event(payload)
                update_atelier_metrics()
                socketio.emit("ateliers_update", to_jsonable(dashboard_state["ateliers"]))
                socketio.emit("performance_update", to_jsonable(dashboard_state["performance"]))

        except Exception as e:
            print(f"[DASHBOARD] ❌ Erreur consumer Kafka: {e}")
            traceback.print_exc()
            time.sleep(1)

    try:
        consumer.close()
    except Exception:
        pass


# -----------------------------------------------------------------------------#
# Performance loop
# -----------------------------------------------------------------------------#

def update_performance_loop():
    while RUNNING:
        try:
            import psutil
            dashboard_state["performance"]["cpu"] = float(psutil.cpu_percent(interval=1))
            dashboard_state["performance"]["memory"] = float(psutil.virtual_memory().percent)
            dashboard_state["performance"]["disk"] = float(psutil.disk_usage("/").percent)

            socketio.emit("performance_update", to_jsonable(dashboard_state["performance"]))
        except Exception:
            traceback.print_exc()

        time.sleep(2)


# -----------------------------------------------------------------------------#
# Start
# -----------------------------------------------------------------------------#

def start_dashboard(host="0.0.0.0", port=5000, debug=False):
    print("\n" + "=" * 70)
    print("🚀 SOC IA DASHBOARD")
    print("=" * 70)

    init_soc_agents()

    t_perf = threading.Thread(target=update_performance_loop, daemon=True)
    t_perf.start()

    t_kafka = threading.Thread(target=kafka_consumer_loop, daemon=True)
    t_kafka.start()

    print(f"\n📊 Dashboard accessible sur: http://{host}:{port}")
    print("📡 WebSocket actif pour mises à jour en temps réel")
    print(f"🔧 Mode debug: {debug}")
    print("\n" + "=" * 70 + "\n")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC IA Dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    start_dashboard(host=args.host, port=args.port, debug=args.debug)
