"""
Cloud Run service: passthrough de Pub/Sub a BigQuery.

DISEÑO:
  - NO parsea el contenido del log (eso lo hace LookML después)
  - Solo decodifica el mensaje base64 de Pub/Sub
  - Lo guarda crudo en BigQuery con un timestamp de ingesta
  - Esto da máxima flexibilidad: los analistas ajustan regex en LookML
    sin necesitar redeploys

Pub/Sub push manda un POST con esta estructura:
{
  "message": {
    "data": "<base64 del log>",
    "messageId": "...",
    "publishTime": "...",
    "attributes": {...}
  },
  "subscription": "projects/X/subscriptions/Y"
}

Reglas de respuesta:
  - 2xx → Pub/Sub hace ACK (no reintenta)
  - 5xx → Pub/Sub hace NACK (reintenta con backoff hasta el DLQ)
"""
import base64
import logging
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify

from bq_writer import insert_row

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/", methods=["POST"])
def pubsub_push():
    envelope = request.get_json(silent=True)
    if not envelope or "message" not in envelope:
        logger.warning("Mensaje Pub/Sub inválido")
        return jsonify({"error": "invalid envelope"}), 400

    message = envelope["message"]
    msg_id = message.get("messageId", "?")

    # Decodificar el log crudo (Pub/Sub envía data en base64)
    try:
        raw_log = base64.b64decode(message.get("data", "")).decode("utf-8", errors="replace")
    except Exception as e:
        logger.error("Error decodificando msg=%s: %s", msg_id, e)
        # Datos corruptos: ACK para no reintentar eternamente
        return "", 200

    if not raw_log.strip():
        return "", 200  # mensaje vacío, ACK silencioso

    # Insertar tal cual en BQ — sin parsear
    try:
        insert_row({
            "ingest_timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_log": raw_log,
        })
    except Exception as e:
        logger.error("Error escribiendo a BQ msg=%s: %s", msg_id, e)
        return jsonify({"error": str(e)}), 503

    logger.info("Procesado msg=%s len=%d", msg_id, len(raw_log))
    return "", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
