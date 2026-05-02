"""
Cloud Run service: recibe Pub/Sub push messages, parsea, escribe a BigQuery.

Pub/Sub push manda un POST con este body (la `data` viene en base64):
{
  "message": {
    "data": "<base64 del log>",
    "messageId": "...",
    "publishTime": "...",
    "attributes": {"source_host": "10.0.0.5"}  # opcional
  },
  "subscription": "projects/X/subscriptions/Y"
}

Reglas de respuesta a Pub/Sub:
  - 2xx → mensaje ACK (no se reintenta)
  - 4xx/5xx → mensaje NACK (Pub/Sub reintenta con backoff)

Por eso devolvemos 200 incluso si el log es "no parseable":
ya lo guardamos como vendor='unknown' y reintentar no ayudaría.
Solo devolvemos 5xx ante fallos transitorios (BQ caído, etc.).
"""
import base64
import json
import logging
import os
from flask import Flask, request, jsonify

from parsers import parse_log
from bq_writer import insert_rows

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
        logger.warning("Mensaje Pub/Sub inválido: %s", envelope)
        return jsonify({"error": "invalid envelope"}), 400

    message = envelope["message"]
    msg_id = message.get("messageId", "?")
    attributes = message.get("attributes", {}) or {}

    # Decodificar el log crudo (Pub/Sub manda data en base64)
    try:
        raw_log = base64.b64decode(message.get("data", "")).decode("utf-8", errors="replace")
    except Exception as e:
        logger.error("No pude decodificar mensaje %s: %s", msg_id, e)
        # Datos corruptos: ACK para que no reintente eternamente
        return "", 200

    if not raw_log.strip():
        return "", 200  # mensaje vacío, ACK silencioso

    # Parsear
    parsed = parse_log(raw_log)

    # Enriquecer con metadata del Pub/Sub si vino
    if "source_host" in attributes:
        parsed.extra["source_host"] = attributes["source_host"]

    # Escribir a BQ
    try:
        insert_rows([parsed.to_bq_row()])
    except Exception as e:
        logger.error("Error escribiendo a BQ msg=%s: %s", msg_id, e)
        # Error transitorio: 5xx → Pub/Sub reintenta
        return jsonify({"error": str(e)}), 503

    logger.info("Procesado msg=%s vendor=%s src=%s",
                msg_id, parsed.vendor, parsed.source_ip)
    return "", 200


if __name__ == "__main__":
    # Solo para debug local; en Cloud Run usa gunicorn (ver Dockerfile)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
