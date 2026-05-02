# Imagen slim, multi-stage no es necesario aquí (todo es Python puro)
FROM python:3.12-slim

# Buenas prácticas: no correr como root
RUN useradd -m -u 1000 app
WORKDIR /app

# Instalar dependencias primero (mejor cache de capas)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY --chown=app:app . .

USER app

# Cloud Run inyecta $PORT (default 8080). Gunicorn con workers async para IO-bound (BQ inserts).
# 1 worker x 8 threads suele ser óptimo para Cloud Run; ajusta según CPU asignada.
ENV PORT=8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 60 main:app
