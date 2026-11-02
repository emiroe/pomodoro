FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" "psycopg[binary]" psycopg_pool
COPY app/ /srv/
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
