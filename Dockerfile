FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY src ./src
COPY datasets ./datasets
COPY configs ./configs
COPY examples ./examples
COPY docs ./docs

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && adduser --disabled-password --gecos "" --home /nonexistent --no-create-home malleus \
    && mkdir -p /tmp/malleus-demo \
    && chown -R malleus:malleus /tmp/malleus-demo

USER malleus

CMD ["malleus", "info"]
