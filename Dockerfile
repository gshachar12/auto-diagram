FROM python:3.12-slim

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    AUTO_DIAGRAM_WORKDIR=/data/auto-diagram


RUN mkdir -p "$AUTO_DIAGRAM_WORKDIR"

COPY requirements.txt ./

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

VOLUME ["/data/auto-diagram"]

EXPOSE 8501

CMD ["streamlit", "run", "src/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
