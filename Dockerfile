FROM python:3.9.22-slim-bullseye

WORKDIR /app

COPY  /app . 

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

CMD ["flask", "run", "--host=0.0.0.0"]

