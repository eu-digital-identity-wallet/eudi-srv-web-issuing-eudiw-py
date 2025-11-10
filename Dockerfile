FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

RUN pip install --no-cache-dir -r app/requirements.txt

# Create required directories for certificates and keys
RUN mkdir -p /etc/eudiw/pid-issuer-dev/cert/ \
    /etc/eudiw/pid-issuer-dev/privKey/ 
    
ENV FLASK_APP=app

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]