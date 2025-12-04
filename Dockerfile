FROM python:3.10-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc wget tar \
    && rm -rf /var/lib/apt/lists/*

RUN tar --version

RUN mkdir -p /app
WORKDIR /app

RUN rm -f assetfinder-linux-amd64-0.1.1.tgz
RUN wget "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz"
RUN tar -xzvf assetfinder-linux-amd64-0.1.1.tgz
RUN mv assetfinder /usr/bin

COPY . .
RUN pip install -r requirements.txt
CMD ["uwsgi", "--socket", "0.0.0.0:8001", "--protocol", "uwsgi", "-w", "wsgi", "--master", "--processes", "4", "--threads", "2", "--wsgi-file", "/app/websicon/wsgi.py"]