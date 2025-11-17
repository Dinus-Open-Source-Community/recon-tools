FROM python:3.10-alpine3.22

RUN apk add --update \
    curl \
    && rm -rf /var/cache/apk/*

RUN apk --no-cache add wget
RUN apk --no-cache add tar

RUN tar --version

RUN mkdir -p /app
WORKDIR /app

RUN rm -f assetfinder-linux-amd64-0.1.1.tgz
RUN wget "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz"
RUN tar -xzvf assetfinder-linux-amd64-0.1.1.tgz
RUN mv assetfinder /usr/bin

COPY . .
RUN pip install -r requirements.txt
CMD [ "python", "manage.py", "runserver", "0.0.0.0:9099" ]