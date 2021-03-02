FROM python:3.8-alpine

LABEL maintainer="Michael 'Sleventyeleven' Contino"
LABEL version="1.0"

RUN mkdir /app
WORKDIR /app

RUN apk add --update --no-cache docker openrc
RUN rc-update add docker boot

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY harvester.py .

CMD python /app/harvester.py -v