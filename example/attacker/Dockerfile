# syntax=docker/dockerfile:1

# Adapted from https://docs.docker.com/language/python/build-images/

FROM python:3.8-slim-buster

RUN apt-get update
RUN apt-get install -y tcpdump iproute2 libpcap-dev

WORKDIR /app

COPY src/Pipfile Pipfile
COPY src/Pipfile.lock Pipfile.lock

RUN pip install pipenv
RUN pipenv install --system --deploy

COPY src/attacker.py attacker.py

ENTRYPOINT [ "python3", "attacker.py" ]
