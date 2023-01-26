FROM python:latest
WORKDIR /usr/app/
COPY ./src ./
RUN pip install coloredlogs
RUN pip install requests
ENTRYPOINT ["python","./victim.py"]