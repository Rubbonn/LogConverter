FROM python:3.13-trixie
COPY . /app
WORKDIR /data
RUN pip install -r /app/requirements.txt --break-system-packages
ENTRYPOINT ["python3", "/app/LogConverter.py"]