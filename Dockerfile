FROM python:3.13-trixie
COPY . /app
WORKDIR /data
RUN pip install -U --no-cache-dir pip setuptools \
    && pip install -U --no-cache-dir -r /app/requirements.txt
ENTRYPOINT ["python3", "/app/LogConverter.py"]