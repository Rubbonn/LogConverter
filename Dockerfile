FROM alpine:latest
COPY ./* /app
WORKDIR /app
RUN mkdir /data && apk update && apk add --no-cache python3 gcc python3-dev linux-headers musl-dev py3-pip && pip install -r requirements.txt --break-system-packages
WORKDIR /data
ENTRYPOINT ["python3", "/app/LogConverter.py"]