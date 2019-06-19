FROM uhhiss/broker-docker:latest

EXPOSE 21 22 23 25 80 110 143 443 587 993 995

RUN echo "===> Installing build-dependencies..." \
    && apk add --no-cache -t .build-deps \
    g++ \
    python3-dev \
    libffi-dev \
    openssl-dev

WORKDIR /app

COPY requirements.txt /app
RUN echo "===> Installing python dependencies via pip..." \
    && pip3 install -r requirements.txt

RUN echo "===> Purging build-dependencies..." \
    && apk del --purge .build-deps

RUN echo "===> Preparing honeygrove runtime folders..." \
    && bash -c "mkdir -p /var/honeygrove/{logs,resources/{quarantine,honeytoken_files}}"
COPY resources /var/honeygrove/resources

RUN echo "===>  Copying honeygrove sources..."
COPY honeygrove /app/honeygrove

ENTRYPOINT ["python3"]
CMD ["-m", "honeygrove"]
