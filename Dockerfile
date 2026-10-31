FROM python:slim-buster

RUN apt-get update && apt-get -y install rsyslog

WORKDIR /usr/src/app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

RUN echo '*.*  action(type="omfwd" target="syslog.koeroo.lan" port="514" protocol="udp")' \
    > /etc/rsyslog.d/10-syslog.koeroo.lan.conf


CMD rsyslogd && python -m pyDANETLSA.monitor --fqdn smtp.koeroo.net --port 25 --protocol SMTP --syslog-ident danetlsa

#ENTRYPOINT [ "cron", "-f" ]

# ENTRYPOINT [ "/bin/bash" ]
#CMD /bin/bash