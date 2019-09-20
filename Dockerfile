FROM tiangolo/uwsgi-nginx-flask:python2.7


COPY ./app /app
COPY ./binary/monitor64 /app/chall
COPY ./binary/syscall64.txt /var/tmp/syscall64.txt
COPY ./binary/flag /app/flag

RUN mkdir /var/tmp/bin
 