#FROM alpine:3.15
FROM nginx:alpine

COPY index.html /usr/share/nginx/html

RUN mkdir /home/apptest
WORKDIR /home/apptest

# Python
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools
RUN apk add gcc g++ make libffi-dev openssl-dev git
RUN pip3 install pycryptodome
RUN pip3 install requests

# Copy our scripts
COPY entrypoint.sh ./
COPY app_node.py ./
CMD ["/home/apptest/entrypoint.sh"]
