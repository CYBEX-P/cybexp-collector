FROM cybexp-priv-libs

# setup environment & install dependencies
COPY ./requirements.txt /collector/requirements.txt
RUN pip3 install -r /collector/requirements.txt

# misc
RUN mkdir -p /secrets

# COPY ./tahoe-honeypot.jsonl /collector/tahoe-honeypot.jsonl

# copy collector,config last
COPY ./collector /collector
# COPY ./config.yaml /collector/config.yaml


WORKDIR /collector
EXPOSE 8080

ENTRYPOINT ["/usr/bin/python3", "-u", "/collector/collector.py"] 
