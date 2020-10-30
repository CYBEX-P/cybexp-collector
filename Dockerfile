FROM cybexp-priv-libs

# setup environment & install dependencies
COPY ./requirements.txt /collector/requirements.txt
RUN pip3 install -r /collector/requirements.txt

# misc
RUN mkdir -p /secrets

# copy collector last
COPY ./collector /collector

WORKDIR /collector
