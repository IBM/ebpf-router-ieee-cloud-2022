FROM gcc:4.9

RUN apt-get update \
 && apt-get --no-install-recommends -y install \
    build-essential make ca-certificates wget libmemcached-tools \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists 

ENV LDFLAGS="-Wl,--copy-dt-needed-entries"
WORKDIR /usr/loca/src/
RUN wget https://launchpad.net/libmemcached/1.0/1.0.18/+download/libmemcached-1.0.18.tar.gz && \
tar xvzf libmemcached-1.0.18.tar.gz && cd libmemcached-1.0.18 && ./configure --enable-memaslap && make && make install

CMD ["/bin/bash", "-c", "tail -f /dev/null"]