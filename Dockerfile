FROM golang:alpine


WORKDIR /go/src/webrisk


RUN apk add --update --no-cache git


# Gets the Proxy server binary
RUN go get github.com/google/webrisk/cmd/wrserver


# If you want to run a container with a different API KEY you can just
# pass this variable as `docker run` argument:
# docker run -e WR_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXX
ARG WR_API_KEY


# If you want to change the Proxy server port you can pass this
# variable as `docker run` argument:
# docker run -e WR_PROXY_PORT=5000
ARG WR_PROXY_PORT


# In case no WR_PROXY_PORT is informed, default value is 8080
ENV WR_PROXY_PORT=8080


# Runs the WebRisk Proxy Server
CMD /go/bin/wrserver \
        -apikey=${WR_API_KEY} \
        -srvaddr=0.0.0.0:${WR_PROXY_PORT} \
        -db=/tmp/webrisk.db
