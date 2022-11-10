FROM golang:1.20 as build

WORKDIR /go/src/webrisk
COPY . .

RUN go mod download
RUN go vet -v
RUN go test -v

RUN CGO_ENABLED=0 go build -o /go/bin/webrisk

FROM gcr.io/distroless/static-debian11

COPY --from=build /go/bin/webrisk /
CMD ["/cmd/wrserver"]
