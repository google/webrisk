FROM golang:1.19 as build

WORKDIR /go/src/webrisk

# cache go.mod to pre-download dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go vet -v
RUN go test -v

RUN CGO_ENABLED=0 go build -o /go/bin/webrisk

FROM gcr.io/distroless/static-debian11

COPY --from=build /go/bin/webrisk /
CMD ["/cmd/wrserver"]
