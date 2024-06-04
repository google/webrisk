# Web Risk Client App | Container & Go

[Web Risk](https://cloud.google.com/web-risk) is the enterprise version of
Google's [Safe Browsing API](https://safebrowsing.google.com/) that protects 5 
Billion devices globally from dangerous URLs including phishing, malware,
unwanted software, and social engineering.

This client implements the Web Risk [Update API](https://cloud.google.com/web-risk/docs/update-api),
which allows for URLs to be checked for badness via privacy-preserving and
low-latency API. It works out-of-the-box via either Docker or Go.

This README provides a quickstart guide to running a client either with Docker
or as Go binaries. It also serves as a reference implementation of the API. The
GoDoc and API documentation in the `.go` source files provide more details on
fine-tuning the parameters if desired.

Supported clients:

- `wrserver` runs a thin HTTP client that can query URLs via a POST request or
a redirection endpoint that diverts bad URLs to a warning page. This is the
client wrapped by Docker.
- `wrlookup` is a command line service that takes URLs from `STDIN` and outputs results to `STDOUT`. It can
accept multiple URLs at a time on separate lines.

Supported blocklists:

 - `MALWARE`
 - `UNWANTED_SOFTWARE`
 - `SOCIAL_ENGINEERING`
 - [`SOCIAL_ENGINEERING_EXTENDED_COVERAGE`](https://cloud.google.com/web-risk/docs/extended-coverage)

The client is originally forked from the [Safebrowsing Go Client](https://github.com/google/safebrowsing).

# Enable Web Risk

To begin using Web Risk, you will need a [GCP](https://cloud.google.com/) 
Account and a project to work in.

1. Enable the [Web Risk API](https://console.cloud.google.com/marketplace/product/google/webrisk.googleapis.com).

2. [Create an API Key](https://console.cloud.google.com/apis/credentials).

3. [Enable Billing](https://console.cloud.google.com/billing) for your account
and make sure it's linked to your project.

# Install Docker and/or Go

To use the Container App, you will need [Docker](https://www.docker.com/). To
compile binaries from source or run tests install [Go](https://go.dev/).

# Docker Quickstart (recommended)

We have included a Dockerfile to accelerate and simplify onboarding. This
container wraps the `wrserver` binary detailed [below](#using-wrserver).

## Clone and Build Container

Building the container is straightforward.

First, clone this repo into a local directory.

```
git clone https://github.com/google/webrisk && cd webrisk
```

Build the container. This will run all tests before compiling `wrserver` into
a distroless container.
```
docker build --tag wr-container .
```

## Run Container

We supply the `APIKEY` as an environmental variable to the container at runtime
so that the API Key is not revealed as part of the docker file or in `docker ps`.
This example also provides a port binding.

```
docker run -e APIKEY=XXXXXXXXXXXXXXXXXXXXXXX -p 8080:8080 wr-container
```

`wrserver` defaults to port 8080, but you can bind any port on the host machine.
See the [Docker documentation](https://docs.docker.com/config/containers/container-networking/)
for details.

See [Using `wrserver`](#using-wrserver) below for how to query URLs or use the
redirection endpoint.

# Go Binary Quickstart | `wrlookup` example

The Go Client can be compiled and run directly without Docker. In this example
we will use that to run the `wrlookup` binary that takes URLs from `STDIN` and
outputs to `STDOUT`.

Before compiling from source you should [install Go](https://go.dev/doc/install)
and have some familiarity with Go development. See [here](https://go.dev/doc/tutorial/getting-started)
for a good place to get started.

## Clone Source & Install Dependencies

To download and install this branch from the source, run the following commands.

First clone this repo into a local directory and switch to the webrisk
directory.

```
git clone https://github.com/google/webrisk && cd webrisk
```

Next, install dependencies.

```
go install .
```

## Build and Execute `wrlookup`

After installing dependencies, you can build and run `wrlookup`

```
go build -o wrlookup cmd/wrlookup/main.go
```

Run the binary and supply an API key.

```
./wrlookup -apikey=XXXXXXXXXXXXXXXXXXXXXXX
```

You should see some output similar to below as `wrlookup` starts up.

```
webrisk: 2023/01/27 19:36:46 database.go:110: no database file specified
webrisk: 2023/01/27 19:36:53 database.go:384: database is now healthy
webrisk: 2023/01/27 19:36:53 webrisk_client.go:492: Next update in 30m29s
```

`wrlookup` will take any URLs from `STDIN`. Test your configuration with a sample:

```
http://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html #input
Unsafe URL: [SOCIAL_ENGINEERING_EXTENDED_COVERAGE] # output
```

# Using `wrserver`

`wrserver` runs a WebRisk API lookup proxy that allows users to check URLs via
a simple JSON API. This local API will use the API key supplied by the Docker
container or the command line that runs the binary.

First start the `wrserver` by either running the container or binary.

To run in Docker:

```
docker run -e APIKEY=XXXXXXXXXXXXXXXXXXXXXXX -p 8080:8080 <container_name>
```

To run from a CLI, compile as [`wrlookup`](#build-and-execute-wrlookup) above
and run:

```
./wrserver -apikey=XXXXXXXXXXXXXXXXXXXXXXX
```

With the default settings this will start a local server at **0.0.0.0:8080**.

The server has a lightweight implementation of a
[Web Risk Lookup API](https://cloud.google.com/web-risk/docs/lookup-api)-like
endpoint at `v1/uris:search`. To use the local endpoint to check a URL, send a
POST request to `0.0.0.0:8080/v1/uris:search` with the a JSON body similar to
the following.

```json
{
  "uri":"http://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html"
}
```

A sample cURL command:

```
curl -H 'Content-Type: application/json' \
	-d '{"uri":"http://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html"}' \
	-X POST '0.0.0.0:8080/v1/uris:search'
```

See [Sample URLs](#sample-urls) below to test the different blocklists.

`wrserver` also serves a URL redirector listening on `/r?url=...` which will
show an interstitial for anything marked unsafe.

If the URL is safe, the client is automatically redirected to the target. 
Otherwise an interstitial warning page is shown as recommended by Web Risk.

Try some sample URLs:

```
http://0.0.0.0:8080/r?url=https://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html
http://0.0.0.0:8080/r?url=https://testsafebrowsing.appspot.com/s/malware.html
http://0.0.0.0:8080/r?url=https://www.google.com/
```

### Differences from Web Risk Lookup API

There are two significant differences between this local endpoint and the
public [`v1/uris:search` endpoint](https://cloud.google.com/web-risk/docs/lookup-api):

  - The public endpoint accepts `GET` requests instead of `POST` requests.
  - The local `wrserver` endpoint uses the privacy-preserving and lower latency
	[Update API](https://cloud.google.com/web-risk/docs/update-api) making it better
	suited for higher-demand use cases.

# Sample URLs

For testing the blocklists, you can use the following URLs:

- Phishing / Social Engineering: https://testsafebrowsing.appspot.com/s/phishing.html
- Malware: https://testsafebrowsing.appspot.com/s/malware.html
- Unwanted Software: https://testsafebrowsing.appspot.com/s/unwanted.html
- Social Engineering Extended Coverage: https://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html

# Troubleshooting

## 4XX Errors

If you start the client without proper credentials or project set up, you will see an error similar to what is shown below on startup:

```
webrisk: 2023/01/27 19:36:13 database.go:217: ListUpdate failure (1): webrisk: unexpected server response code: 400
```

For 400 errors, this usually means the API key is incorrect or was not supplied correctly.

For 403 errors, this could mean the Web Risk API is not enabled for your project **or** your project does not have Billing enabled.

# Configuration

Both `wrserver` (used by `docker run`) and `wrlookup` support several command line flags.

- `apikey` (required) -- Used to Authenticate requests with the Web Risk API.
The API itself must also be enabled on the same project & be linked to a Billing account.

- `threatTypes` (optional) -- A comma-separated lists of different blocklists to load and check URLs against.
Available options include `MALWARE`,`UNWANTED_SOFTWARE`,`SOCIAL_ENGINEERING`,
`SOCIAL_ENGINEERING_EXTENDED_COVERAGE`. This arg will also accept `ALL` which is
the default behavior.

- `maxDiffEntries` (optional) -- An int32 value that will set the max number of hash prefixes
returned in a single diff request. This can be used in resource-bound environments to control
bandwidth usage. The default value of 0 will result in this limit being ignored. Otherwise, this
must be set to a positive integer which must be a power of 2 between 2 ^ 10 and 2 ^ 20.

- `maxDatabaseEntries` (optional) -- An in32 value that will set the upper boundary has prefixes
to be returned from the API and stored locally. This can be used to limit the number of hash
prefixes to be searched against. The default value of 0 will result in this limit being ignored. Otherwise, this
must be set to a positive integer which must be a power of 2 between 2 ^ 10 and 2 ^ 20. *Note*: Setting this limit
will decrease blocklist coverage.

# About the Social Engineering Extended Coverage List

This is a newer blocklist that includes a greater range of risky URLs that
are not included in the Safebrowsing blocklists shipped to most browsers.
The extended coverage list offers significantly more coverage, but may have
a higher number of false positives. For more details, see [here](https://cloud.google.com/web-risk/docs/extended-coverage).

## WebRisk System Test
To perform an end-to-end test on the package with the WebRisk backend,
run the following command after exporting your API key as $APIKEY:

```
go test github.com/google/webrisk -v -run TestWebriskClient
```
