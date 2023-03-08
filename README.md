# Reference Implementation for the Usage of Google Cloud WebRisk APIs

The `webrisk` Go package can be used with the
[Google Cloud WebRisk APIs](https://cloud.google.com/web-risk/)
to access the Google Cloud WebRisk lists of unsafe web resources. Inside the
`cmd` sub-directory, you can find two programs: `wrlookup` and `wrserver`. The
`wrserver` program creates a proxy local server to check URLs and a URL
redirector to redirect users to a warning page for unsafe URLs. The `wrlookup`
program is a command line service that can also be used to check URLs.

This **README.md** is a quickstart guide on how to build, deploy, and use the
WebRisk Go package. It can be used out-of-the-box. The GoDoc and API
documentation in the .go source files provide more details on fine tuning the
parameters if desired.

This client implements the [Update API](https://cloud.google.com/web-risk/docs/update-api),
and includes a simplified Dockerfile. It is not necessary to run as a container
to test the client or new blocklist.

This container branch also includes support for the
`SOCIAL_ENGINEERING_EXTENDED_COVERAGE` blocklist. 

# Enable Web Risk

To begin using Web Risk, you will need a GCP Account and a project to work in.

1. Enable the Web Risk API (requires Billing).

2. Generate an API Key.

# Docker Container App Quickstart

We have included a Dockerfile to accelerate and simplify onboarding. This
container wraps the `wrserver` binary detailed below.

If you haven't already, you must install [Docker](https://www.docker.com/).

## Clone and Build Container

Building the container is straightforward.

```
# clone this repo into a local directory & switch to the container branch
> git clone -b container https://github.com/google/webrisk && cd webrisk

# build the a docker container
> docker build --tag wr-container .
```

## Run Container

We supply the `APIKEY` as an environmental variable to the container at runtime
so that the API Key is not revealed as part of the docker file or in `docker ps`.
This example also provides a port binding.

```
> docker run -e APIKEY=XXXXXXXXXXXXXXXXXXXXXXX -p 8080:8080 wr-container
```

`wrserver` defaults to port 8080, but you can bind any port on the host machine.
See the [Docker documentation](https://docs.docker.com/config/containers/container-networking/)
for details.

# Go Binary Quickstart | `wrlookup` example

The Go Client can be compiled and run directly without Docker. In this example
we will use that to run the `wrlookup` binary that takes URLs from `STDIN` and
outputs to `STDOUT`.

Before compiling from source you should [install Go](https://go.dev/doc/install)
and have some familiarity with Go development. See [here](https://go.dev/doc/tutorial/getting-started)
for a good place to get started.

## Clone Source & Install Dependencies

To download and install this branch from the source, run the following command:

```
# clone this repo into a local directory & switch to the container branch
> git clone -b container https://github.com/google/webrisk && cd webrisk

# install dependencies
.../webrisk> go install
```

## Build and Execute `wrlookup`

After installing dependencies, you can build and run `wrlookup`

```
# builds a wrlookup binary in the current directory
.../webrisk> go build -o wrlookup cmd/wrlookup/main.go


# run the binary and supply an API Key
.../webrisk> ./wrlookup -apikey=XXXXXXXXXXXXXXXXXXXXXXX
```

You should see some output similar to below as `wrlookup` starts up.

```
webrisk: 2023/01/27 19:36:46 database.go:110: no database file specified
webrisk: 2023/01/27 19:36:53 database.go:384: database is now healthy
webrisk: 2023/01/27 19:36:53 webrisk_client.go:492: Next update in 30m29s
```

`wrlookup` will take any URLs from `STDIN`. Test your configuration with a sample:

```
http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ #input
Unsafe URL: [MALWARE] # output
```

An incorrect API Key or other auth error might result in an error as below:

```
webrisk: 2023/01/27 19:36:13 database.go:217: ListUpdate failure (1): webrisk: unexpected server response code: 400
```

# Using `wrserver`

`wrserver` runs a WebRisk API lookup proxy that allows users to check URLs via
a simple JSON API. This local API will use the API key supplied by the Docker
container or the command line that runs the binary.

1.	Start the `wrserver` by either running the container or binary.

	```
	# run in docker
	> docker run -e APIKEY=XXXXXXXXXXXXXXXXXXXXXXX -p 8080:8080 <container_name>

	# run from CLI, compile as above but use `wrserver` in place of `wrlookup`
	> ./wrserver -apikey=XXXXXXXXXXXXXXXXXXXXXXX
	```

	With the default settings this will start a local server at **0.0.0.0:8080**.

2.  `wrserver` serves a URL redirector listening on `/r` which will show an interstitial for anything marked unsafe.

	If the URL is safe, the client is automatically redirected to the target. 
	Otherwise an interstitial warning page is shown as recommended by Web Risk.  
	Try these URLs:

	```
	0.0.0.0:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/
	0.0.0.0:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/
	0.0.0.0:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/
	0.0.0.0:8080/r?url=http://www.google.com/
	```

3.	The server also has a lightweight implementation of a [Web Risk Lookup API](https://cloud.google.com/web-risk/docs/lookup-api)-like endpoint at `v1/uris:search`.
To use the local endpoint to check a URL, send a POST request to `0.0.0.0:8080/v1/uris:search` with the a JSON body similar to the following.

	```json
	{
    	"uri":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
   		"threatTypes":["MALWARE"]
  }
	```

4. Test with the following cURL command:

	```
	> curl -X POST 0.0.0.0:8080/v1/uris:search \ 
		-H 'Content-Type: application/json' \ 
		-d '{"uri":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/", "threatTypes":["MALWARE"]}'
	```

There are two significant differences between this local endpoint and the
public `v1/uris:search` endpoint:

  - The public endpoint accepts `GET` requests instead of `POST` requests.
  - The local `wrserver` endpoint uses the privacy-preserving and lower latency
	[Update API](https://cloud.google.com/web-risk/docs/update-api) making it better
	suited for higher-demand use cases.


## WebRisk System Test
To perform an end-to-end test on the package with the WebRisk backend,
run the following command after exporting your API key as $APIKEY:

```
go test github.com/google/webrisk -v -run TestWebriskClient
```
