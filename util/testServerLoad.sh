#!/bin/bash
# This is a utilty script for testing wrserver shutdown under load. To run
# this test, you need to compile wrserver and supply an API Key. Consult the
# README for help.

# This test works by flooding the server with enough connections that some will
# still be in-flight when a SIGTERM arrives. This test is flaky because and
# shouldn't be included in any CI chain.

# IMPORTANT: This test uses a real API Key and could result in a chargable
# event. The built in caching of the server will minimize this.

# Usage info and args.
if [ $# -ne 2 ]; then
  echo "Usage: $0 <wrserver_binary> <api_key>"
  exit 1
fi

wrserver=$1
apikey=$2

# Starts our server in a background process, save the process.
./"$wrserver" --apikey="$apikey" &
p=$!

# Wait for startup and DB sync.
# Increase this timer if you're on a slow connection.
sleep 10

echo "Beginning Test at $(date +%s%N | cut -b1-13)"

# Sends a request to our server and outputs the response. The timing output are
# not exact because there's some latency to running the different comands,
# which makes this test potentially flaky. We minimize this by using a large
# number of requests and only waiting a short time before sending our SIGTERM.
send_req() {
  i=$1
  s=$(date +%s%N | cut -b1-13)
  r=$(curl -s -o /dev/null -w "%{http_code}" -H 'Content-Type: application/json' \
	-d '{"uri":"http://testsafebrowsing.appspot.com/s/social_engineering_extended_coverage.html"}' \
	-X POST '0.0.0.0:8080/v1/uris:search')
  e=$(date +%s%N | cut -b1-13)
  echo "Req $i started: $s ended: $e resp: $r"
}

# Sends 100 requests to our server.
for i in {1..100}; do
  (send_req $i) &
done

# Wait for enough time that all the requests have begun.
sleep 0.15

# Send our kill signal. All inflight connections are expected to resolve with
# a 200 status. All connections sent after shutown are expected to fail with a
# 000 status. 
echo "Sending SIGTERM..."
kill -s SIGTERM $p
st=$(date +%s%N | cut -b1-13)
echo "SIGTERM sent at: $st"
echo "Further requests are expected to fail."

sleep 0.1

# Send additional requests to confirm our server is down.
for i in {1..5}; do
  (send_req $i) &
done

# Wait for all the background tasks sent with '&' to complete.
wait

echo "Test complete at $(date +%s%N | cut -b1-13)"