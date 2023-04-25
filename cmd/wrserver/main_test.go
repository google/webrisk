// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"io"
	"net/http"
	"syscall"
	"testing"
	"time"
)

// Provide an override hostname so that we can run the test within Docker's build step.
var (
	hostnameFlag = flag.String("hostname", "http://[::1]:8080", "Specify a hostname for testing.")
)

// isClosed checks if a channel is closed without blocking the thread.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// closeOrTimeout waits for a channel to close for `ms` milliseconds and sends an error on timeout.
func closeOrTimeout(t *testing.T, ms int64, ch chan struct{}, txt string) {
	to := time.After(time.Duration(ms) * time.Millisecond)

	for !isClosed(ch) {
		select {
		case <-to:
			t.Errorf("Timeout Error Waiting for: %s", txt)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// closeOrTimeout2 waits for a channel to close for `ms` milliseconds and sends an error on timeout.
// This second function takes a one-way channel.
func closeOrTimeout2(t *testing.T, ms int64, ch <-chan struct{}, txt string) {
	to := time.After(time.Duration(ms) * time.Millisecond)

	for !isClosed(ch) {
		select {
		case <-to:
			t.Errorf("Timeout Error Waiting for: %s", txt)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// mockHandler is used to send a simple response and signal when started and finished.
func mockHandler(start, fin chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		close(start)
		io.WriteString(w, "Hello there.")
		close(fin)
	}
}

func TestServerShutdown(t *testing.T) {
	// Channels for our handler to use later.
	started := make(chan struct{})
	finished := make(chan struct{})

	// Set up mock handler and server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", mockHandler(started, finished))

	testServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start server and wait for it to be ready.
	exit, down := runServer(testServer)
	time.Sleep(1 * time.Second)

	// Open a test connection.
	_, err := http.Get(*hostnameFlag + "/")
	if err != nil {
		t.Fatalf("Error connecting to server, test cannot continue: %v", err)
	}

	// Wait for confirmation the request was received.
	closeOrTimeout(t, 1000, started, "Request Received")

	// Send a SIGTERM to the server to gracefully exit.
	exit <- syscall.SIGTERM

	// Wait for confirmation the request was finished.
	closeOrTimeout(t, 1000, finished, "Response Finished")

	// Wait for confirmation the server is down.
	closeOrTimeout2(t, 1000, down, "Server Shutting Down")

	// Make sure the server will not accept more connections.
	_, err = http.Get(*hostnameFlag + "/")
	if err == nil {
		t.Errorf("Server accepted connection when it should be shut down.")
	}
}
