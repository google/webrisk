// Copyright 2019 Google LLC
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
package webrisk

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/google/webrisk/internal/webrisk_proto"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
)

const (
	findHashPath    = "v1/hashes:search"
	fetchUpdatePath = "v1/threatLists:computeDiff"
	threatTypeString = "threat_type"
	versionTokenString = "version_token"
	supportedCompressionsString = "constraints.supported_compressions"
	hashPrefixString = "hash_prefix"
	threatTypesString = "threat_types"
)

// The api interface specifies wrappers around the Web Risk API.
type api interface {
	ListUpdate(ctx context.Context, threat_type pb.ThreatType, version_token []byte,
		compressionTypes []pb.CompressionType) (*pb.ComputeThreatListDiffResponse, error)
	HashLookup(ctx context.Context, hashPrefix []byte,
		threatTypes []pb.ThreatType) (*pb.SearchHashesResponse, error)
}

// netAPI is an api object that talks to the server over HTTP.
type netAPI struct {
	client *http.Client
	url    *url.URL
}

// newNetAPI creates a new netAPI object pointed at the provided root URL.
// For every request, it will use the provided API key.
// If a proxy URL is given, it will be used in place of the default $HTTP_PROXY.
// If the protocol is not specified in root, then this defaults to using HTTPS.
func newNetAPI(root string, key string, proxy string) (*netAPI, error) {
	if !strings.Contains(root, "://") {
		root = "https://" + root
	}
	u, err := url.Parse(root)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{}

	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}
	}

	q := u.Query()
	q.Set("key", key)
	u.RawQuery = q.Encode()
	return &netAPI{url: u, client: httpClient}, nil
}

// doRequests performs a GET to requestPath. It automatically unmarshals the
// response body payload as resp.
func (a *netAPI) doRequest(ctx context.Context, urlString string, resp proto.Message) error {
	httpReq, err := http.NewRequest("GET", urlString, nil)
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("User-Agent", "Webrisk-Client/0.1.3")
	httpReq = httpReq.WithContext(ctx)
	httpResp, err := a.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return fmt.Errorf("webrisk: unexpected server response code: %d", httpResp.StatusCode)
	}
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	return jsonpb.UnmarshalString(string(body), resp)
}

// ListUpdate issues a ComputeThreatListDiff API call and returns the response.
func (a *netAPI) ListUpdate(ctx context.Context, threatType pb.ThreatType, versionToken []byte,
	compressionTypes []pb.CompressionType) (*pb.ComputeThreatListDiffResponse, error) {
	resp := new(pb.ComputeThreatListDiffResponse)
	u := *a.url // Make a copy of URL
	// Add fields from ComputeThreatListDiffRequest to URL request
	q := u.Query()
	q.Set(threatTypeString, threatType.String())
	if len(versionToken) != 0 {
		q.Set(versionTokenString, base64.StdEncoding.EncodeToString(versionToken))
	}
	for _, compressionType := range compressionTypes {
		q.Add(supportedCompressionsString, compressionType.String())
	}
	u.RawQuery = q.Encode()
	u.Path = fetchUpdatePath
	return resp, a.doRequest(ctx, u.String(), resp)
}

// HashLookup issues a SearchHashes API call and returns the response.
func (a *netAPI) HashLookup(ctx context.Context, hashPrefix []byte,
	threatTypes []pb.ThreatType) (*pb.SearchHashesResponse, error) {
	resp := new(pb.SearchHashesResponse)
	u := *a.url // Make a copy of URL
	// Add fields from SearchHashesRequest to URL request
	q := u.Query()
	q.Set(hashPrefixString, base64.StdEncoding.EncodeToString(hashPrefix))
	for _, threatType := range threatTypes {
		q.Add(threatTypesString, threatType.String())
	}
	u.RawQuery = q.Encode()
	u.Path = findHashPath
	return resp, a.doRequest(ctx, u.String(), resp)
}
