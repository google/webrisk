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
package webrisk

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	err_pb "github.com/google/webrisk/internal/http_error_proto"
	pb "github.com/google/webrisk/internal/webrisk_proto"
)

const (
	findHashPath                = "v1/hashes:search"
	fetchUpdatePath             = "v1/threatLists:computeDiff"
	threatTypeString            = "threat_type"
	versionTokenString          = "version_token"
	supportedCompressionsString = "constraints.supported_compressions"
	hashPrefixString            = "hash_prefix"
	threatTypesString           = "threat_types"
	userAgentString             = "Webrisk-Client/0.2.1"
)

// The api interface specifies wrappers around the Web Risk API.
type api interface {
	ListUpdate(ctx context.Context, req *pb.ComputeThreatListDiffRequest) (*pb.ComputeThreatListDiffResponse, error)
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
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
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
	if err != nil {
		return err
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("User-Agent", userAgentString)
	httpReq = httpReq.WithContext(ctx)
	httpResp, err := a.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return a.parseError(httpResp)
	}
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(body, resp)
}

// parseError parses an error JSON body and returns an error summary.
func (a *netAPI) parseError(httpResp *http.Response) error {
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	ep := new(err_pb.Error)
	o := protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}
	if err := o.Unmarshal(body, ep); err != nil {
		return fmt.Errorf("webrisk: unknown error, response code: %d", httpResp.StatusCode)
	}
	return fmt.Errorf("webrisk: unexpected server response code: %d, status: %s, message: %s",
		httpResp.StatusCode, ep.GetError().GetStatus(), ep.GetError().GetMessage())
}

// ListUpdate issues a ComputeThreatListDiff API call and returns the response.
func (a *netAPI) ListUpdate(ctx context.Context, req *pb.ComputeThreatListDiffRequest) (*pb.ComputeThreatListDiffResponse, error) {
	resp := new(pb.ComputeThreatListDiffResponse)
	u := *a.url // Make a copy of URL
	// Add fields from ComputeThreatListDiffRequest to URL request
	q := u.Query()
	q.Set(threatTypeString, req.GetThreatType().String())
	if len(req.GetVersionToken()) != 0 {
		q.Set(versionTokenString, base64.StdEncoding.EncodeToString(req.GetVersionToken()))
	}
	for _, compressionType := range req.GetConstraints().GetSupportedCompressions() {
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
