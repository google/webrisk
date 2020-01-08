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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	pb "github.com/google/webrisk/internal/webrisk_proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

type mockAPI struct {
	listUpdate func(ctx context.Context, threatType pb.ThreatType, versionToken []byte,
		compressionTypes []pb.CompressionType) (*pb.ComputeThreatListDiffResponse, error)
	hashLookup func(ctx context.Context, hashPrefix []byte,
		threatTypes []pb.ThreatType) (*pb.SearchHashesResponse, error)
}

func (m *mockAPI) ListUpdate(ctx context.Context, threatType pb.ThreatType, versionToken []byte,
	compressionTypes []pb.CompressionType) (*pb.ComputeThreatListDiffResponse, error) {
	return m.listUpdate(ctx, threatType, versionToken, compressionTypes)
}

func (m *mockAPI) HashLookup(ctx context.Context, hashPrefix []byte,
	threatTypes []pb.ThreatType) (*pb.SearchHashesResponse, error) {
	return m.hashLookup(ctx, hashPrefix, threatTypes)
}

func TestNetAPI(t *testing.T) {
	var gotReqThreatType, wantReqThreatType pb.ThreatType
	var gotReqCompressionTypes, wantReqCompressionTypes []pb.CompressionType
	var gotReqHashPrefix, wantReqHashPrefix []byte
	var gotReqThreatTypes, wantReqThreatTypes []pb.ThreatType
	var gotResp, wantResp proto.Message
	responseMisformatter := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p string
		var err error
		marshaler := jsonpb.Marshaler{}
		for key, value := range r.URL.Query() {
			if (key == "threat_type") {
				if (len(value) == 0) {
					t.Fatalf("missing value for key: %v", key)
				}
				gotReqThreatType = pb.ThreatType(pb.ThreatType_value[value[0]])
			} else if (key == "constraints.supported_compressions") {
				if (len(value) == 0) {
					t.Fatalf("missing value for key: %v", key)
				}
				for _, comp := range value {
					gotReqCompressionTypes = append(gotReqCompressionTypes,
						pb.CompressionType(pb.CompressionType_value[comp]))
				}
			} else if (key == "hash_prefix") {
				if (len(value) == 0) {
					t.Fatalf("missing value for key: %v", key)
				}
				gotReqHashPrefix, err = base64.StdEncoding.DecodeString(value[0])
				if (err != nil) {
					t.Fatalf("unexpected hash prefix decoding error for: %v", value[0])
				}
			} else if (key == "threat_types") {
				if (len(value) == 0) {
					t.Fatalf("missing value for key: %v", key)
				}
				for _, threat := range value {
					gotReqThreatTypes = append(gotReqThreatTypes,
						pb.ThreatType(pb.ThreatType_value[threat]))
				}
			} else if (key != "key") {
				t.Fatalf("unexpected request param error for key: %v", key)
			}
		}
		if p, err = marshaler.MarshalToString(wantResp); err != nil {
			t.Fatalf("unexpected jsonpb MarshalToString error: %v", err)
		}
		if _, err := w.Write([]byte(responseMisformatter + p)); err != nil {
			t.Fatalf("unexpected ResponseWriter.Write error: %v", err)
		}
	}))
	defer ts.Close()

	api, err := newNetAPI(ts.URL, "fizzbuzz", "")
	if err != nil {
		t.Errorf("unexpected newNetAPI error: %v", err)
	}

	// Test that ListUpdate marshal/unmarshal works.
	wantReqThreatType = pb.ThreatType_MALWARE
	wantReqCompressionTypes = []pb.CompressionType{0, 1, 2}

	wantResp = &pb.ComputeThreatListDiffResponse{
		ResponseType: 1,
		Checksum:     &pb.ComputeThreatListDiffResponse_Checksum{Sha256: []byte("abcd")},
		Removals: &pb.ThreatEntryRemovals{
			RawIndices: &pb.RawIndices{Indices: []int32{1, 2, 3}},
		},
	}
	resp1, err := api.ListUpdate(context.Background(), wantReqThreatType, []byte {},
	    wantReqCompressionTypes)
	gotResp = resp1
	if err != nil {
		t.Errorf("unexpected ListUpdate error: %v", err)
	}
	if !reflect.DeepEqual(gotReqThreatType, wantReqThreatType) {
		t.Errorf("mismatching ListUpdate requests for threat type:\ngot  %+v\nwant %+v",
			gotReqThreatType, wantReqThreatType)
	}
	if !reflect.DeepEqual(gotReqCompressionTypes, wantReqCompressionTypes) {
		t.Errorf("mismatching ListUpdate requests for compression types:\ngot  %+v\nwant %+v",
			gotReqCompressionTypes, wantReqCompressionTypes)
	}
	if !reflect.DeepEqual(gotResp, wantResp) {
		t.Errorf("mismatching ListUpdate responses:\ngot  %+v\nwant %+v", gotResp, wantResp)
	}

	// Test that HashLookup marshal/unmarshal works.
	wantReqHashPrefix = []byte("aaaa")
	wantReqThreatTypes = []pb.ThreatType{1, 2, 3}

	wantResp = &pb.SearchHashesResponse{Threats: []*pb.SearchHashesResponse_ThreatHash{{
		ThreatTypes: []pb.ThreatType{pb.ThreatType_MALWARE},
		Hash:        []byte("abcd")}}}
	resp2, err := api.HashLookup(context.Background(), wantReqHashPrefix, wantReqThreatTypes)
	gotResp = resp2
	if err != nil {
		t.Errorf("unexpected HashLookup error: %v", err)
	}
	if !reflect.DeepEqual(gotReqHashPrefix, wantReqHashPrefix) {
		t.Errorf("mismatching HashLookup requests for hash prefix:\ngot  %+v\nwant %+v",
			gotReqHashPrefix, wantReqHashPrefix)
	}
	if !reflect.DeepEqual(gotReqThreatTypes, wantReqThreatTypes) {
		t.Errorf("mismatching HashLookup requests for threat types:\ngot  %+v\nwant %+v",
			gotReqThreatTypes, wantReqThreatTypes)
	}
	if !reflect.DeepEqual(gotResp, wantResp) {
		t.Errorf("mismatching HashLookup responses:\ngot  %+v\nwant %+v", gotResp, wantResp)
	}

	// Test canceled Context returns an error.
	wantReqHashPrefix = []byte("aaaa")
	wantReqThreatTypes = []pb.ThreatType{1, 2, 3}

	wantResp = &pb.SearchHashesResponse{Threats: []*pb.SearchHashesResponse_ThreatHash{{
		ThreatTypes: []pb.ThreatType{pb.ThreatType_MALWARE},
		Hash:        []byte("abcd")},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = api.HashLookup(ctx, wantReqHashPrefix, wantReqThreatTypes)
	if err == nil {
		t.Errorf("unexpected HashLookup success, wanted HTTP request canceled")
	}

	// Test misformatted HashLookup response returns an error.
	wantReqHashPrefix = []byte("aaaa")
	wantReqThreatTypes = []pb.ThreatType{1, 2, 3}

	wantResp = &pb.SearchHashesResponse{Threats: []*pb.SearchHashesResponse_ThreatHash{{
		ThreatTypes: []pb.ThreatType{pb.ThreatType_MALWARE},
		Hash:        []byte("abcd")}}}
	responseMisformatter = "bb"
	_, err = api.HashLookup(context.Background(), wantReqHashPrefix, wantReqThreatTypes)
	if err == nil {
		t.Errorf("unexpected HashLookup success, wanted malformed JSON error")
	}
}
