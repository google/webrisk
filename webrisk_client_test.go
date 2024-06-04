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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseThreatTypes(t *testing.T) {
	vectors := []struct {
		args   string
		output []ThreatType
		fail   bool
	}{{
		args:   "MALWARE",
		output: []ThreatType{ThreatTypeMalware},
	}, {
		args:   "UNWANTED_SOFTWARE",
		output: []ThreatType{ThreatTypeUnwantedSoftware},
	}, {
		args:   "MALWARE,SOCIAL_ENGINEERING",
		output: []ThreatType{ThreatTypeMalware, ThreatTypeSocialEngineering},
	}, {
		args:   "MALWARE,SOCIAL_ENGINEERING,UNWANTED_SOFTWARE",
		output: []ThreatType{ThreatTypeMalware, ThreatTypeSocialEngineering, ThreatTypeUnwantedSoftware},
	}, {
		args:   "ALL",
		output: []ThreatType{ThreatTypeMalware, ThreatTypeSocialEngineering, ThreatTypeUnwantedSoftware, ThreatTypeSocialEngineeringExtended},
	}, {
		args:   "",
		output: []ThreatType{ThreatTypeMalware, ThreatTypeSocialEngineering, ThreatTypeUnwantedSoftware, ThreatTypeSocialEngineeringExtended},
	}, {
		args: "FAIL_TEST",
		fail: true,
	}, {
		args: "MALWARE,FAIL_TEST",
		fail: true,
	}}

	for i, v := range vectors {
		threatTypes, err := parseThreatTypes(v.args)
		if err != nil != v.fail {
			if err != nil {
				t.Errorf("test %d, unexpected error: %v", i, err)
			} else {
				t.Errorf("test %d, unexpected success", i)
			}
			continue
		}
		if !cmp.Equal(threatTypes, v.output) {
			t.Errorf("test %d, parseThreatTypes(%v), want %v", i, threatTypes, v.output)
		}
	}
}

func TestValidateMaxEntries(t *testing.T) {
	tests := []struct {
		n       int32
		wantErr error
	}{
		{
			n:       0,
			wantErr: nil,
		},
		{
			n:       1024,
			wantErr: nil,
		},
		{
			n:       4096,
			wantErr: nil,
		},
		{
			n:       1048576,
			wantErr: nil,
		},
		{
			n:       -1024,
			wantErr: errMaxEntries,
		},
		{
			n:       100,
			wantErr: errMaxEntries,
		},
		{
			n:       1026,
			wantErr: errMaxEntries,
		},
		{
			n:       2097152,
			wantErr: errMaxEntries,
		},
	}

	for _, tc := range tests {
		gotErr := validateMaxEntries(tc.n)
		if gotErr != tc.wantErr {
			t.Errorf("validateMaxEntries(%d) = %v, want %v", tc.n, gotErr, tc.wantErr)
		}
	}
}
