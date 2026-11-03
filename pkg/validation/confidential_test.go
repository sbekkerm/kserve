/*
Copyright 2026 The KServe Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package validation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
)

func TestValidateConfidentialSpec(t *testing.T) {
	base := field.NewPath("spec", "model")
	validID := ptr.To("kbs:///default/key/model-key")
	validTLS := &ConfidentialTLS{
		CertResourceId: ptr.To("kbs:///default/cert/tls-crt"),
		KeyResourceId:  ptr.To("kbs:///default/cert/tls-key"),
	}

	tests := []struct {
		name           string
		enabled        bool
		resourceId     *string
		tls            *ConfidentialTLS
		uri            string
		wantErrStrings []string
		wantWarnings   []string
	}{
		{
			name:    "disabled with no tls",
			enabled: false,
			uri:     "hf://model",
		},
		{
			name:         "enabled without tls warns",
			enabled:      true,
			uri:          "hf://model",
			wantWarnings: []string{ConfidentialTLSMissingWarning},
		},
		{
			name:       "enabled with valid tls has no missing-tls warning",
			enabled:    true,
			resourceId: validID,
			tls:        validTLS,
			uri:        "hf://model",
		},
		{
			name:           "tls requires enabled",
			enabled:        false,
			tls:            validTLS,
			uri:            "hf://model",
			wantErrStrings: []string{"confidential.tls requires confidential.enabled"},
		},
		{
			name:    "cert and key required together - only cert",
			enabled: true,
			tls: &ConfidentialTLS{
				CertResourceId: ptr.To("kbs:///default/cert/tls-crt"),
			},
			uri:            "hf://model",
			wantErrStrings: []string{"certResourceId and keyResourceId must be set together"},
		},
		{
			name:    "empty tls object requires cert and key",
			enabled: true,
			tls:     &ConfidentialTLS{},
			uri:     "hf://model",
			wantErrStrings: []string{
				"certResourceId and keyResourceId are required",
			},
		},
		{
			name:    "malformed cert resource id",
			enabled: true,
			tls: &ConfidentialTLS{
				CertResourceId: ptr.To("not-kbs"),
				KeyResourceId:  ptr.To("kbs:///default/cert/tls-key"),
			},
			uri:            "hf://model",
			wantErrStrings: []string{"kbs:///<repo>/<type>/<tag>"},
		},
		{
			name:    "malformed ca resource id",
			enabled: true,
			tls: &ConfidentialTLS{
				CertResourceId: ptr.To("kbs:///default/cert/tls-crt"),
				KeyResourceId:  ptr.To("kbs:///default/cert/tls-key"),
				CAResourceId:   ptr.To("bad"),
			},
			uri:            "hf://model",
			wantErrStrings: []string{"kbs:///<repo>/<type>/<tag>"},
		},
		{
			name:         "oci uri warns in addition to missing tls",
			enabled:      true,
			uri:          "oci://registry/model:latest",
			wantWarnings: []string{"OCI URIs", "confidential.tls"},
		},
		{
			name:           "malformed model resourceId",
			enabled:        true,
			resourceId:     ptr.To("invalid"),
			uri:            "hf://model",
			wantErrStrings: []string{"kbs:///<repo>/<type>/<tag>"},
			wantWarnings:   []string{ConfidentialTLSMissingWarning},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, errs := ValidateConfidentialSpec(tt.enabled, tt.resourceId, tt.tls, tt.uri, base)
			if len(tt.wantErrStrings) == 0 {
				assert.Empty(t, errs)
			} else {
				require.NotEmpty(t, errs)
				joined := errs.ToAggregate().Error()
				for _, want := range tt.wantErrStrings {
					assert.Contains(t, joined, want)
				}
			}
			for _, want := range tt.wantWarnings {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, want) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected warning containing %q, got %v", want, warnings)
			}
		})
	}
}

func TestValidateConfidentialTLSRouter(t *testing.T) {
	assert.Empty(t, ValidateConfidentialTLSRouter(false, true, true), "scheduler allowed when tls is omitted")
	assert.Empty(t, ValidateConfidentialTLSRouter(true, false, true), "route without scheduler allowed")

	errs := ValidateConfidentialTLSRouter(true, true, false)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "spec.router.scheduler")
	assert.Contains(t, errs[0].Error(), ConfidentialTLSSchedulerForbidden)

	errs = ValidateConfidentialTLSRouter(true, true, true)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Error(), "spec.router.scheduler")
	assert.Contains(t, errs[1].Error(), "spec.router.route")
	assert.Contains(t, errs[1].Error(), ConfidentialTLSSchedulerRouteForbidden)
}
