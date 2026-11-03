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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/kserve/kserve/pkg/constants"
)

func envMap(container *corev1.Container) map[string]string {
	out := make(map[string]string, len(container.Env))
	for _, env := range container.Env {
		out[env.Name] = env.Value
	}
	return out
}

func TestApplyConfidentialContainerConfig(t *testing.T) {
	t.Run("enabled with resource id", func(t *testing.T) {
		c := &corev1.Container{}
		ApplyConfidentialContainerConfig(c, "kbs:///default/key/model-key", nil)
		got := envMap(c)
		assert.Equal(t, "true", got[constants.ConfidentialEnabledEnvVar])
		assert.Equal(t, "kbs:///default/key/model-key", got[constants.ConfidentialResourceIdEnvVar])
		assert.Empty(t, got[constants.ConfidentialTLSCertResourceIdEnvVar])
	})

	t.Run("tls resource ids", func(t *testing.T) {
		c := &corev1.Container{}
		ApplyConfidentialContainerConfig(c, "", &ConfidentialTLSEnv{
			CertResourceId: "kbs:///default/cert/tls-crt",
			KeyResourceId:  "kbs:///default/cert/tls-key",
			CAResourceId:   "kbs:///default/cert/ca-crt",
		})
		got := envMap(c)
		assert.Equal(t, "true", got[constants.ConfidentialEnabledEnvVar])
		assert.Equal(t, "kbs:///default/cert/tls-crt", got[constants.ConfidentialTLSCertResourceIdEnvVar])
		assert.Equal(t, "kbs:///default/cert/tls-key", got[constants.ConfidentialTLSKeyResourceIdEnvVar])
		assert.Equal(t, "kbs:///default/cert/ca-crt", got[constants.ConfidentialTLSCAResourceIdEnvVar])
	})
}

func TestConfidentialTLSEnvFromAnnotations(t *testing.T) {
	assert.Nil(t, ConfidentialTLSEnvFromAnnotations(nil))
	assert.Nil(t, ConfidentialTLSEnvFromAnnotations(map[string]string{}))

	got := ConfidentialTLSEnvFromAnnotations(map[string]string{
		constants.ConfidentialTLSCertResourceIdAnnotationKey: "kbs:///default/cert/tls-crt",
		constants.ConfidentialTLSKeyResourceIdAnnotationKey:  "kbs:///default/cert/tls-key",
	})
	assert.Equal(t, "kbs:///default/cert/tls-crt", got.CertResourceId)
	assert.Equal(t, "kbs:///default/cert/tls-key", got.KeyResourceId)
	assert.Empty(t, got.CAResourceId)
}
