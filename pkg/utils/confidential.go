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
	corev1 "k8s.io/api/core/v1"

	"github.com/kserve/kserve/pkg/constants"
)

// ConfidentialTLSEnv holds KBS resource IDs for serving TLS material fetched
// by the storage-initializer via CDH.
type ConfidentialTLSEnv struct {
	CertResourceId string
	KeyResourceId  string
	CAResourceId   string
}

// ApplyConfidentialContainerConfig configures a container for confidential model serving
// by injecting the required environment variables.
// This is shared between the InferenceService webhook (annotation-driven) and the
// LLMInferenceService controller (spec-driven).
func ApplyConfidentialContainerConfig(container *corev1.Container, resourceId string, tls *ConfidentialTLSEnv) {
	AddOrReplaceEnv(container, constants.ConfidentialEnabledEnvVar, "true")

	if resourceId != "" {
		AddOrReplaceEnv(container, constants.ConfidentialResourceIdEnvVar, resourceId)
	}

	if tls == nil {
		return
	}
	if tls.CertResourceId != "" {
		AddOrReplaceEnv(container, constants.ConfidentialTLSCertResourceIdEnvVar, tls.CertResourceId)
	}
	if tls.KeyResourceId != "" {
		AddOrReplaceEnv(container, constants.ConfidentialTLSKeyResourceIdEnvVar, tls.KeyResourceId)
	}
	if tls.CAResourceId != "" {
		AddOrReplaceEnv(container, constants.ConfidentialTLSCAResourceIdEnvVar, tls.CAResourceId)
	}
}

// ConfidentialTLSEnvFromAnnotations reconstructs TLS KBS resource IDs from pod
// annotations set by the InferenceService controller.
func ConfidentialTLSEnvFromAnnotations(annotations map[string]string) *ConfidentialTLSEnv {
	if annotations == nil {
		return nil
	}
	cert := annotations[constants.ConfidentialTLSCertResourceIdAnnotationKey]
	key := annotations[constants.ConfidentialTLSKeyResourceIdAnnotationKey]
	ca := annotations[constants.ConfidentialTLSCAResourceIdAnnotationKey]
	if cert == "" && key == "" && ca == "" {
		return nil
	}
	return &ConfidentialTLSEnv{
		CertResourceId: cert,
		KeyResourceId:  key,
		CAResourceId:   ca,
	}
}
