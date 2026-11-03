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

package llmisvc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kserve/kserve/pkg/apis/serving/v1alpha2"
	"github.com/kserve/kserve/pkg/constants"
)

func TestConfidentialTLSPassthrough(t *testing.T) {
	tls := &v1alpha2.ConfidentialTLSSpec{
		CertResourceId: ptr.To("kbs:///default/cert/tls-crt"),
		KeyResourceId:  ptr.To("kbs:///default/cert/tls-key"),
	}
	route := &v1alpha2.GatewayRoutesSpec{HTTP: &v1alpha2.HTTPRouteSpec{}}
	scheduler := &v1alpha2.SchedulerSpec{}

	assert.False(t, confidentialTLSPassthrough(&v1alpha2.LLMInferenceService{}))
	assert.False(t, confidentialTLSPassthrough(&v1alpha2.LLMInferenceService{
		Spec: v1alpha2.LLMInferenceServiceSpec{
			Model:  v1alpha2.LLMModelSpec{Confidential: &v1alpha2.ConfidentialSpec{Enabled: true, TLS: tls}},
			Router: &v1alpha2.RouterSpec{Scheduler: scheduler},
		},
	}), "scheduler plus tls is not passthrough")
	assert.False(t, confidentialTLSPassthrough(&v1alpha2.LLMInferenceService{
		Spec: v1alpha2.LLMInferenceServiceSpec{
			Model: v1alpha2.LLMModelSpec{Confidential: &v1alpha2.ConfidentialSpec{Enabled: true, TLS: tls}},
		},
	}), "no router means no TLSRoute")
	assert.True(t, confidentialTLSPassthrough(&v1alpha2.LLMInferenceService{
		Spec: v1alpha2.LLMInferenceServiceSpec{
			Model:  v1alpha2.LLMModelSpec{Confidential: &v1alpha2.ConfidentialSpec{Enabled: true, TLS: tls}},
			Router: &v1alpha2.RouterSpec{Route: route},
		},
	}))
}

func TestApplyConfidentialTLSVolumes(t *testing.T) {
	spec := &v1alpha2.LLMInferenceServiceSpec{
		WorkloadSpec: v1alpha2.WorkloadSpec{
			Template: &corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: constants.ConfidentialTLSCertsVolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "svc-kserve-self-signed-certs"},
					},
				}},
			},
		},
	}
	applyConfidentialTLSVolumes(spec)
	require.Len(t, spec.Template.Volumes, 1)
	require.NotNil(t, spec.Template.Volumes[0].EmptyDir)
	assert.Equal(t, corev1.StorageMediumMemory, spec.Template.Volumes[0].EmptyDir.Medium)
	assert.Nil(t, spec.Template.Volumes[0].Secret)
}

func TestFindTLSPassthroughListener(t *testing.T) {
	_, ok := findTLSPassthroughListener(&gwapiv1.Gateway{})
	assert.False(t, ok)

	name, ok := findTLSPassthroughListener(&gwapiv1.Gateway{
		Spec: gwapiv1.GatewaySpec{
			Listeners: []gwapiv1.Listener{{
				Name:     "https-passthrough",
				Port:     443,
				Protocol: gwapiv1.TLSProtocolType,
				TLS:      &gwapiv1.ListenerTLSConfig{Mode: ptr.To(gwapiv1.TLSModePassthrough)},
			}},
		},
	})
	assert.True(t, ok)
	assert.Equal(t, gwapiv1.SectionName("https-passthrough"), name)
}

func TestExpectedTLSRoute(t *testing.T) {
	llmSvc := &v1alpha2.LLMInferenceService{
		ObjectMeta: metav1.ObjectMeta{Name: "llama", Namespace: "ns"},
		Spec: v1alpha2.LLMInferenceServiceSpec{
			Router: &v1alpha2.RouterSpec{Route: &v1alpha2.GatewayRoutesSpec{}},
		},
	}
	route := expectedTLSRoute(llmSvc)
	assert.Equal(t, "llama-kserve-tlsroute", route.Name)
	assert.Equal(t, "ns", route.Namespace)
	require.Len(t, route.OwnerReferences, 1)
}
