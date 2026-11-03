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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kserve/kserve/pkg/apis/serving/v1alpha2"
	kservescheme "github.com/kserve/kserve/pkg/scheme"
)

func tlsRouteTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, kservescheme.AddLLMISVCAPIs(s))
	return s
}

func confidentialTLSService(withRoute bool) *v1alpha2.LLMInferenceService {
	svc := &v1alpha2.LLMInferenceService{
		ObjectMeta: metav1.ObjectMeta{Name: "llama", Namespace: "test-ns", UID: "uid-1"},
		Spec: v1alpha2.LLMInferenceServiceSpec{
			Model: v1alpha2.LLMModelSpec{
				Confidential: &v1alpha2.ConfidentialSpec{
					Enabled: true,
					TLS: &v1alpha2.ConfidentialTLSSpec{
						CertResourceId: ptr.To("kbs:///default/cert/tls-crt"),
						KeyResourceId:  ptr.To("kbs:///default/cert/tls-key"),
					},
				},
			},
		},
	}
	if withRoute {
		svc.Spec.Router = &v1alpha2.RouterSpec{
			Gateway: &v1alpha2.GatewaySpec{
				Refs: []v1alpha2.GatewayObjectReference{{
					UntypedObjectReference: v1alpha2.UntypedObjectReference{Name: "ingress", Namespace: "test-ns"},
				}},
			},
			Route: &v1alpha2.GatewayRoutesSpec{
				HTTP: &v1alpha2.HTTPRouteSpec{
					Spec: &gwapiv1.HTTPRouteSpec{
						Hostnames: []gwapiv1.Hostname{"llama.example.com"},
					},
				},
			},
		}
	}
	return svc
}

func passthroughGateway() *gwapiv1.Gateway {
	return &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "test-ns"},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "envoy",
			Listeners: []gwapiv1.Listener{{
				Name:     "https-passthrough",
				Port:     443,
				Protocol: gwapiv1.TLSProtocolType,
				TLS:      &gwapiv1.ListenerTLSConfig{Mode: ptr.To(gwapiv1.TLSModePassthrough)},
			}},
		},
	}
}

func TestReconcileTLSRoutes_CreatesTLSRoute(t *testing.T) {
	llmSvc := confidentialTLSService(true)
	gw := passthroughGateway()
	r := &LLMISVCReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(tlsRouteTestScheme(t)).
			WithObjects(llmSvc, gw).
			Build(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	resolved, err := r.reconcileTLSRoutes(t.Context(), llmSvc, &Config{})
	require.NoError(t, err)
	require.Len(t, resolved, 1)

	got := &gwapiv1.TLSRoute{}
	require.NoError(t, r.Get(t.Context(), client.ObjectKey{Namespace: "test-ns", Name: "llama-kserve-tlsroute"}, got))
	require.Len(t, got.Spec.Rules, 1)
	require.Len(t, got.Spec.Rules[0].BackendRefs, 1)
	assert.Equal(t, gwapiv1.ObjectName("llama-kserve-workload-svc"), got.Spec.Rules[0].BackendRefs[0].Name)
	require.Len(t, got.Spec.Hostnames, 1)
	assert.Equal(t, gwapiv1.Hostname("llama.example.com"), got.Spec.Hostnames[0])
	require.Len(t, llmSvc.Status.Addresses, 1)
	assert.Equal(t, "https", llmSvc.Status.Addresses[0].URL.Scheme)
	assert.Equal(t, "llama.example.com", llmSvc.Status.Addresses[0].URL.Host)
}

func TestReconcileTLSRoutes_MissingPassthroughListener(t *testing.T) {
	llmSvc := confidentialTLSService(true)
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "test-ns"},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "envoy",
			Listeners: []gwapiv1.Listener{{
				Name:     "http",
				Port:     80,
				Protocol: gwapiv1.HTTPProtocolType,
			}},
		},
	}
	r := &LLMISVCReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(tlsRouteTestScheme(t)).
			WithObjects(llmSvc, gw).
			Build(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	_, err := r.reconcileTLSRoutes(t.Context(), llmSvc, &Config{})
	require.NoError(t, err)

	got := &gwapiv1.TLSRoute{}
	err = r.Get(t.Context(), client.ObjectKey{Namespace: "test-ns", Name: "llama-kserve-tlsroute"}, got)
	assert.True(t, apierrors.IsNotFound(err))

	cond := llmSvc.Status.GetCondition(v1alpha2.GatewaysReady)
	require.NotNil(t, cond)
	assert.True(t, cond.IsFalse())
	assert.Equal(t, "TLSPassthroughListenerMissing", cond.Reason)
}

func TestReconcileTLSRoutes_NoRouterOmitsTLSRoute(t *testing.T) {
	llmSvc := confidentialTLSService(false)
	r := &LLMISVCReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(tlsRouteTestScheme(t)).
			WithObjects(llmSvc).
			Build(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	resolved, err := r.reconcileTLSRoutes(t.Context(), llmSvc, &Config{})
	require.NoError(t, err)
	assert.Nil(t, resolved)

	got := &gwapiv1.TLSRoute{}
	err = r.Get(t.Context(), client.ObjectKey{Namespace: "test-ns", Name: "llama-kserve-tlsroute"}, got)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestDeleteManagedHTTPRoute_Passthrough(t *testing.T) {
	llmSvc := confidentialTLSService(true)
	httpRoute := managedRoute(llmSvc)
	r := &LLMISVCReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(tlsRouteTestScheme(t)).
			WithObjects(llmSvc, httpRoute).
			Build(),
		EventRecorder: record.NewFakeRecorder(10),
	}

	require.NoError(t, r.deleteManagedHTTPRoute(t.Context(), llmSvc, &Config{}))
	got := &gwapiv1.HTTPRoute{}
	err := r.Get(t.Context(), client.ObjectKey{Namespace: llmSvc.Namespace, Name: httpRoute.Name}, got)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestDeleteSelfSignedCertsSecret(t *testing.T) {
	llmSvc := confidentialTLSService(true)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      selfSignedCertsSecretName(llmSvc),
			Namespace: llmSvc.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(llmSvc, v1alpha2.LLMInferenceServiceGVK),
			},
		},
	}
	r := &LLMISVCReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(tlsRouteTestScheme(t)).
			WithObjects(llmSvc, secret).
			Build(),
		EventRecorder: record.NewFakeRecorder(10),
	}
	require.NoError(t, r.deleteSelfSignedCertsSecret(t.Context(), llmSvc))
	err := r.Get(t.Context(), client.ObjectKeyFromObject(secret), &corev1.Secret{})
	assert.True(t, apierrors.IsNotFound(err))
}
