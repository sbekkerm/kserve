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
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	"knative.dev/pkg/kmeta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kserve/kserve/pkg/apis/serving/v1alpha2"
	"github.com/kserve/kserve/pkg/utils"
)

func tlsRouteName(llmSvc *v1alpha2.LLMInferenceService) string {
	return kmeta.ChildName(llmSvc.GetName(), "-kserve-tlsroute")
}

func (r *LLMISVCReconciler) deleteManagedHTTPRoute(ctx context.Context, llmSvc *v1alpha2.LLMInferenceService, cfg *Config) error {
	expected, _ := r.expectedHTTPRoute(ctx, llmSvc, cfg)
	llmSvc.MarkGroupReadyUnset()
	llmSvc.MarkPerModelPathsDroppedUnset()
	llmSvc.MarkHTTPRoutesReadyUnset()
	return Delete(ctx, r, llmSvc, expected)
}

func (r *LLMISVCReconciler) deleteManagedTLSRoute(ctx context.Context, llmSvc *v1alpha2.LLMInferenceService) error {
	return Delete(ctx, r, llmSvc, expectedTLSRoute(llmSvc))
}

func expectedTLSRoute(llmSvc *v1alpha2.LLMInferenceService) *gwapiv1.TLSRoute {
	return &gwapiv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tlsRouteName(llmSvc),
			Namespace: llmSvc.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(llmSvc, v1alpha2.LLMInferenceServiceGVK),
			},
			Labels: RouterLabels(llmSvc),
		},
	}
}

// reconcileTLSRoutes creates a TLSRoute for confidential TLS passthrough, or
// deletes a leftover TLSRoute when passthrough does not apply.
func (r *LLMISVCReconciler) reconcileTLSRoutes(ctx context.Context, llmSvc *v1alpha2.LLMInferenceService, cfg *Config) ([]ResolvedGateway, error) {
	logger := log.FromContext(ctx)
	expected := expectedTLSRoute(llmSvc)

	if utils.GetForceStopRuntime(llmSvc) || !confidentialTLSPassthrough(llmSvc) {
		if err := Delete(ctx, r, llmSvc, expected); err != nil {
			return nil, err
		}
		return nil, nil
	}

	logger.Info("Reconciling TLSRoute for confidential TLS passthrough")

	parentRefs, err := r.tlsRouteParentRefs(ctx, llmSvc, cfg)
	if err != nil {
		llmSvc.MarkGatewaysNotReady("TLSPassthroughListenerMissing", "%s", err.Error())
		return nil, nil
	}

	expected.Spec = gwapiv1.TLSRouteSpec{
		CommonRouteSpec: gwapiv1.CommonRouteSpec{
			ParentRefs: parentRefs,
		},
		Hostnames: tlsRouteHostnames(llmSvc),
		Rules: []gwapiv1.TLSRouteRule{{
			BackendRefs: []gwapiv1.BackendRef{{
				BackendObjectReference: gwapiv1.BackendObjectReference{
					Group: ptr.To(gwapiv1.Group("")),
					Kind:  ptr.To(gwapiv1.Kind("Service")),
					Name:  gwapiv1.ObjectName(workloadServiceName(llmSvc)),
					Port:  ptr.To(gwapiv1.PortNumber(8000)),
				},
			}},
		}},
	}

	if err := Reconcile(ctx, r, llmSvc, &gwapiv1.TLSRoute{}, expected, semanticTLSRouteIsEqual); err != nil {
		return nil, fmt.Errorf("failed to reconcile TLSRoute %s/%s: %w", expected.GetNamespace(), expected.GetName(), err)
	}

	resolved, err := r.discoverTLSRouteGateways(ctx, expected)
	if err != nil {
		return nil, err
	}
	r.updateTLSRoutingStatus(llmSvc, expected, resolved)
	llmSvc.MarkHTTPRoutesReadyUnset()
	return resolved, nil
}

func tlsRouteHostnames(llmSvc *v1alpha2.LLMInferenceService) []gwapiv1.Hostname {
	if llmSvc.Spec.Router == nil || llmSvc.Spec.Router.Route == nil || !llmSvc.Spec.Router.Route.HTTP.HasSpec() {
		return nil
	}
	return llmSvc.Spec.Router.Route.HTTP.Spec.Hostnames
}

func (r *LLMISVCReconciler) tlsRouteParentRefs(ctx context.Context, llmSvc *v1alpha2.LLMInferenceService, cfg *Config) ([]gwapiv1.ParentReference, error) {
	refs := tlsRouteBaseParentRefs(llmSvc, cfg)
	out := make([]gwapiv1.ParentReference, 0, len(refs))
	for _, ref := range refs {
		section, err := r.ensureTLSPassthroughListener(ctx, llmSvc, ref)
		if err != nil {
			return nil, err
		}
		ref.SectionName = ptr.To(section)
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil, errors.New("no parent Gateway for confidential TLS passthrough")
	}
	return out, nil
}

func tlsRouteBaseParentRefs(llmSvc *v1alpha2.LLMInferenceService, cfg *Config) []gwapiv1.ParentReference {
	if llmSvc.Spec.Router != nil && llmSvc.Spec.Router.Route != nil && llmSvc.Spec.Router.Route.HTTP.HasSpec() &&
		len(llmSvc.Spec.Router.Route.HTTP.Spec.ParentRefs) > 0 {
		return llmSvc.Spec.Router.Route.HTTP.Spec.ParentRefs
	}
	if llmSvc.Spec.Router != nil && llmSvc.Spec.Router.Gateway.HasRefs() {
		return ToParentRefs(llmSvc.Spec.Router.Gateway.Refs)
	}
	if cfg == nil {
		return nil
	}
	ref := gwapiv1.ParentReference{
		Group: ptr.To(gwapiv1.Group("gateway.networking.k8s.io")),
		Kind:  ptr.To(gwapiv1.Kind("Gateway")),
		Name:  gwapiv1.ObjectName(cfg.IngressGatewayName),
	}
	if cfg.IngressGatewayNamespace != "" && cfg.IngressGatewayNamespace != llmSvc.GetNamespace() {
		ns := gwapiv1.Namespace(cfg.IngressGatewayNamespace)
		ref.Namespace = &ns
	}
	return []gwapiv1.ParentReference{ref}
}

func (r *LLMISVCReconciler) ensureTLSPassthroughListener(ctx context.Context, llmSvc *v1alpha2.LLMInferenceService, ref gwapiv1.ParentReference) (gwapiv1.SectionName, error) {
	gw := &gwapiv1.Gateway{}
	key := types.NamespacedName{
		Name:      string(ref.Name),
		Namespace: llmSvc.GetNamespace(),
	}
	if ref.Namespace != nil && *ref.Namespace != "" {
		key.Namespace = string(*ref.Namespace)
	}
	if err := r.Get(ctx, key, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("parent Gateway %s/%s not found", key.Namespace, key.Name)
		}
		return "", fmt.Errorf("failed to get parent Gateway %s/%s: %w", key.Namespace, key.Name, err)
	}

	if name, ok := findTLSPassthroughListener(gw); ok {
		return name, nil
	}

	if !isOwnedBy(gw, llmSvc) {
		return "", fmt.Errorf("parent Gateway %s/%s has no TLS passthrough listener on port 443; add protocol: TLS, tls.mode: Passthrough", key.Namespace, key.Name)
	}

	gw.Spec.Listeners = append(gw.Spec.Listeners, gwapiv1.Listener{
		Name:     tlsPassthroughListenerName,
		Port:     443,
		Protocol: gwapiv1.TLSProtocolType,
		TLS: &gwapiv1.ListenerTLSConfig{
			Mode: ptr.To(gwapiv1.TLSModePassthrough),
		},
		AllowedRoutes: &gwapiv1.AllowedRoutes{
			Namespaces: &gwapiv1.RouteNamespaces{From: ptr.To(gwapiv1.NamespacesFromAll)},
		},
	})
	if err := r.Update(ctx, gw); err != nil {
		return "", fmt.Errorf("failed to add TLS passthrough listener to managed Gateway %s/%s: %w", key.Namespace, key.Name, err)
	}
	return tlsPassthroughListenerName, nil
}

func findTLSPassthroughListener(gw *gwapiv1.Gateway) (gwapiv1.SectionName, bool) {
	for _, listener := range gw.Spec.Listeners {
		if listener.Protocol != gwapiv1.TLSProtocolType {
			continue
		}
		if listener.TLS == nil || listener.TLS.Mode == nil || *listener.TLS.Mode != gwapiv1.TLSModePassthrough {
			continue
		}
		if listener.Port != 0 && listener.Port != 443 {
			continue
		}
		return listener.Name, true
	}
	return "", false
}

func isOwnedBy(obj client.Object, owner *v1alpha2.LLMInferenceService) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == owner.UID && ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

func (r *LLMISVCReconciler) discoverTLSRouteGateways(ctx context.Context, route *gwapiv1.TLSRoute) ([]ResolvedGateway, error) {
	resolved := make([]ResolvedGateway, 0, len(route.Spec.ParentRefs))
	for _, ref := range route.Spec.ParentRefs {
		gw := &gwapiv1.Gateway{}
		key := types.NamespacedName{
			Name:      string(ref.Name),
			Namespace: route.GetNamespace(),
		}
		if ref.Namespace != nil && *ref.Namespace != "" {
			key.Namespace = string(*ref.Namespace)
		}
		if err := r.Get(ctx, key, gw); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("failed to get Gateway %s/%s: %w", key.Namespace, key.Name, err)
		}
		resolved = append(resolved, ResolvedGateway{Gateway: gw, ParentRef: ref})
	}
	return resolved, nil
}

func (r *LLMISVCReconciler) updateTLSRoutingStatus(llmSvc *v1alpha2.LLMInferenceService, route *gwapiv1.TLSRoute, gateways []ResolvedGateway) {
	addresses := make([]v1alpha2.SourcedAddress, 0)
	for _, host := range route.Spec.Hostnames {
		addresses = append(addresses, v1alpha2.SourcedAddress{
			Addressable: duckv1.Addressable{URL: apis.HTTPS(string(host))},
		})
	}
	if len(addresses) == 0 {
		for _, gw := range gateways {
			for _, addr := range gw.Gateway.Status.Addresses {
				if addr.Value != "" {
					addresses = append(addresses, v1alpha2.SourcedAddress{
						Addressable: duckv1.Addressable{URL: apis.HTTPS(addr.Value)},
					})
				}
			}
		}
	}
	if len(addresses) == 0 {
		addresses = append(addresses, v1alpha2.SourcedAddress{
			Addressable: duckv1.Addressable{
				URL: apis.HTTPS(workloadServiceName(llmSvc) + "." + llmSvc.GetNamespace() + ".svc"),
			},
		})
	}
	llmSvc.Status.Addresses = addresses
}

func semanticTLSRouteIsEqual(e *gwapiv1.TLSRoute, c *gwapiv1.TLSRoute) bool {
	return equality.Semantic.DeepEqual(e.Spec.Rules, c.Spec.Rules) &&
		equality.Semantic.DeepDerivative(e.Spec.ParentRefs, c.Spec.ParentRefs) &&
		equality.Semantic.DeepDerivative(e.Spec.Hostnames, c.Spec.Hostnames) &&
		equality.Semantic.DeepDerivative(e.Labels, c.Labels) &&
		!hasStaleControllerLabels(e.Labels, c.Labels)
}
