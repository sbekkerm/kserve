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
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// KBSResourceIdRegexp validates KBS resource ID format: kbs:///<repo>/<type>/<tag>.
// Each segment allows alphanumeric characters, hyphens, underscores, and dots.
// Query parameters are intentionally not supported; the three-segment path is
// the standard KBS addressing scheme defined by the Confidential Containers project.
var KBSResourceIdRegexp = regexp.MustCompile(`^kbs:///[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)

// ConfidentialTLSMissingWarning is returned when confidential serving is enabled
// without KBS-fetched serving certificates.
const ConfidentialTLSMissingWarning = "confidential.enabled without confidential.tls protects encrypted model artifacts only; inference traffic is not attested TLS and remains visible to the host. Set spec.model.confidential.tls (certResourceId and keyResourceId) to fetch serving certificates from KBS"

// ConfidentialTLSSchedulerForbidden is returned when confidential TLS is combined
// with InferencePool/EPP (spec.router.scheduler).
const ConfidentialTLSSchedulerForbidden = "InferencePool/EPP is not supported with confidential TLS; omit spec.router.scheduler for TLS passthrough, or omit spec.model.confidential.tls for EPP"

// ConfidentialTLSSchedulerRouteForbidden is returned when confidential TLS
// passthrough (spec.router.route) is combined with spec.router.scheduler.
const ConfidentialTLSSchedulerRouteForbidden = "confidential TLS passthrough (spec.router.route) cannot be used with spec.router.scheduler; EPP requires Gateway TLS terminate. Omit spec.router.route when scheduler is set"

// ConfidentialTLS holds the optional serving-certificate KBS resource IDs.
// A non-nil value means spec.model.confidential.tls was set.
type ConfidentialTLS struct {
	CertResourceId *string
	KeyResourceId  *string
	CAResourceId   *string
}

// ValidateConfidentialSpec validates confidential model serving configuration.
// It is shared between InferenceService (v1beta1) and LLMInferenceService
// webhooks to avoid duplicating the validation logic.
func ValidateConfidentialSpec(enabled bool, resourceId *string, tls *ConfidentialTLS, uri string, basePath *field.Path) (admission.Warnings, field.ErrorList) {
	var warnings admission.Warnings
	var allErrs field.ErrorList

	confidentialPath := basePath.Child("confidential")
	tlsPath := confidentialPath.Child("tls")

	if tls != nil && !enabled {
		allErrs = append(allErrs, field.Forbidden(tlsPath,
			"confidential.tls requires confidential.enabled to be true"))
		return warnings, allErrs
	}

	if !enabled {
		return warnings, allErrs
	}

	// Warn if OCI URI is used with confidential
	if strings.HasPrefix(uri, "oci://") {
		warnings = append(warnings,
			"confidential has no effect with OCI URIs; OCI image decryption is handled by the container runtime via runtimeClassName")
	}

	// Warn if PVC URI is used with confidential
	if strings.HasPrefix(uri, "pvc://") {
		warnings = append(warnings,
			"confidential has no effect with PVC URIs; the storage-initializer is not injected for PVC volumes")
	}

	if tls == nil {
		warnings = append(warnings, ConfidentialTLSMissingWarning)
	}

	// Validate resourceId format if provided
	if resourceId != nil && *resourceId != "" {
		if !KBSResourceIdRegexp.MatchString(*resourceId) {
			allErrs = append(allErrs, field.Invalid(
				confidentialPath.Child("resourceId"),
				*resourceId,
				"must be in the format kbs:///<repo>/<type>/<tag>"))
		}
	}

	if tls != nil {
		allErrs = append(allErrs, validateConfidentialTLS(tls, tlsPath)...)
	}

	return warnings, allErrs
}

func validateConfidentialTLS(tls *ConfidentialTLS, tlsPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	certSet := tls.CertResourceId != nil && *tls.CertResourceId != ""
	keySet := tls.KeyResourceId != nil && *tls.KeyResourceId != ""
	if certSet != keySet {
		allErrs = append(allErrs, field.Invalid(tlsPath, tls,
			"certResourceId and keyResourceId must be set together"))
	} else if !certSet {
		allErrs = append(allErrs, field.Required(tlsPath.Child("certResourceId"),
			"certResourceId and keyResourceId are required when confidential.tls is set"))
		allErrs = append(allErrs, field.Required(tlsPath.Child("keyResourceId"),
			"certResourceId and keyResourceId are required when confidential.tls is set"))
	}

	validateID := func(id *string, name string) {
		if id == nil || *id == "" {
			return
		}
		if !KBSResourceIdRegexp.MatchString(*id) {
			allErrs = append(allErrs, field.Invalid(
				tlsPath.Child(name),
				*id,
				"must be in the format kbs:///<repo>/<type>/<tag>"))
		}
	}
	validateID(tls.CertResourceId, "certResourceId")
	validateID(tls.KeyResourceId, "keyResourceId")
	validateID(tls.CAResourceId, "caResourceId")

	return allErrs
}

// ValidateConfidentialTLSRouter rejects combining confidential TLS with
// InferencePool/EPP. HTTPRoute+EPP remains valid when tls is omitted.
func ValidateConfidentialTLSRouter(tlsSet, hasScheduler, hasRoute bool) field.ErrorList {
	if !tlsSet || !hasScheduler {
		return nil
	}
	var allErrs field.ErrorList
	allErrs = append(allErrs, field.Forbidden(
		field.NewPath("spec", "router", "scheduler"),
		ConfidentialTLSSchedulerForbidden,
	))
	if hasRoute {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec", "router", "route"),
			ConfidentialTLSSchedulerRouteForbidden,
		))
	}
	return allErrs
}
