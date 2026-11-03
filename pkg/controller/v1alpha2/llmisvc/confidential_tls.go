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
	corev1 "k8s.io/api/core/v1"

	"github.com/kserve/kserve/pkg/apis/serving/v1alpha2"
	"github.com/kserve/kserve/pkg/constants"
	"github.com/kserve/kserve/pkg/utils"
)

// tlsPassthroughListenerName is the Gateway listener the TLSRoute attaches to
// when the service owns a managed Gateway.
const tlsPassthroughListenerName = "https-passthrough" //nolint:gosec // Gateway API section name, not a credential

func confidentialTLSEnabled(llmSvc *v1alpha2.LLMInferenceService) bool {
	return llmSvc != nil && llmSvc.Spec.Model.Confidential != nil && llmSvc.Spec.Model.Confidential.TLS != nil
}

// confidentialTLSPassthrough is true when north-south traffic should use a
// Gateway TLSRoute (confidential.tls + router.route + no scheduler).
func confidentialTLSPassthrough(llmSvc *v1alpha2.LLMInferenceService) bool {
	return confidentialTLSEnabled(llmSvc) &&
		llmSvc.Spec.Router != nil &&
		llmSvc.Spec.Router.Route != nil &&
		llmSvc.Spec.Router.Scheduler == nil
}

func confidentialTLSEnv(tls *v1alpha2.ConfidentialTLSSpec) *utils.ConfidentialTLSEnv {
	if tls == nil {
		return nil
	}
	env := &utils.ConfidentialTLSEnv{}
	if tls.CertResourceId != nil {
		env.CertResourceId = *tls.CertResourceId
	}
	if tls.KeyResourceId != nil {
		env.KeyResourceId = *tls.KeyResourceId
	}
	if tls.CAResourceId != nil {
		env.CAResourceId = *tls.CAResourceId
	}
	return env
}

func applyConfidentialInitConfig(initContainer *corev1.Container, llmSvc *v1alpha2.LLMInferenceService) {
	confidential := llmSvc.Spec.Model.Confidential
	if confidential == nil || !confidential.Enabled {
		return
	}
	resourceId := ""
	if confidential.ResourceId != nil {
		resourceId = *confidential.ResourceId
	}
	utils.ApplyConfidentialContainerConfig(initContainer, resourceId, confidentialTLSEnv(confidential.TLS))
}

// applyConfidentialTLSVolumes replaces the preset tls-certs Secret volume with
// an in-memory emptyDir so the serving private key is never written to etcd.
func applyConfidentialTLSVolumes(spec *v1alpha2.LLMInferenceServiceSpec) {
	replace := func(pod *corev1.PodSpec) {
		if pod == nil {
			return
		}
		ensureConfidentialTLSCertsVolume(pod)
	}
	replace(spec.Template)
	replace(spec.Worker)
	if spec.Prefill != nil {
		replace(spec.Prefill.Template)
		replace(spec.Prefill.Worker)
	}
	if spec.Router != nil && spec.Router.Scheduler != nil {
		replace(spec.Router.Scheduler.Template)
		if spec.Router.Scheduler.Tokenizer != nil {
			replace(spec.Router.Scheduler.Tokenizer.Template)
		}
	}
}

func ensureConfidentialTLSCertsVolume(podSpec *corev1.PodSpec) {
	for i := range podSpec.Volumes {
		if podSpec.Volumes[i].Name == constants.ConfidentialTLSCertsVolumeName {
			podSpec.Volumes[i].VolumeSource = corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
			}
			return
		}
	}
	podSpec.Volumes = append(podSpec.Volumes, corev1.Volume{
		Name: constants.ConfidentialTLSCertsVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
		},
	})
}

func ensureConfidentialTLSCertsMount(container *corev1.Container, readOnly bool) {
	for i := range container.VolumeMounts {
		if container.VolumeMounts[i].Name == constants.ConfidentialTLSCertsVolumeName {
			container.VolumeMounts[i].MountPath = constants.ConfidentialTLSCertsMountPath
			container.VolumeMounts[i].ReadOnly = readOnly
			return
		}
	}
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      constants.ConfidentialTLSCertsVolumeName,
		MountPath: constants.ConfidentialTLSCertsMountPath,
		ReadOnly:  readOnly,
	})
}

func attachConfidentialTLSCertsMount(podSpec *corev1.PodSpec, initContainer *corev1.Container) {
	ensureConfidentialTLSCertsVolume(podSpec)
	ensureConfidentialTLSCertsMount(initContainer, false)
}
