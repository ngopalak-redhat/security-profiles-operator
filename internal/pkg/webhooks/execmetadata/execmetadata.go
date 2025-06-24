/*
Copyright 2025 The Kubernetes Authors.

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

package execmetadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/go-logr/logr"
	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	ExecRequestUid = "SPO_EXEC_REQUEST_UID"
)

type Handler struct {
	log logr.Logger
}

// Ensure ExecMetadataHandler implements admission.Handler at compile time.
var _ admission.Handler = (*Handler)(nil)

func (p Handler) getPodEphermeralPatch(req admission.Request) (*jsonpatch.JsonPatchOperation, error) {
	execPodObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &execPodObject); err != nil {
		return nil, errors.New("failed to unmarshal pod exec object")
	}

	p.log.Info("execPodObject before mutate", "execPodObject", execPodObject)

	execPodObject.Spec.Containers[0].Env = append(execPodObject.Spec.Containers[0].Env,
		corev1.EnvVar{Name: ExecRequestUid, Value: string(req.UID)})

	p.log.Info("execPodObject after mutate", "execPodObject", execPodObject)

	return &jsonpatch.JsonPatchOperation{
		Operation: "replace",
		Path:      "/spec/containers/0/env",
		Value:     execPodObject.Spec.Containers[0].Env,
	}, nil
}

func (p Handler) getPodExecPatch(req admission.Request) (*jsonpatch.JsonPatchOperation, error) {
	execObject := corev1.PodExecOptions{}

	if err := json.Unmarshal(req.Object.Raw, &execObject); err != nil {

		return nil, errors.New("failed to unmarshal pod exec object")
	}

	execObject.Command = removeRegexMatches(execObject.Command,
		ExecRequestUid+"=.*")

	execObject.Command = slices.Insert(execObject.Command, 0, "env",
		fmt.Sprintf("%s=%s", ExecRequestUid, req.UID))

	p.log.Info("execObject after mutate", "execObject", execObject)

	return &jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/command",
		Value:     execObject.Command,
	}, nil
}

//nolint:gocritic
func (p Handler) Handle(_ context.Context, req admission.Request) admission.Response {

	var jsonPathOp jsonpatch.JsonPatchOperation
	if req.Kind.Kind == "PodExecOptions" {
		fmt.Println("PodExecOptions")
		podExecJsonPathOp, err := p.getPodExecPatch(req)
		if err != nil {
			return admission.Allowed("pod exec request unmodified")
		} else {
			jsonPathOp = *podExecJsonPathOp
		}
	} else if req.Kind.Kind == "Pod" {
		fmt.Println("Pod")
		podEphJsonPathOp, err := p.getPodEphermeralPatch(req)
		if err != nil {
			return admission.Allowed("pod exec request unmodified")
		} else {
			jsonPathOp = *podEphJsonPathOp
		}
	} else {
		fmt.Println("Unrecognized kind")
		return admission.Allowed("pod exec request unmodified")
	}

	jsonPathOps := []jsonpatch.JsonPatchOperation{
		jsonPathOp,
	}

	resp := admission.Patched("UID added to execmetadata", jsonPathOps...)

	// The RequestUid will be used to correlate the log from container and API server
	resp.AuditAnnotations = map[string]string{
		ExecRequestUid: string(req.UID),
	}

	fmt.Println("Modified and sent" + resp.String())

	p.log.Info("response sent", "resp", resp)

	return resp
}

func removeRegexMatches(slice []string, pattern string) []string {
	re := regexp.MustCompile(pattern)

	var result []string

	for _, s := range slice {
		if !re.MatchString(s) {
			result = append(result, s)
		}
	}

	return result
}

func RegisterWebhook(server webhook.Server) {
	server.Register(
		"/mutate-v1-exec-metadata",
		&webhook.Admission{
			Handler: &Handler{
				log: logf.Log.WithName("execmetadata"),
			},
		},
	)
}
