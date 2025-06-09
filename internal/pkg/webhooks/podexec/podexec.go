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

package podexec

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	RequestUserIdEnv   = "REQUEST_USER_ID"
	RequestUserNameEnv = "REQUEST_USER_NAME"
)

type podExecHandler struct {
	log logr.Logger
}

func removeRegexMatches(slice []string, pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	var result []string

	for _, s := range slice {
		if !re.MatchString(s) {
			result = append(result, s)
		}
	}

	return result, nil
}

//nolint:gocritic
func (p podExecHandler) Handle(_ context.Context, req admission.Request) admission.Response {
	execObject := corev1.PodExecOptions{}
	if err := json.Unmarshal(req.Object.Raw, &execObject); err != nil {
		p.log.Error(err, "unmarshal pod exec request")

		return admission.Allowed("pod exec request unmodified")
	}

	p.log.V(1).Info("execObject before: ", "execObject", execObject)

	var rErr error

	execObject.Command, rErr = removeRegexMatches(execObject.Command,
		RequestUserIdEnv+"=.*")
	if rErr != nil {
		p.log.Error(rErr, "request modification failed for pod exec request")

		return admission.Allowed("pod exec request unmodified")
	}

	execObject.Command, rErr = removeRegexMatches(execObject.Command,
		RequestUserNameEnv+".*")
	if rErr != nil {
		p.log.Error(rErr, "request modification failed for pod exec request")

		return admission.Allowed("pod exec request unmodified")
	}

	execObject.Command = slices.Insert(execObject.Command, 0, "env",
		fmt.Sprintf("%s=%s", RequestUserIdEnv, req.UserInfo.UID),
		fmt.Sprintf("%s=%s", RequestUserNameEnv, req.UserInfo.Username))

	p.log.V(1).Info("execObject after: ", "execObject", execObject)

	commandPatches := []map[string]interface{}{
		{
			"op":    "add",
			"path":  "/command",
			"value": execObject.Command,
		},
	}

	marshaledExec, mErr := json.Marshal(commandPatches)
	if mErr != nil {
		p.log.Error(mErr, "marshal pod exec request")

		return admission.Allowed("pod exec request unmodified")
	}

	resp := admission.PatchResponseFromRaw(req.Object.Raw, marshaledExec)

	resp.AuditAnnotations = map[string]string{
		"exec.spo.io": "User Id and username have been set",
	}

	return resp
}

// Ensure podExecHandler implements admission.Handler at compile time.
var _ admission.Handler = (*podExecHandler)(nil)

func RegisterWebhook(server webhook.Server) {
	server.Register(
		"/mutate-v1-pod-exec",
		&webhook.Admission{
			Handler: &podExecHandler{
				log: logf.Log.WithName("podexec"),
			},
		},
	)
}
