/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

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

package kcpvpn

import (
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"k8s.io/klog"
)

type operationMode int

const (
	operationModeServer operationMode = iota
	operationModeClient
)

func (i *kcpvpn_driver) calculateOperationMode(remoteEndpoint *v1.EndpointSpec) operationMode {
	defaultValue := false
	leftPreferred, err := i.localEndpoint.Spec.GetBackendBool(v1.PreferredServerConfig, &defaultValue)
	if err != nil {
		klog.Errorf("Error parsing local endpoint config: %s", err)
	}

	rightPreferred, err := remoteEndpoint.GetBackendBool(v1.PreferredServerConfig, &defaultValue)
	if err != nil {
		klog.Errorf("Error parsing remote endpoint config %q: %s", remoteEndpoint.CableName, err)
	}

	if *leftPreferred && !*rightPreferred {
		return operationModeServer
	}

	if *rightPreferred && !*leftPreferred {
		return operationModeClient
	}

	// At this point both would like to be server, so we decide based on the cable name
	if i.localEndpoint.Spec.CableName > remoteEndpoint.CableName {
		return operationModeServer
	}

	return operationModeClient
}

func (m operationMode) String() string {
	switch m {
	case operationModeServer:
		return "server"
	case operationModeClient:
		return "client"
	default:
		return "unknown"
	}
}
