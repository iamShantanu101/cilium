// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

// EgressRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - For now, combining ToPorts and ToCIDR in the same rule is not supported
//   and such rules will be rejected. In the future, this will be supported and
//   if if multiple members of the structure are specified, then all members
//   must match in order for the rule to take effect.
type EgressRule struct {
	// ToEndpoints is a list of endpoints identified by an EndpointSelector to
	// which the endpoints subject to the rule are allowed to communicate.
	//
	// Example:
	// Any endpoint with the label "role=frontend" can communicate with any
	// endpoint carrying the label "role=backend".
	//
	// +optional
	ToEndpoints []EndpointSelector `json:"toEndpoints,omitempty"`

	// ToRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be able to connect to other
	// endpoints. These additional constraints do no by itself grant access
	// privileges and must always be accompanied with at least one matching
	// ToEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires any endpoint to which it
	// communicates to also carry the label "team=A".
	//
	// +optional
	ToRequires []EndpointSelector `json:"toRequires,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +optional
	ToPorts []PortRule `json:"toPorts,omitempty"`

	// ToCIDR is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections. Only connections destined for
	// outside of the cluster and not targeting the host will be subject
	// to CIDR rules.  This will match on the destination IP address of
	// outgoing connections. Adding a prefix into ToCIDR or into ToCIDRSet
	// with no ExcludeCIDRs is equivalent. Overlaps are allowed between
	// ToCIDR and ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24
	//
	// +optional
	ToCIDR CIDRSlice `json:"toCIDR,omitempty"`

	// ToCIDRSet is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections to in addition to connections
	// which are allowed via FromEndpoints, along with a list of subnets contained
	// within their corresponding IP block to which traffic should not be
	// allowed. This will match on the destination IP address of outgoing
	// connections. Adding a prefix into ToCIDR or into ToCIDRSet with no
	// ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and
	// ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24 except from IPs in subnet 10.2.3.0/28.
	//
	// +optional
	ToCIDRSet CIDRRuleSlice `json:"toCIDRSet,omitempty"`

	// ToEntities is a list of special entities to which the endpoint subject
	// to the rule is allowed to initiate connections. Supported entities are
	// `world`, `cluster` and `host`
	//
	// +optional
	ToEntities EntitySlice `json:"toEntities,omitempty"`

	// ToServices is a list of services to which the endpoint subject
	// to the rule is allowed to initiate connections.
	//
	// Example:
	// Any endpoint with the label "app=backend-app" is allowed to
	// initiate connections to all cidrs backing the "external-service" service
	// + optional
	ToServices []Service `json:"toServices,omitempty"`

	// ToFQDN allows whitelisting DNS names in place of IPs. The IPs that result
	// from DNS resolution of `ToFQDN.MatchName`s are added to the same
	// EgressRule object as ToCIDRSet entries, and behave accordingly. Any L4 and
	// L7 rules within this EgressRule will also apply to these IPs.
	// The DNS -> IP mapping is re-resolved periodically from within the
	// cilium-agent, and the IPs in the DNS response are effected in the policy
	// for selected pods as-is (i.e. the list of IPs is not modified in any way).
	// Note: An explicit rule to allow for DNS traffic is needed for the pods, as
	// ToFQDN counts as an egress rule and will enforce egress policy when
	// PolicyEnforcment=default.
	// Note: If the resolved IPs are IPs within the kubernetes cluster, the
	// ToFQDN rule will not apply to that IP.
	// Note: ToFQDN cannot occur in the same policy as other To* rules.
	//
	// The current implementation has a number of limitations:
	// - The DNS resolution originates from cilium-agent, and not from the pods.
	// Differences between the responses seen by cilium agent and a particular
	// pod will whitelist the incorrect IP.
	// - DNS TTLs are ignored, and cilium-agent will repoll on a short interval
	// (5 seconds). Each change to the DNS data will trigger a policy
	// regeneration. This may result in delayed updates to the policy for an
	// endpoint when the data changes often or the system is under load.
	//
	// +optional
	ToFQDNs []FQDNSelector `json:"toFQDNs,omitempty"`
}

// GetDestinationEndpointSelectors returns a slice of endpoints selectors
// covering all L3 destination selectors of the egress rule
func (e *EgressRule) GetDestinationEndpointSelectors() EndpointSelectorSlice {
	res := append(e.ToEndpoints, e.ToEntities.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDR.GetAsEndpointSelectors()...)
	return append(res, e.ToCIDRSet.GetAsEndpointSelectors()...)
}

// IsLabelBased returns true whether the L3 destination endpoints are selected
// based on labels, i.e. either by setting ToEndpoints or ToEntities, or not
// setting any To field.
func (e *EgressRule) IsLabelBased() bool {
	return len(e.ToRequires)+len(e.ToCIDR)+len(e.ToCIDRSet)+len(e.ToServices) == 0
}
