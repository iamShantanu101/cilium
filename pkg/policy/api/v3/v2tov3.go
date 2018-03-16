// Copyright 2017-2018 Authors of Cilium
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

package v3

import (
	"github.com/cilium/cilium/pkg/policy/api/v2"
)

func v2RuleTov3Rule(v2Rule *v2.Rule) *Rule {
	if v2Rule == nil {
		return nil
	}
	v3Rule := &Rule{}

	v3Rule.EndpointSelector = *v2ESTov3ES(&v2Rule.EndpointSelector)

	if v3Rule.Ingress != nil {
		v3Rule.Ingress = []IngressRule{}
	}
	for _, v := range v2Rule.Ingress {
		v3Rule.Ingress = append(v3Rule.Ingress, v2IRTov3IR(&v)...)
	}

	if v3Rule.Egress != nil {
		v3Rule.Egress = []EgressRule{}
	}
	for _, v := range v2Rule.Egress {
		v3Rule.Egress = append(v3Rule.Egress, v2ERTov3ER(&v)...)
	}

	v3Rule.Labels = v2Rule.Labels.DeepCopy()

	v3Rule.Description = v2Rule.Description

	return v3Rule
}

func v2ESTov3ES(v2ES *v2.EndpointSelector) *EndpointSelector {
	if v2ES == nil {
		return nil
	}

	v3ES := &EndpointSelector{}

	if v2ES.LabelSelector != nil {
		v3ES.LabelSelector = v2ES.LabelSelector.DeepCopy()
	}

	return v3ES
}

func v2IRTov3IR(v2IR *v2.IngressRule) []IngressRule {
	if v2IR == nil {
		return nil
	}
	var (
		v3IR []IngressRule
		v3PR PortRules
	)

	if v2IR.ToPorts != nil {
		v3PR = make(PortRules, 0, len(v2IR.ToPorts))
	}
	for i, v := range v2IR.ToPorts {
		v3PR[i] = *v2PRTov3PR(&v)
	}

	for _, v := range v2IR.FromCIDR {
		fromIPs := &CIDRMeta{
			CIDR: &CIDRRule{
				CIDR: v2CIDRTov3CIDR(v),
			},
			ToPorts: v3PR.DeepCopy(),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromIPs: fromIPs})
	}

	for _, v := range v2IR.FromCIDRSet {
		fromIPs := &CIDRMeta{
			CIDR:    v2CIDRRuleTov3CIDRRule(&v),
			ToPorts: v3PR.DeepCopy(),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromIPs: fromIPs})
	}

	for _, v := range v2IR.FromEndpoints {
		fromEndpoints := &Endpoint{
			EndpointSelector: v2ESTov3ES(&v),
			ToPorts:          v3PR.DeepCopy(),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromEndpoint: fromEndpoints})
	}

	for _, v := range v2IR.FromRequires {
		fromRequires := &Endpoint{
			EndpointSelector: v2ESTov3ES(&v),
			ToPorts:          v3PR.DeepCopy(),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromRequire: fromRequires})
	}

	for _, v := range v2IR.FromEntities {
		fromEntities := &EntityRule{
			Entity:  v2EntityTov3Entity(&v),
			ToPorts: v3PR.DeepCopy(),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromEntity: fromEntities})
	}

	return v3IR
}

func v2ERTov3ER(v2ER *v2.EgressRule) []EgressRule {
	if v2ER == nil {
		return nil
	}
	var (
		v3ER []EgressRule
		v3PR PortRules
	)

	if v2ER.ToPorts != nil {
		v3PR = make(PortRules, 0, len(v2ER.ToPorts))
	}
	for i, v := range v2ER.ToPorts {
		v3PR[i] = *v2PRTov3PR(&v)
	}

	for _, v := range v2ER.ToCIDR {
		toIPs := &CIDRMeta{
			CIDR: &CIDRRule{
				CIDR: v2CIDRTov3CIDR(v),
			},
			ToPorts: v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToIPs: toIPs})
	}

	for _, v := range v2ER.ToCIDRSet {
		toIPs := &CIDRMeta{
			CIDR:    v2CIDRRuleTov3CIDRRule(&v),
			ToPorts: v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToIPs: toIPs})
	}

	for _, v := range v2ER.ToEndpoints {
		toEndpoints := &Endpoint{
			EndpointSelector: v2ESTov3ES(&v),
			ToPorts:          v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToEndpoint: toEndpoints})
	}

	for _, v := range v2ER.ToRequires {
		toRequires := &Endpoint{
			EndpointSelector: v2ESTov3ES(&v),
			ToPorts:          v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToRequire: toRequires})
	}

	for _, v := range v2ER.ToEntities {
		toEntities := &EntityRule{
			Entity:  v2EntityTov3Entity(&v),
			ToPorts: v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToEntity: toEntities})
	}

	for _, v := range v2ER.ToServices {
		toServices := &ServiceRule{
			Service: *v2ServiceTov3Service(&v),
			ToPorts: v3PR.DeepCopy(),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToService: toServices})
	}

	return v3ER
}

func v2CIDRRuleTov3CIDRRule(v2CR *v2.CIDRRule) *CIDRRule {
	var v3CR *CIDRRule
	if v2CR == nil {
		return v3CR
	}

	v2CRCpy := v2CR.DeepCopy()

	v3CR.CIDR = v2CIDRTov3CIDR(v2CRCpy.Cidr)

	if v2CR.ExceptCIDRs != nil {
		v3CR.ExceptCIDRs = make([]CIDR, 0, len(v2CR.ExceptCIDRs))
	}
	for i, v := range v2CR.ExceptCIDRs {
		v3CR.ExceptCIDRs[i] = v2CIDRTov3CIDR(v)
	}

	v3CR.Generated = v2CR.Generated

	return v3CR
}

func v2CIDRTov3CIDR(v2C v2.CIDR) CIDR {
	return CIDR(string(v2C))
}

func v2EntityTov3Entity(v2E *v2.Entity) *Entity {
	if v2E == nil {
		return nil
	}
	e := Entity(string(*v2E))
	return &e
}

func v2PRTov3PR(v2PR *v2.PortRule) *PortRule {
	if v2PR == nil {
		return nil
	}

	v3PR := &PortRule{}

	if v2PR.Rules != nil {
		if v2PR.Rules.HTTP != nil {
			v3PR.Rules.HTTP = []PortRuleHTTP{}
		}
		for _, v := range v2PR.Rules.HTTP {
			http := *v2PRHTTPTov3PRHTTP(&v)
			v3PR.Rules.HTTP = append(v3PR.Rules.HTTP, http)
		}

		if v2PR.Rules.Kafka != nil {
			v3PR.Rules.Kafka = []PortRuleKafka{}
		}
		for _, v := range v2PR.Rules.Kafka {
			kafka := *v2PRKafkaTov3PRKafka(&v)
			v3PR.Rules.Kafka = append(v3PR.Rules.Kafka, kafka)
		}
	}

	if v2PR.Ports != nil {
		v3PR.Ports = make([]PortProtocol, 0, len(v2PR.Ports))
		for i, v := range v2PR.Ports {
			v3PR.Ports[i] = *v2PPTov3PP(&v)
		}
	}

	return v3PR
}

func v2PRHTTPTov3PRHTTP(v2PRH *v2.PortRuleHTTP) *PortRuleHTTP {
	if v2PRH == nil {
		return nil
	}

	v3PRH := PortRuleHTTP{
		Host:   v2PRH.Host,
		Method: v2PRH.Method,
		Path:   v2PRH.Path,
	}

	if v2PRH.Headers != nil {
		v3PRH.Headers = make([]string, len(v2PRH.Headers))
		copy(v3PRH.Headers, v2PRH.Headers)
	}

	return &v3PRH
}

func v2PRKafkaTov3PRKafka(v2K *v2.PortRuleKafka) *PortRuleKafka {
	if v2K == nil {
		return nil
	}

	v3K := PortRuleKafka{
		Role:       v2K.Role,
		APIKey:     v2K.APIKey,
		APIVersion: v2K.APIVersion,
		ClientID:   v2K.ClientID,
		Topic:      v2K.Topic,
		// FIXME
		apiKeyInt:     KafkaRole{},
		apiVersionInt: nil,
	}

	return &v3K
}

func v2PPTov3PP(v2PP *v2.PortProtocol) *PortProtocol {
	if v2PP == nil {
		return nil
	}

	return &PortProtocol{
		Port:     v2PP.Port,
		Protocol: L4Proto(string(v2PP.Protocol)),
	}
}

func v2ServiceTov3Service(v2S *v2.Service) *Service {
	if v2S == nil {
		return nil
	}

	return &Service{
		K8sServiceSelector: v2K8sSSNTov3K8sSSN(v2S.K8sServiceSelector),
		K8sService:         v2K8sSNTov3K8sSN(v2S.K8sService),
	}
}

func v2K8sSNTov3K8sSN(v2K8sSN *v2.K8sServiceNamespace) *K8sServiceNamespace {
	if v2K8sSN == nil {
		return nil
	}

	return &K8sServiceNamespace{
		Namespace:   v2K8sSN.Namespace,
		ServiceName: v2K8sSN.ServiceName,
	}
}

func v2K8sSSNTov3K8sSSN(k8sSSN *v2.K8sServiceSelectorNamespace) *K8sServiceSelectorNamespace {

	if k8sSSN == nil {
		return nil
	}

	return &K8sServiceSelectorNamespace{
		Selector:  v2SSTov3SS(k8sSSN.Selector),
		Namespace: k8sSSN.Namespace,
	}

}

func v2SSTov3SS(v2SS v2.ServiceSelector) ServiceSelector {
	es := v2.EndpointSelector(v2SS)
	sel := v2ESTov3ES(&es)
	if sel == nil {
		return ServiceSelector(EndpointSelector{})
	}
	return ServiceSelector(*sel)
}
