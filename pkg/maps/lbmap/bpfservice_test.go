// Copyright 2018 Authors of Cilium
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

package lbmap

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LBMapTestSuite struct{}

var _ = Suite(&LBMapTestSuite{})

func createBackend(c *C, ip string, port, revnat uint16) ServiceValue {
	i := net.ParseIP(ip)
	c.Assert(i, Not(IsNil))
	v := NewService4Value(0, i, port, revnat, 0)
	c.Assert(v, Not(IsNil))
	return v
}

func (b *LBMapTestSuite) TestScaleService(c *C) {
	ip := net.ParseIP("1.1.1.1")
	c.Assert(ip, Not(IsNil))
	frontend := NewService4Key(ip, 80, 0)

	svc := newBpfService(frontend)
	c.Assert(svc, Not(IsNil))

	b1 := createBackend(c, "2.2.2.2", 80, 1)
	svc.addBackend(b1)
	c.Assert(len(svc.backendsByMapIndex), Equals, 1)
	c.Assert(len(svc.holes), Equals, 0)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b1)

	b2 := createBackend(c, "3.3.3.3", 80, 1)
	svc.addBackend(b2)
	c.Assert(len(svc.backendsByMapIndex), Equals, 2)
	c.Assert(len(svc.holes), Equals, 0)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b1)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)

	svc.deleteBackend(b1)
	c.Assert(len(svc.backendsByMapIndex), Equals, 2)
	c.Assert(len(svc.holes), Equals, 1)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)

	b3 := createBackend(c, "4.4.4.4", 80, 1)
	svc.addBackend(b3)
	c.Assert(len(svc.backendsByMapIndex), Equals, 2)
	c.Assert(len(svc.holes), Equals, 0)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b3)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)

	b4 := createBackend(c, "5.5.5.5", 80, 1)
	svc.addBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 3)
	c.Assert(len(svc.holes), Equals, 0)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b3)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b4)
	c.Assert(svc.backendsByMapIndex[3].isHole, Equals, false)

	svc.deleteBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 3)
	c.Assert(len(svc.holes), Equals, 1)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b3)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	// either b2 or b3 can be used to fill in
	c.Assert(svc.backendsByMapIndex[3].isHole && (svc.backendsByMapIndex[3].bpfValue == b3 || svc.backendsByMapIndex[3].bpfValue == b2), Equals, true)

	svc.deleteBackend(b3)
	c.Assert(len(svc.backendsByMapIndex), Equals, 3)
	c.Assert(len(svc.holes), Equals, 2)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[3].isHole, Equals, true)

	// last backend is removed, we can finally remove all backend slots
	svc.deleteBackend(b2)
	c.Assert(len(svc.backendsByMapIndex), Equals, 0)
	c.Assert(len(svc.holes), Equals, 0)

	svc.addBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 1)
	c.Assert(len(svc.holes), Equals, 0)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b4)
}

func (b *LBMapTestSuite) TestPrepareUpdate(c *C) {
	cache := newLBMapCache()

	ip := net.ParseIP("1.1.1.1")
	c.Assert(ip, Not(IsNil))
	frontend := NewService4Key(ip, 80, 0)

	b1 := createBackend(c, "2.2.2.2", 80, 1)
	b2 := createBackend(c, "3.3.3.3", 80, 1)
	b3 := createBackend(c, "4.4.4.4", 80, 1)

	bpfSvc := cache.prepareUpdate(frontend, []ServiceValue{b1, b2})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, DeepEquals, b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, DeepEquals, b2)

	backends := bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 2)
	c.Assert(backends[0], DeepEquals, b1)
	c.Assert(backends[1], DeepEquals, b2)

	bpfSvc = cache.prepareUpdate(frontend, []ServiceValue{b1, b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, DeepEquals, b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, DeepEquals, b3)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 3)
	c.Assert(backends[0], DeepEquals, b1)
	c.Assert(backends[1], DeepEquals, b2)
	c.Assert(backends[2], DeepEquals, b3)

	bpfSvc = cache.prepareUpdate(frontend, []ServiceValue{b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, Not(DeepEquals), b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, DeepEquals, b3)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 3)
	c.Assert(backends[0], Not(DeepEquals), b1)
	c.Assert(backends[1], DeepEquals, b2)
	c.Assert(backends[2], DeepEquals, b3)

	bpfSvc = cache.prepareUpdate(frontend, []ServiceValue{b1, b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, DeepEquals, b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, DeepEquals, b3)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 3)
	c.Assert(backends[0], DeepEquals, b1)
	c.Assert(backends[1], DeepEquals, b2)
	c.Assert(backends[2], DeepEquals, b3)

	bpfSvc = cache.prepareUpdate(frontend, []ServiceValue{})
	c.Assert(len(bpfSvc.backendsByMapIndex), Equals, 0)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 0)
}
