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

package loader

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"

	"github.com/vishvananda/netlink"
)

const (
	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
)

func replaceQdisc(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	// Replacing the qdisc after the first creation will always fail with
	// the current netlink library due to the issue fixed in this PR:
	// https://github.com/vishvananda/netlink/pull/382
	//
	// FIXME GH-5423 rebase against the latest netlink library
	if err = netlink.QdiscReplace(qdisc); err != nil {
		log.WithError(err).Debugf("netlink: Replacing qdisc for %s failed", ifName)
	} else {
		log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func replaceDatapath(ctx context.Context, ifName string, objPath string, progSec string) error {
	err := replaceQdisc(ifName)
	if err != nil {
		return fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
	}

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	_, err = cmd.CombinedOutput(log, true)
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		args := []string{"-e", objPath, "-r", retCode}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
		cmd.Env = bpf.Environment()
		_, _ = cmd.CombinedOutput(log, true) // ignore errors
	}()

	// FIXME: replace exec with native call
	args := []string{"filter", "replace", "dev", ifName, "ingress",
		"prio", "1", "handle", "1", "bpf", "da", "obj", objPath,
		"sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err = cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to load tc filter: %s", err)
	}

	return nil
}
