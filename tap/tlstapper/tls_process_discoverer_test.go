package tlstapper

import (
	"testing"
)

const cid = "40009af77900ffec14133a310fa943634bd932395a160a07f481467d36fbbfdd"

// TestNormalizeCgroup covers the container-ID extraction from the
// /proc/<pid>/cgroup line across the runtimes the tapper sees. The
// cgroup-v2 + containerd case ("0::" single line, "cri-containerd-<ID>.scope")
// is the one that broke on real hosts before the last-hyphen fix.
func TestNormalizeCgroup(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cgroupv2 containerd", "0::/kubepods-burstable-pod0502972e_6f26_4a71_a8d5_cae07843d720.slice/cri-containerd-" + cid + ".scope", cid},
		{"cgroupv1 docker", "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3beae8e0_164d_4689_a087_efd902d8c2ab.slice/docker-" + cid + ".scope", cid},
		{"cgroupv1 containerd", "/system.slice/containerd-" + cid + ".scope", cid},
		{"cgroupv1 cri-crio", "/system.slice/cri-crio-" + cid + ".scope", cid},
		{"cgroupv1 bare id", "/kubepods/besteffort/pod7709c1d5-447c-428f-bed9-8ddec35c93f4/" + cid, cid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeCgroup(c.in); got != c.want {
				t.Errorf("normalizeCgroup(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
