package tlstapper

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/karthick-kk/kubeshark-oss/logger"
	v1 "k8s.io/api/core/v1"
)

var numberRegex = regexp.MustCompile("[0-9]+")

func UpdateTapTargets(tls *TlsTapper, pods *[]v1.Pod, procfs string) error {
	containerIds := buildContainerIdsMap(pods)
	containerPids, err := findContainerPids(procfs, containerIds)

	if err != nil {
		return err
	}

	tls.ClearPids()

	for pid, pod := range containerPids {
		if err := tls.AddSSLLibPid(procfs, pid, pod.Namespace); err != nil {
			LogError(err)
		}

		if err := tls.AddGoPid(procfs, pid, pod.Namespace); err != nil {
			LogError(err)
		}
	}

	return nil
}

func findContainerPids(procfs string, containerIds map[string]v1.Pod) (map[uint32]v1.Pod, error) {
	result := make(map[uint32]v1.Pod)

	pids, err := ioutil.ReadDir(procfs)

	if err != nil {
		return result, err
	}

	logger.Log.Infof("Starting tls auto discoverer %v %v - scanning %v potential pids",
		procfs, containerIds, len(pids))

	for _, pid := range pids {
		if !pid.IsDir() {
			continue
		}

		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		cgroup, err := getProcessCgroup(procfs, pid.Name())

		if err != nil {
			continue
		}

		pod, ok := containerIds[cgroup]

		if !ok {
			continue
		}

		pidNumber, err := strconv.Atoi(pid.Name())

		if err != nil {
			continue
		}

		result[uint32(pidNumber)] = pod
	}

	return result, nil
}

func buildContainerIdsMap(pods *[]v1.Pod) map[string]v1.Pod {
	result := make(map[string]v1.Pod)

	for _, pod := range *pods {
		for _, container := range pod.Status.ContainerStatuses {
			parsedUrl, err := url.Parse(container.ContainerID)

			if err != nil {
				logger.Log.Warningf("Expecting URL like container ID %v", container.ContainerID)
				continue
			}

			result[parsedUrl.Host] = pod
		}
	}

	return result
}

func getProcessCgroup(procfs string, pid string) (string, error) {
	filePath := fmt.Sprintf("%s/%s/cgroup", procfs, pid)

	bytes, err := ioutil.ReadFile(filePath)

	if err != nil {
		logger.Log.Warningf("Error reading cgroup file %s - %v", filePath, err)
		return "", err
	}

	lines := strings.Split(string(bytes), "\n")
	cgrouppath := extractCgroup(lines)

	if cgrouppath == "" {
		return "", errors.Errorf("Cgroup path not found for %s, %s", pid, lines)
	}

	return normalizeCgroup(cgrouppath), nil
}

// extractCgroup returns the cgroup path from the lines of /proc/<pid>/cgroup.
// cgroup-v2 has a single "0::<path>" line; cgroup-v1 has one "<id>:<controllers>:<path>"
// line per hierarchy. The file always ends in a newline, so the last split element is
// empty and we must not gate on the raw line count.
func extractCgroup(lines []string) string {
	// cgroup v2: a single "0::<path>" line
	for _, line := range lines {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(strings.TrimSpace(line), "0::")
		}
	}

	// cgroup v1: prefer the pids controller line, fall back to any non-empty line
	var fallback string
	for _, line := range lines {
		if strings.Contains(line, ":pids:") {
			parts := strings.Split(line, ":")
			return parts[len(parts)-1]
		}
		if fallback == "" && strings.TrimSpace(line) != "" {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				fallback = parts[len(parts)-1]
			}
		}
	}

	return fallback
}

// cgroup in the /proc/<pid>/cgroup may look something like
//
//	/system.slice/docker-<ID>.scope
//	/system.slice/containerd-<ID>.scope
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3beae8e0_164d_4689_a087_efd902d8c2ab.slice/docker-<ID>.scope
//	0::/kubepods-burstable-pod3beae8e0_164d_4689_a087_efd902d8c2ab.slice/cri-containerd-<ID>.scope
//	/kubepods/besteffort/pod7709c1d5-447c-428f-bed9-8ddec35c93f4/<ID>
//
// This function extracts the <ID> out of the cgroup path; the <ID> must match
// the container ID ("containerd://<ID>") reported in the pod's
// containerStatuses so the tls discoverer can map it to a PID. The container
// ID is the 64-hex suffix after the last hyphen (docker-/cri-containerd-/
// cri-crio-), so we take the segment after the final hyphen rather than
// assuming a fixed runtime prefix — that is what lets it resolve on
// cgroup-v2 + containerd hosts, whose cgroup line is a single "0::" entry.
func normalizeCgroup(cgrouppath string) string {
	basename := strings.TrimSpace(path.Base(cgrouppath))

	if i := strings.LastIndex(basename, "."); i >= 0 {
		basename = basename[:i]
	}

	if i := strings.LastIndex(basename, "-"); i >= 0 {
		basename = basename[i+1:]
	}

	return basename
}
