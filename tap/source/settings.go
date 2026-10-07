package source

import "os"

// DisablePort443FilterEnvVarName disables the hardcoded "port not 443" BPF
// exclusion so L4 traffic on :443 (TLS legs, raw TCP) is captured. Default is
// false (37.0 behavior: :443 excluded). Set to "1" to include :443.
const DisablePort443FilterEnvVarName = "KUBESHARK_DISABLE_PORT_443_FILTER"

func disablePort443Filter() bool {
	return os.Getenv(DisablePort443FilterEnvVarName) == "1"
}
