package check

import (
	"fmt"

	"github.com/karthick-kk/kubeshark-oss/cli/config"
	"github.com/karthick-kk/kubeshark-oss/cli/uiUtils"
	"github.com/karthick-kk/kubeshark-oss/logger"
	"github.com/karthick-kk/kubeshark-oss/shared/kubernetes"
	"github.com/karthick-kk/kubeshark-oss/shared/semver"
)

func KubernetesApi() (*kubernetes.Provider, *semver.SemVersion, bool) {
	logger.Log.Infof("\nkubernetes-api\n--------------------")

	kubernetesProvider, err := kubernetes.NewProvider(config.Config.KubeConfigPath(), config.Config.KubeContext)
	if err != nil {
		logger.Log.Errorf("%v can't initialize the client, err: %v", fmt.Sprintf(uiUtils.Red, "✗"), err)
		return nil, nil, false
	}
	logger.Log.Infof("%v can initialize the client", fmt.Sprintf(uiUtils.Green, "√"))

	kubernetesVersion, err := kubernetesProvider.GetKubernetesVersion()
	if err != nil {
		logger.Log.Errorf("%v can't query the Kubernetes API, err: %v", fmt.Sprintf(uiUtils.Red, "✗"), err)
		return nil, nil, false
	}
	logger.Log.Infof("%v can query the Kubernetes API", fmt.Sprintf(uiUtils.Green, "√"))

	return kubernetesProvider, kubernetesVersion, true
}
