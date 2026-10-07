package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/karthick-kk/kubeshark-oss/cli/utils"

	"github.com/karthick-kk/kubeshark-oss/cli/apiserver"
	"github.com/karthick-kk/kubeshark-oss/cli/config"
	"github.com/karthick-kk/kubeshark-oss/cli/kubeshark/fsUtils"
	"github.com/karthick-kk/kubeshark-oss/cli/uiUtils"
	"github.com/karthick-kk/kubeshark-oss/logger"
	"github.com/karthick-kk/kubeshark-oss/shared/kubernetes"
)

func runKubesharkView() {
	kubernetesProvider, err := getKubernetesProviderForCli()
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	url := config.Config.View.Url

	if url == "" {
		exists, err := kubernetesProvider.DoesServiceExist(ctx, config.Config.KubesharkResourcesNamespace, kubernetes.ApiServerPodName)
		if err != nil {
			logger.Log.Errorf("Failed to found kubeshark service %v", err)
			cancel()
			return
		}
		if !exists {
			logger.Log.Infof("%s service not found, you should run `kubeshark tap` command first", kubernetes.ApiServerPodName)
			cancel()
			return
		}

		url = GetApiServerUrl(config.Config.View.GuiPort)

		response, err := http.Get(fmt.Sprintf("%s/", url))
		if err == nil && response.StatusCode == 200 {
			logger.Log.Infof("Found a running service %s and open port %d", kubernetes.ApiServerPodName, config.Config.View.GuiPort)
			return
		}
		logger.Log.Infof("Establishing connection to k8s cluster...")
		startProxyReportErrorIfAny(kubernetesProvider, ctx, cancel, config.Config.View.GuiPort)
	}

	apiServerProvider := apiserver.NewProvider(url, apiserver.DefaultRetries, apiserver.DefaultTimeout)
	if err := apiServerProvider.TestConnection(); err != nil {
		logger.Log.Errorf(uiUtils.Error, fmt.Sprintf("Couldn't connect to API server, for more info check logs at %s", fsUtils.GetLogFilePath()))
		return
	}

	logger.Log.Infof("Kubeshark is available at %s", url)

	if !config.Config.HeadlessMode {
		uiUtils.OpenBrowser(url)
	}

	utils.WaitForFinish(ctx, cancel)
}
