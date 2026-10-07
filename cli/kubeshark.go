package main

import (
	"github.com/karthick-kk/kubeshark-oss/cli/cmd"
	"github.com/karthick-kk/kubeshark-oss/cli/cmd/goUtils"
)

func main() {
	goUtils.HandleExcWrapper(cmd.Execute)
}
