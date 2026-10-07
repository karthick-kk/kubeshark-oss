package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karthick-kk/kubeshark-oss/agent/pkg/app"
	"github.com/karthick-kk/kubeshark-oss/agent/pkg/config"
	"github.com/karthick-kk/kubeshark-oss/shared"
	basenine "github.com/up9inc/basenine/client/go"
)

func Flush(c *gin.Context) {
	if err := basenine.Flush(shared.BasenineHost, shared.BaseninePort); err != nil {
		c.JSON(http.StatusBadRequest, err)
	} else {
		c.JSON(http.StatusOK, "Flushed.")
	}
}

func Reset(c *gin.Context) {
	if err := basenine.Reset(shared.BasenineHost, shared.BaseninePort); err != nil {
		c.JSON(http.StatusBadRequest, err)
	} else {
		app.ConfigureBasenineServer(shared.BasenineHost, shared.BaseninePort, config.Config.MaxDBSizeBytes, config.Config.LogLevel, config.Config.InsertionFilter)
		c.JSON(http.StatusOK, "Resetted.")
	}
}
