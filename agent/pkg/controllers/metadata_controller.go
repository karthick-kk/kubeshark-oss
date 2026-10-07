package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karthick-kk/kubeshark-oss/agent/pkg/version"
	"github.com/karthick-kk/kubeshark-oss/shared"
)

func GetVersion(c *gin.Context) {
	resp := shared.VersionResponse{Ver: version.Ver}
	c.JSON(http.StatusOK, resp)
}
