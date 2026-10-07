package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/karthick-kk/kubeshark-oss/agent/pkg/controllers"
)

func QueryRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/query")

	routeGroup.POST("/validate", controllers.PostValidate)
}
