package routes

import (
	"github.com/karthick-kk/kubeshark-oss/agent/pkg/controllers"

	"github.com/gin-gonic/gin"
)

// DdRoutes defines the group of database routes.
func DbRoutes(app *gin.Engine) {
	routeGroup := app.Group("/db")

	routeGroup.GET("/flush", controllers.Flush)
	routeGroup.GET("/reset", controllers.Reset)
}
