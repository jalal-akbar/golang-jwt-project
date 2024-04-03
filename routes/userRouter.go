package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/jalal-akbar/golang-jwt-project/controllers"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}
