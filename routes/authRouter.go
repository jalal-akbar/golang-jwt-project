package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/jalal-akbar/golang-jwt-project/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/login", controllers.Login())
	incomingRoutes.POST("users/signup", controllers.Signup())
}
