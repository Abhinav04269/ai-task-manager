package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

var jwtKey = []byte("your_secret_key")

// User structure
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	r := gin.Default()

	// Authentication routes
	r.POST("/login", loginHandler)
	r.POST("/signup", signupHandler)

	// Task management routes (protected)
	authRoutes := r.Group("/tasks")
	authRoutes.Use(authMiddleware)
	{
		authRoutes.POST("/create", createTaskHandler)
		authRoutes.GET("/list", listTasksHandler)
	}

	r.Run(":8080")
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Simulated authentication
	if user.Username != "test" || user.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func signupHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Signup endpoint (Implement DB storage)"})
}

func createTaskHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Task created! (Implement DB logic)"})
}

func listTasksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"tasks": []string{"Task 1", "Task 2"}})
}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		c.Abort()
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	c.Set("username", claims.Username)
	c.Next()
}
