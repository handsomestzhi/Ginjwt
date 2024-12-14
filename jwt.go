package jwt

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"time"
)

type Jwt interface {
	CreateToken() string
	ParseToken() (jwt.MapClaims, string)
}

type JwtClient struct {
	Expire int64
	AppKey string
}

func NewJwtClient() *JwtClient {
	return &JwtClient{
		Expire: 24,
		AppKey: "wyz",
	}
}

func (j *JwtClient) CreateToken(id string) string {
	// 颁发一个有限期一小时的证书
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  id,
		"exp": time.Now().Add(time.Hour * time.Duration(j.Expire)).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, _ := token.SignedString([]byte(j.AppKey))
	return tokenString
}

func (j *JwtClient) ParseToken(tokenString string) (jwt.MapClaims, string) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return []byte(j.AppKey), nil })
	if token.Valid {
		fmt.Println("You look nice today")
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, "That's not even a token"
	} else if errors.Is(err, jwt.ErrTokenUnverifiable) {
		return nil, "We could not verify this token"
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return nil, "This token has an invalid signature"
	} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
		return nil, "Timing is everything"
	} else {
		fmt.Println("Couldn't handle this token:", err)
		return nil, "Couldn't handle this token:"
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
		return claims, ""
	} else {
		fmt.Println(err)
	}
	return nil, "Failed to parse token claims"
}

func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "未登录",
			})
			c.Abort()
			return
		}
		token = token[7:]
		claims, err := NewJwtClient().ParseToken(token)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": err,
			})
			c.Abort()
			return
		}
		id := claims["id"].(string)
		c.Set("userId", id)
		fmt.Println(id)
		c.Next()
	}
}
