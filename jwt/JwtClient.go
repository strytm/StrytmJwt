package jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

func CreateToken(model ModelJwt , key string) (string, error) {
	// create the token
	token := jwt.New(jwt.SigningMethodHS256)

	claims := make(jwt.MapClaims)

	// set some claims                                                                                                                                                                           
	claims["username"] = model.Username
	claims["userID"] = model.UserID
	claims["exp"] = model.ExpireTime
	claims["iss"] = model.Iss

	token.Claims = claims
	//Sign and get the complete encoded token as string
	return token.SignedString([]byte(key))

}

func IsValidToken(tokenValue string , key string) (ModelJwt, error) {
	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error){

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(key) , nil
	})

	var jwtModel = ModelJwt{}

	if err != nil{
		return jwtModel, err
	}

	if token.Valid{


		err := mapstructure.Decode(token.Claims.(jwt.MapClaims), &jwtModel)
		if err != nil{
			return jwtModel , err
		}
		return jwtModel , nil
	}else
	{
		return jwtModel , errors.New("tokem moshkel darad")
	}
}


