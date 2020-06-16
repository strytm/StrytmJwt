package jwt

type ModelJwt struct {
	ExpireTime int64
	Iss        string
	Username   string
	UserID     uint
	IsAdmin    uint
}
