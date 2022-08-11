package tokenWrapper

import "golang.org/x/oauth2"

type AccessToken struct {
	token *oauth2.Token
}

func NewAccessToken(token *oauth2.Token) *AccessToken {
	return &AccessToken{
		token: token,
	}
}

// need to export method so the libraries will be able to get the token
func (t *AccessToken) Token() (*oauth2.Token, error) {
	return t.token, nil
}
