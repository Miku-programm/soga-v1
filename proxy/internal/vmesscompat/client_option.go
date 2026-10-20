package vmess

import "github.com/gofrs/uuid/v5"

type ClientOption func(*Client)

// ClientWithLegacyUUID permits interoperability testing of the historical
// alterId=0 MD5 header, without changing its encryption or packet framing.
func ClientWithLegacyUUID(id string) ClientOption {
	return func(client *Client) {
		user, err := uuid.FromString(id)
		if err != nil {
			user = uuid.NewV5(uuid.Nil, id)
		}
		client.alterId = 1
		client.alterKey = [16]byte(user)
	}
}

func ClientWithGlobalPadding() ClientOption {
	return func(client *Client) {
		client.globalPadding = true
	}
}

func ClientWithAuthenticatedLength() ClientOption {
	return func(client *Client) {
		client.authenticatedLength = true
	}
}

func ClientWithTimeFunc(timeFunc TimeFunc) ClientOption {
	return func(client *Client) {
		client.time = timeFunc
	}
}
