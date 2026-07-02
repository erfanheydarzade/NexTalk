package encoding

import (
	"encoding/base64"
	"encoding/json"
)

func EncodeBase64JSON(v any) (string, error) {
    b, err := json.Marshal(v)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(b), nil
}