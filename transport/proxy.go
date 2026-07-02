package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type ProxyConfig struct {
	ProxyUrl string
}

type ProxyChatStorage struct {
	proxyUrl   string
	httpClient *http.Client
}

func NewProxyChatStorage(cfg ProxyConfig) *ProxyChatStorage {
	return &ProxyChatStorage{
		proxyUrl:   cfg.ProxyUrl,
		httpClient: &http.Client{},
	}
}

func (s *ProxyChatStorage) WritePayload(chatId, folder string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("json encode error: %w", err)
	}

	reqUrl := fmt.Sprintf("%s/api/upload?folder=%s&chatId=%s", s.proxyUrl, url.QueryEscape(folder), url.QueryEscape(chatId))
	req, err := http.NewRequest(http.MethodPost, reqUrl, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxy write error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy returned status: %s", resp.Status)
	}

	return nil
}

func (s *ProxyChatStorage) ReadPayloads(chatId, folder string) ([][]byte, error) {
	reqUrl := fmt.Sprintf("%s/api/download?folder=%s&chatId=%s", s.proxyUrl, url.QueryEscape(folder), url.QueryEscape(chatId))
	resp, err := s.httpClient.Get(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("proxy read error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status: %s", resp.Status)
	}

	var payloads []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payloads); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	var bytesPayloads [][]byte
	for _, p := range payloads {
		bytesPayloads = append(bytesPayloads, []byte(p))
	}

	return bytesPayloads, nil
}
