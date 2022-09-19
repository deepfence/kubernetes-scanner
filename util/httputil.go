package util

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	MethodPost = "POST"
)

func HttpRequest(method string, requestUrl string, postData string, header map[string]string, config Config) ([]byte, int, error) {
	retryCount := 0
	statusCode := 0
	var response []byte
	for {
		httpReq, err := http.NewRequest(method, requestUrl, bytes.NewReader([]byte(postData)))
		if err != nil {
			return response, 0, err
		}
		httpReq.Close = true
		httpReq.Header.Set("deepfence-key", config.DeepfenceKey)
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+config.Token)
		if header != nil {
			for k, v := range header {
				httpReq.Header.Set(k, v)
			}
		}
		client, _ := buildHttpClient()
		resp, err := client.Do(httpReq)
		if err != nil {
			return response, 0, err
		}
		statusCode = resp.StatusCode
		if statusCode == 200 {
			response, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return response, statusCode, err
			}
			resp.Body.Close()
			break
		} else {
			if retryCount > 10 {
				response, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					logrus.Error(err)
				}
				errMsg := fmt.Sprintf("Unable to complete request on %s. Got %d - %s", requestUrl, resp.StatusCode, response)
				resp.Body.Close()
				return response, statusCode, errors.New(errMsg)
			}
			if statusCode == 401 {
				config.Token, err = GetApiAccessToken(config)
				if err != nil {
					logrus.Error(err.Error())
				}
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}
	return response, statusCode, nil
}

func buildHttpClient() (*http.Client, error) {
	// Set up our own certificate pool
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1024,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Minute,
				KeepAlive: 15 * time.Minute,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
		Timeout: 15 * time.Minute,
	}
	return client, nil
}

func GetApiAccessToken(config Config) (string, error) {
	resp, _, err := HttpRequest(MethodPost,
		"https://"+config.ManagementConsoleUrl+"/deepfence/v1.5/users/auth",
		`{"api_key":"`+config.DeepfenceKey+`"}`,
		nil, config)
	if err != nil {
		return "", err
	}
	var dfApiAuthResponse dfApiAuthResponse
	err = json.Unmarshal(resp, &dfApiAuthResponse)
	if err != nil {
		return "", err
	}
	if !dfApiAuthResponse.Success {
		return "", errors.New(dfApiAuthResponse.Error.Message)
	}
	return dfApiAuthResponse.Data.AccessToken, nil
}

type dfApiAuthResponse struct {
	Data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
	Success bool `json:"success"`
}
