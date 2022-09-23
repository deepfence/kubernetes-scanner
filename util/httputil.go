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

func GetKubernetesClusterId() string {
	var kubeSystemNamespaceUid string
	serviceHost := "kubernetes.default.svc"
	// servicePort := "443"
	caCertPool := x509.NewCertPool()
	caCert, caToken, err := getK8sCaCert()
	if err != nil {
		logrus.Error("Error in reading certs:" + err.Error())
		return ""
	}
	caCertPool.AppendCertsFromPEM(caCert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}}

	// Get kubeSystemNamespaceUid
	url := fmt.Sprintf("https://%s/api/v1/namespaces/kube-system", serviceHost)
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewBuffer([]byte{}))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(caToken)))
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					var kubeSystemNamespaceDetails k8sNamespaceDetails
					err = json.Unmarshal(bodyBytes, &kubeSystemNamespaceDetails)
					if err == nil {
						kubeSystemNamespaceUid = kubeSystemNamespaceDetails.Metadata.UID
					}
				}
			}
		} else {
			logrus.Error(err.Error())
		}
	} else {
		logrus.Error(err.Error())
		logrus.Error(err)
	}
	return kubeSystemNamespaceUid
}

func getK8sCaCert() ([]byte, []byte, error) {
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, nil, err
	}
	caToken, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return caCert, caToken, err
}

type k8sNamespaceDetails struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
}
