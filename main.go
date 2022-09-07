package kspm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/deepfence/kspm/util"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"time"
)

var (
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	deepfenceKey          = flag.String("deepfence-key", "", "Deepfence key for auth")
	nodeId                = flag.String("node-id", "", "node-id of the cluster it is deployed in")
	debug                 = flag.Bool("debug", false, "set log level to debug")
)

const (
	MethodPost = "POST"
)

func main() {
	exec.Command("/bin/sh", "/home/deepfence/token.sh")
	flag.Parse()

	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	customFormatter.DisableLevelTruncation = true
	customFormatter.PadLevelText = true
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.CallerPrettyfier = func(f *runtime.Frame) (string, string) {
		return "", path.Base(f.File) + ":" + strconv.Itoa(f.Line)
	}

	logrus.SetReportCaller(true)
	logrus.SetFormatter(customFormatter)
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	config := util.Config{
		Quiet:                 *quiet,
		ManagementConsoleUrl:  *managementConsoleUrl,
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          *deepfenceKey,
		HttpServerRequired:    false,
		NodeId:                *nodeId,
	}
	config.Token, _ = getApiAccessToken(config)

	runServices(config)
}

func runServices(config util.Config) {
	registerNodeId(config)
}

func registerNodeId(config util.Config) {
	registerNodePayload := `{"node_id": "` + config.NodeId + `"}`
	resp, _, err := HttpRequest(MethodPost,
		"https://"+config.ManagementConsoleUrl+"/deepfence/v1.5/cloud_compliance/kubernetes",
		bytes.NewReader([]byte(registerNodePayload)),
		map[string]string{"Authorization": "Bearer " + config.Token}, config)
	if err != nil {
		logrus.Error(err)
	}
	var scansResponse util.ScansResponse
	err = json.Unmarshal(resp, &scansResponse)
	if err != nil {
		logrus.Error(err)
	}
	pendingScans := make(map[string]util.PendingScan)
	for scanId, scanDetails := range scansResponse.Data.Scans {
		if _, ok := pendingScans[scanId]; !ok {
			pendingScans[scanId] = scanDetails
		}
	}
}

func HttpRequest(method string, requestUrl string, postReader io.Reader, header map[string]string, config util.Config) ([]byte, int, error) {
	retryCount := 0
	statusCode := 0
	var response []byte
	for {
		httpReq, err := http.NewRequest(method, requestUrl, postReader)
		if err != nil {
			return response, 0, err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", config.DeepfenceKey)
		httpReq.Header.Set("Content-Type", "application/json")
		if header != nil {
			for k, v := range header {
				httpReq.Header.Add(k, v)
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

func getApiAccessToken(config util.Config) (string, error) {
	resp, _, err := HttpRequest(MethodPost,
		"https://"+config.ManagementConsoleUrl+"/deepfence/v1.5/users/auth",
		bytes.NewReader([]byte(`{"api_key":"`+config.DeepfenceKey+`"}`)),
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
