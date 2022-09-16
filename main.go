package main

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
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
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
	_, err := exec.Command("/bin/sh", "/home/deepfence/token.sh").CombinedOutput()
	if err != nil {
		logrus.Error(err)
	} else {
		logrus.Debug("Token generated successfully")
	}
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
	logrus.Debug("Token generated success:{}", config.Token)
	fmt.Println("Token generated success:{}", config.Token)
	runServices(config)
}

func runServices(config util.Config) {
	ticker := time.NewTicker(1 * time.Minute / 2)
	for {
		select {
		case <-ticker.C:
			registerNodeId(config)
		}
	}
}

func registerNodeId(config util.Config) {
	logrus.Error(config.NodeId)
	logrus.Error(config)
	registerNodePayload := `{"node_id": "` + config.NodeId + `"}`
	resp, _, err := HttpRequest(MethodPost,
		"https://"+config.ManagementConsoleUrl+"/deepfence/v1.5/cloud_compliance/kubernetes",
		bytes.NewReader([]byte(registerNodePayload)),
		map[string]string{"Authorization": "Bearer " + config.Token}, config)
	if err != nil {
		logrus.Error(err)
		fmt.Println(err.Error())
	}
	//fmt.Println(string(resp))
	logrus.Error(string(resp))
	var scansResponse util.ScansResponse
	err = json.Unmarshal(resp, &scansResponse)
	if err != nil {
		logrus.Error(err)
	}
	pendingScans := make(map[string]util.PendingScan)
	for scanId, scanDetails := range scansResponse.Data.Scans {
		if _, ok := pendingScans[scanId]; !ok {
			pendingScans[scanId] = scanDetails
			err := SendScanStatustoConsole(scanId, "cis", "", "INPROGRESS", nil, config)

			if err != nil {
				logrus.Error(err)
			}
			scanResult, err := RunComplianceScan()
			if err != nil {
				err = SendScanStatustoConsole(scanId, "cis", err.Error(), "ERROR", nil, config)
				continue
			}
			config.ScanId = scanId
			//b, _ := json.Marshal(scanResult)
			//logrus.Error("scanResult:")
			//logrus.Error(string(b))
			complianceDocs, complianceSummary, err := ParseComplianceResults(scanResult, config)
			fmt.Println("Parsed Compliance Docs:")
			b, _ := json.Marshal(complianceDocs)
			fmt.Println(string(b))
			err = IngestComplianceResults(complianceDocs, config)
			if err != nil {
				logrus.Error(err)
			}
			extras := map[string]interface{}{
				"node_name":    config.NodeId,
				"node_id":      config.NodeId,
				"result":       complianceSummary,
				"total_checks": complianceSummary.Alarm + complianceSummary.Ok + complianceSummary.Info + complianceSummary.Skip + complianceSummary.Error,
			}
			err = SendScanStatustoConsole(config.ScanId, "cis", "", "COMPLETED", extras, config)
			if err != nil {
				logrus.Error(err)
			}
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
			if statusCode == 401 {
				config.Token, err = getApiAccessToken(config)
				logrus.Error("Token updated to :" + config.Token)
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

func RunComplianceScan() (util.ComplianceGroup, error) {
	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	//defer os.Remove(tempFileName)
	spKubePath := "/opt/steampipe/steampipe-mod-kubernetes-compliance"
	cmd := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s benchmark.nsa_cisa_v1", spKubePath, tempFileName)
	stdOut, stdErr := exec.Command("bash", "-c", cmd).CombinedOutput()
	var complianceResults util.ComplianceGroup
	if _, err := os.Stat(tempFileName); errors.Is(err, os.ErrNotExist) {
		return complianceResults, fmt.Errorf("%s: %v", stdOut, stdErr)
	}
	tempFile, err := os.Open(tempFileName)
	if err != nil {
		return complianceResults, err
	}
	results, err := ioutil.ReadAll(tempFile)
	if err != nil {
		return complianceResults, err
	}
	err = json.Unmarshal(results, &complianceResults)
	if err != nil {
		return complianceResults, err
	}
	return complianceResults, nil
}

func SendScanStatustoConsole(scanId string, scanType string, scanMsg string, status string, extras map[string]interface{}, config util.Config) error {
	scanMsg = strings.Replace(scanMsg, "\n", " ", -1)
	scanLog := map[string]interface{}{
		"scan_id":                 scanId,
		"time_stamp":              util.GetIntTimestamp(),
		"@timestamp":              util.GetDatetimeNow(),
		"scan_message":            scanMsg,
		"scan_status":             status,
		"masked":                  "false",
		"type":                    util.ComplianceScanLogsIndexName,
		"node_name":               config.NodeId,
		"node_id":                 config.NodeId,
		"kubernetes_cluster_name": config.NodeId,
		"kubernetes_cluster_id":   config.NodeId,
		"compliance_check_type":   scanType,
	}
	for k, v := range extras {
		scanLog[k] = v
	}
	scanLogJson, err := json.Marshal(scanLog)
	if err != nil {
		logrus.Error("Error parsing JSON: ", scanLog)
		return err
	}
	postReader := bytes.NewReader(scanLogJson)
	ingestScanStatusAPI := fmt.Sprintf("https://" + config.ManagementConsoleUrl + "/df-api/ingest?doc_type=" + util.ComplianceScanLogsIndexName)
	_, _, err = HttpRequest(MethodPost, ingestScanStatusAPI, postReader, nil, config)
	return err
}

func IngestComplianceResults(complianceDocs []util.ComplianceDoc, config util.Config) error {
	logrus.Debugf("Number of docs to ingest: %d", len(complianceDocs))
	docBytes, err := json.Marshal(complianceDocs)
	if err != nil {
		logrus.Error(err)
		return err
	}
	postReader := bytes.NewReader(docBytes)
	ingestScanStatusAPI := fmt.Sprintf("https://" + config.ManagementConsoleUrl + "/df-api/ingest?doc_type=" + util.ComplianceScanIndexName)
	_, _, err = HttpRequest("POST", ingestScanStatusAPI, postReader, nil, config)
	return err
}
