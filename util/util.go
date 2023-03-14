package util

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func GetKubernetesClusterId() string {
	var kubeSystemNamespaceUid string
	serviceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	servicePort := os.Getenv("KUBERNETES_SERVICE_PORT")
	caCertPool := x509.NewCertPool()
	caCert, caToken, err := getK8sCaCert()
	if err != nil {
		logrus.Error("Error in reading certs:" + err.Error())
		return ""
	}
	caCertPool.AppendCertsFromPEM(caCert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}}

	// Get kubeSystemNamespaceUid
	url := fmt.Sprintf("https://%s:%s/api/v1/namespaces/kube-system", serviceHost, servicePort)
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewBuffer([]byte{}))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(caToken)))
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := io.ReadAll(resp.Body)
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
	}
	return kubeSystemNamespaceUid
}

func getK8sCaCert() ([]byte, []byte, error) {
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, nil, err
	}
	caToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return caCert, caToken, err
}

type k8sNamespaceDetails struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
}

func GetIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetDatetimeNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// StructToMap Converts a struct to a map while maintaining the json alias as keys
func StructToMap(obj interface{}) (newMap map[string]interface{}, err error) {
	data, err := json.Marshal(obj) // Convert to a json string

	if err != nil {
		return
	}

	err = json.Unmarshal(data, &newMap) // Convert to a map
	return
}

func writeScanDataToFile(scanMsg string, filename string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	scanMsg = strings.Replace(scanMsg, "\n", " ", -1)
	if _, err = f.WriteString(scanMsg + "\n"); err != nil {
		return err
	}
	return nil
}

func getDfInstallDir() string {
	installDir, exists := os.LookupEnv("DF_INSTALL_DIR")
	if exists {
		return installDir
	} else {
		return ""
	}
}
