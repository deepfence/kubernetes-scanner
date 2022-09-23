package util

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"math/rand"
	"strings"
	"time"
)

func GetIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetDatetimeNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000")
}

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

func PrintJSON(d interface{}) string {
	s, _ := json.Marshal(d)
	return string(s)
}

// ToKafkaRestFormat data needs to be in this format for kafka rest proxy
// {"records":[{"value":<record1>},{"value":record2}]}
func ToKafkaRestFormat(data []map[string]interface{}) string {
	values := make([]string, len(data))
	for index, d := range data {
		encoded, err := json.Marshal(&d)
		if err != nil {
			logrus.Errorf("failed to encode doc: %s", err)
			continue
		}
		values[index] = "{\"value\":" + string(encoded) + "}"
	}
	return "{\"records\":[" + strings.Join(values, ",") + "]}"
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
