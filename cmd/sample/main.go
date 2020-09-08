package main

import (
	"bytes"
	json "encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type Data struct {
	Machines []models.WatcherRegistrationRequest `json:"machines"`
	Alerts   []models.Alert                      `json:"alerts"`
}

const URL = "http://localhost:8080/"
const machinesURL = URL + "machines"
const alertsURL = URL + "alerts"

func main() {
	jsonFile, err := ioutil.ReadFile("sample.json")
	if err != nil {
		log.Fatalln(err)
	}

	var data Data

	err = json.Unmarshal([]byte(jsonFile), &data)
	if err != nil {
		log.Fatalln(err)
	}

	// Create machines
	for _, machine := range data.Machines {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(machine)
		res, err := http.Post(machinesURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		io.Copy(os.Stdout, res.Body)
		time.Sleep(1 * time.Second)
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(data.Alerts)
	res, err := http.Post(alertsURL, "application/json;charset=utf-8", b)
	if err != nil {
		log.Fatalln(err)
	}
	io.Copy(os.Stdout, res.Body)
}
