package main

import (
	"bytes"
	json "encoding/json"
	"github.com/crowdsecurity/crowdsec/cmd/api/controllers"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type Data struct {
	Machines []controllers.CreateMachineInput `json:"machines"`
	Alerts   []controllers.CreateAlertInput   `json:"alerts"`
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

	// Create alerts
	for _, alert := range data.Alerts {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(alert)
		res, err := http.Post(alertsURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		io.Copy(os.Stdout, res.Body)
		time.Sleep(1 * time.Second)
	}
}
