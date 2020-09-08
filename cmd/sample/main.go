package main

import (
	"bytes"
	json "encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
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

	duration := flag.String("d", "2m", "Default duration is 2 minutes. Supported format (30s, 1m, 4h)")
	flag.Parse()

	jsonFile, err := ioutil.ReadFile("machines.json")
	if err != nil {
		log.Fatalln(err)
	}
	var machines []models.WatcherRegistrationRequest
	err = json.Unmarshal([]byte(jsonFile), &machines)
	if err != nil {
		log.Fatalln(err)
	}

	// Create machines
	for _, machine := range machines {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(machine)
		res, err := http.Post(machinesURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		fmt.Printf("%v\n\n", bodyString)
		time.Sleep(1 * time.Second)
	}

	jsonFile, err = ioutil.ReadFile("alerts.json")
	if err != nil {
		log.Fatalln(err)
	}
	var alerts []models.Alert
	err = json.Unmarshal([]byte(jsonFile), &alerts)
	if err != nil {
		log.Fatalln(err)
	}

	for _, alert := range alerts {
		for _, decision := range alert.Decisions {
			decision.Duration = *duration
		}
		b := new(bytes.Buffer)
		data := []models.Alert{}
		data = append(data, alert)
		json.NewEncoder(b).Encode(data)
		res, err := http.Post(alertsURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}

		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		fmt.Printf("%v\n\n", bodyString)
	}
}
