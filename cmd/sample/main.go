package main

import (
	"bytes"
	json "encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type Data struct {
	Machines []models.WatcherRegistrationRequest `json:"machines"`
	Alerts   []models.Alert                      `json:"alerts"`
}

const URL = "http://localhost:8080/"
const machinesURL = URL + "watchers"
const alertsURL = URL + "alerts"
const loginURL = URL + "watchers/login"

type Session struct {
	Token     string
	MachineID string
	Expire    time.Time
}

type loginRespone struct {
	Code   int       `json:"code"`
	Expire time.Time `json:"expire"`
	Token  string    `json:"token"`
}

func main() {
	sessions := make(map[string]*Session, 0)
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

	for _, machine := range machines {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(machine)
		res, err := http.Post(loginURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		response := &loginRespone{}
		if err := json.Unmarshal(bodyBytes, response); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Reponse : %+v \n", string(bodyBytes))

		session := &Session{
			Token:     response.Token,
			Expire:    response.Expire,
			MachineID: machine.MachineID,
		}
		sessions[machine.MachineID] = session
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
		if alert.MachineID == "" {
			log.Fatal("please provide machine_id to push alert")
		}
		if _, ok := sessions[alert.MachineID]; !ok {
			log.Fatal("don't have session for machine '%s' to push alerts", machine.MachineId)
		}
		httpToken := sessions[alert.MachineID].Token
		for _, decision := range alert.Decisions {
			decision.Duration = *duration
		}
		b := new(bytes.Buffer)
		data := []models.Alert{}
		data = append(data, alert)
		json.NewEncoder(b).Encode(data)

		httpClient := &http.Client{}
		req, _ := http.NewRequest("POST", alertsURL, b)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", httpToken))
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
		res, err := httpClient.Do(req)
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
