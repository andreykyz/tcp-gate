package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"os"
)

type UserInfo struct {
	Id     uint32
	Name   string
	Passwd string
}

type Configuration struct {
	Users []UserInfo
}

func readConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Errorf("Failed to open config file %s", filename)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Error("error:", err)
	}
	log.Info(config.Users)
}
