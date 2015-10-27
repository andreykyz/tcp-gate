package main

import (
	"encoding/json"
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
		Error.Printf("Failed to open config file %s", filename)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		Error.Println("error:", err)
	}
	Info.Println(config.Users)
}
