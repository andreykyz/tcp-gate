package main

import (
	md5 "crypto/md5"
	log "github.com/Sirupsen/logrus"
	gcfg "gopkg.in/gcfg.v1"
)

type UserConfig struct {
	Id       uint32
	Password string
}

type UserInfo struct {
	Name     string
	Password string
	hash     [16]byte
	enabled  bool
}

type ServerInfo struct {
	Ip   string
	Port uint16
}

type Configuration struct {
	config struct {
		Listen ServerInfo
		User   map[string]*UserConfig
	}
	Listen ServerInfo
	User   []UserInfo
}

func (cfg *Configuration) readConfig(filename string) {
	err := gcfg.ReadFileInto(&cfg.config, filename)
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}
	log.Info(cfg.config.User)
	var id uint32
	id = 0
	for _, user := range cfg.config.User {
		if user.Id > id {
			id = user.Id
		}
	}
	if id > 100000 {
		id = 100000
	}
	cfg.User = make([]UserInfo, id+1)
	for _, user := range cfg.User {
		user.enabled = false
	}
	for userName, user := range cfg.config.User {
		if user.Id > 100000 {
			log.Warningf("Skip user (%s) id(%u) more then 1000", userName, user.Id)
			continue
		}
		cfg.User[user.Id].Name = userName
		cfg.User[user.Id].enabled = true
		cfg.User[user.Id].hash = md5.Sum([]byte(user.Password))
		log.Infof("id %d user %s pass %s hash %x", user.Id, userName, user.Password, cfg.User[user.Id].hash)
	}
}
