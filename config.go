package main

import (
	md5 "crypto/md5"
	log "github.com/Sirupsen/logrus"
	gcfg "gopkg.in/gcfg.v1"
	"strconv"
)

type UserConfig struct {
	Name     string
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
	idMax := uint32(100000)
	err := gcfg.ReadFileInto(&cfg.config, filename)
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}
	id := uint32(0)
	for userIdStr, _ := range cfg.config.User {
		userId, _ := strconv.ParseUint(userIdStr, 10, 32)
		if uint32(userId) > id {
			id = uint32(userId)
		}
	}
	if id > idMax {
		id = idMax
	}
	cfg.User = make([]UserInfo, id+1)
	for _, user := range cfg.User {
		user.enabled = false
	}
	for userIdStr, user := range cfg.config.User {
		userId, _ := strconv.ParseUint(userIdStr, 10, 32)
		if uint32(userId) > idMax {
			log.Warningf("Skip user (%s) id(%u) more then %d", user.Name, userId, idMax)
			continue
		}
		cfg.User[userId].Name = user.Name
		cfg.User[userId].enabled = true
		cfg.User[userId].hash = md5.Sum([]byte(user.Password))
		log.Debugf("id %d user %s pass %s hash %x", userId, user.Name, user.Password, cfg.User[userId].hash)
	}
}
