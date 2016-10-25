package main

import (
	md5 "crypto/md5"
	"strconv"

	log "github.com/Sirupsen/logrus"
	gcfg "gopkg.in/gcfg.v1"
)

type UserConfig struct {
	Name     string
	Password string
	Skipack  bool
	Datath   int
	Timeout  int
}

type UserInfo struct {
	Name     string
	Password string
	hash     [16]byte
	enabled  bool
	Skipack  bool
	Datath   int
	Timeout  int
}

// ServerInfo provide IP:Port to bind
type ServerInfo struct {
	IP   string
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
	for userIDStr, _ := range cfg.config.User {
		userID, _ := strconv.ParseUint(userIDStr, 10, 32)
		if uint32(userID) > id {
			id = uint32(userID)
		}
	}
	if id > idMax {
		id = idMax
	}
	cfg.User = make([]UserInfo, id+1)
	for _, user := range cfg.User {
		user.enabled = false
	}
	for userIDStr, user := range cfg.config.User {
		userID, _ := strconv.ParseUint(userIDStr, 10, 32)
		if uint32(userID) > idMax {
			log.Warningf("Skip user (%s) id(%u) more then %d", user.Name, userID, idMax)
			continue
		}
		cfg.User[userID].Name = user.Name
		cfg.User[userID].enabled = true
		cfg.User[userID].hash = md5.Sum([]byte(user.Password))
		cfg.User[userID].Skipack = user.Skipack
		cfg.User[userID].Datath = user.Datath
		cfg.User[userID].Timeout = user.Timeout
		if cfg.User[userID].Datath == 0 || cfg.User[userID].Timeout == 0 {
			cfg.User[userID].Datath = 1000000
			cfg.User[userID].Timeout = 60 * 60 * 60
		}
		log.Debug("timeout ", cfg.User[userID].Timeout, " datath ", cfg.User[userID].Datath)
		log.Debugf("id %d user %s pass %s hash %x skipAck %t", userID, user.Name, user.Password, cfg.User[userID].hash, cfg.User[userID].Skipack)
	}
}
