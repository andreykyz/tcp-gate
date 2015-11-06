package main

import (
	log "github.com/Sirupsen/logrus"
)

type MyFormatter struct {
}

func (f *MyFormatter) Format(entry *log.Entry) ([]byte, error) {
	return append([]byte(entry.Message), '\n'), nil
}
