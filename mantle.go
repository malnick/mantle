package main

import (
	//"crypto"
	//"crypto/md5"
	//"crypto/rand"
	//"crypto/rsa"
	"flag"
	//"fmt"
	"gopkg.in/yaml.v2"
	//"io"
	//"os"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
)

// CLI Falgs
var configPath = flag.String("c", "./config.yaml", "Path to config.yaml.")
var verbose = flag.Bool("v", false, "Log verbosity.")

// Config from YAML
type Config struct {
	Marathons    []string `yaml:"marathons"`
	KeyDirectory string   `yaml:"key_directory"`
	EyamlRepo    string   `yaml:"eyaml_repo"`
}

func setConfig(cp string) (o Config, err error) {
	cf, err := ioutil.ReadFile(cp)
	if err != nil {
		log.Error("Are you sure file exists? ", cp)
		panic(err)
	}
	err = yaml.Unmarshal(cf, &o)
	if err != nil {
		log.Error("Is the ", cp, " proper YAML format?")
		panic(err)
	}
	return o, nil

}

func main() {
	flag.Parse()
	// Set loglevel
	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Loglevel: Debug")
	} else {
		log.SetLevel(log.InfoLevel)
		log.Info("Loglevel: Info")
	}
	// Set config
	config, _ := setConfig(*configPath)
	log.Debug(config)
}
