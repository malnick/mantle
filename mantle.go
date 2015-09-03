package main

import (
	//"crypto"
	//"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	//"io"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
)

// CLI Falgs
var configPath = flag.String("c", "./config.yaml", "Path to config.yaml.")
var verbose = flag.Bool("v", false, "Log verbosity.")
var encrypt = flag.String("encrypt", "", "Encrypt JSON. Accepts /path/to/json.json.")
var gen = flag.Bool("generate", false, "Generate PKCS keys. Deposits keys in ~/.mantle/keys.")

// Config from YAML
type Config struct {
	Marathons    []string `yaml:"marathons"`
	KeyDirectory string   `yaml:"key_directory"`
	EyamlRepo    string   `yaml:"eyaml_repo"`
}

func checkError(err error) {
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
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

func generateKeys(keyPath string) {
	privPath := fmt.Sprintf("%s/privatekey.pem", keyPath)
	//	pubPath := fmt.Sprintf("%s/publickey.pem", keyPath)
	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 1024)
	checkError(err)
	// Write Private Key
	privKeyOut, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	checkError(err)
	pem.Encode(privKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	out, _ := ioutil.ReadFile(privPath)
	log.Info("Private Key: ", privPath)
	fmt.Println(string(out))
	privKeyOut.Close()
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
	log.Debug("Configuration: ", config)

	if *gen {
		log.Info("Generating PKCS keys...")
		generateKeys(config.KeyDirectory)
	}
}
