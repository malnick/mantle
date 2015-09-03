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
	"regexp"
	//"io"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
)

// CLI Falgs
var configPath = flag.String("c", "./config.yaml", "Path to config.yaml.")
var verbose = flag.Bool("v", false, "Log verbosity.")
var encode = flag.String("encode", "", "Encrypt JSON. Accepts /path/to/json.json.")
var decode = flag.String("decode", "", "Decode JSON. Accepts /path/to/json.json.")
var deploy = flag.String("deploy", "", "Deploy JSON to Marathon. Accepts /path/to/json.json.")
var gen = flag.Bool("generate", false, "Generate PKCS keys. Deposits keys in ~/.mantle/keys.")

// Config from YAML
type Config struct {
	Marathons      []string `yaml:"marathons"`
	KeyDirectory   string   `yaml:"key_directory"`
	EyamlRepo      string   `yaml:"eyaml_repo"`
	EyamlDirectory string   `yaml:"eyaml_dir"`
	User           string   `yaml:"user"`
}

var EncodeJson interface{}

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

func generateKeys(c Config) {
	keyPath := c.KeyDirectory
	user := c.User
	privPath := fmt.Sprintf("%s/privatekey_%s.pem", keyPath, user)
	pubPath := fmt.Sprintf("%s/publickey_%s.pem", keyPath, user)
	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 1024)
	checkError(err)
	// Write Private Key
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
	})
	ioutil.WriteFile(privPath, privBytes, 0600)
	log.Info("Private Key: ", privPath)
	fmt.Println(string(privBytes))
	// Write Public Key
	ansipub, err := x509.MarshalPKIXPublicKey(&privatekey.PublicKey)
	checkError(err)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: ansipub,
	})
	ioutil.WriteFile(pubPath, pubBytes, 0644)
	log.Info("Public Key: ", pubPath)
	fmt.Println(string(pubBytes))
}
func decodeJson(decodeThis string, c Config) {
	files, err := ioutil.ReadDir(c.EyamlDirectory)
	checkError(err)
	for _, file := range files {
		log.Debug("eYaml found: ", file)
	}
}

func encodeToYaml(encodeThis string, c Config) {
	jsonFile, err := ioutil.ReadFile(encodeThis)
	checkError(err)
	err = json.Unmarshal(jsonFile, &EncodeJson)
	checkError(err)
	log.Debug("JSON mapped: ", EncodeJson)
	envVars := EncodeJson.(map[string]interface{})["env"]
	log.Debug("ENV: ", envVars)
	for k, v := range envVars.(map[string]interface{}) {
		log.Debug(fmt.Sprintf("%s: %s", k, v))
		match, err := regexp.Compile("^ENC\\[*")
		checkError(err)
		if match.MatchString(v.(string)) {
			log.Debug("Matched ENC: ", v)
			// Write the k,v to the users encrypted_$user.yaml file
			// Open eyaml file for user
			userEymlFile := fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User)
			if _, err := os.Stat(userEymlFile); os.IsNotExist(err) {
				log.Warn(fmt.Sprintf("%s does not exist, creating.", userEymlFile))
				os.Create(userEymlFile)
				checkError(err)
			}
			efile, err := ioutil.ReadFile(fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User))
			checkError(err)
			log.Debug("eYaml File: ", fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User))
			log.Debug(efile)
			// Get users' private key and decode
			pemData, err := ioutil.ReadFile(fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.User))
			checkError(err)
			log.Debug("Private key file: ", fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.User))
			log.Debug(pemData)

		}

	}

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
	// If generate is passed do the things and exit
	if *gen {
		log.Info("Generating PKCS keys...")
		generateKeys(config)
		os.Exit(0)
	}
	if len(*decode) > 0 {
		log.Info(*decode)
		os.Exit(0)
	}
	if len(*encode) > 0 {
		log.Info("Encoding ", *encode)
		encodeToYaml(*encode, config)
	}
}
