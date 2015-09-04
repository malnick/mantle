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
	"strings"
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
var Eyaml map[string]interface{}

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
	// Open users eyaml file and make one if it doesnt exist
	userEymlFile := fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User)
	if _, err := os.Stat(userEymlFile); os.IsNotExist(err) {
		log.Warn(fmt.Sprintf("%s does not exist, creating.", userEymlFile))
		err := ioutil.WriteFile(userEymlFile, []byte(fmt.Sprintf("---\nuser: %s", c.User)), 0644)
		checkError(err)
	}
	efile, err := ioutil.ReadFile(fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User))
	checkError(err)
	log.Debug("eYaml File: ", fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.User))
	log.Debug("File:\n", string(efile))
	// Unmarshal the yaml to something we can use later
	err = yaml.Unmarshal(efile, &Eyaml)
	checkError(err)
	log.Debug("Marshelled YAML:\n", Eyaml)

	for jsonkey, jsonvalue := range envVars.(map[string]interface{}) {
		log.Debug(fmt.Sprintf("%s: %s", jsonkey, jsonvalue))
		match, err := regexp.Compile("^ENC\\[*")
		checkError(err)
		if match.MatchString(jsonvalue.(string)) {
			log.Debug("Matched ENC: ", jsonvalue)
			// Open eyaml file for user
			// Get users' private key and decode
			pemData, err := ioutil.ReadFile(fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.User))
			checkError(err)
			log.Debug("Private key file: ", fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.User))
			log.Debug(string(pemData))
			// Split the json match and encode the value
			encodevalue := strings.Split(strings.Split(jsonvalue.(string), ":")[1], "]")[0]
			log.Debug("Encoding value: ", encodevalue)

			Eyaml[jsonkey] = jsonvalue
		}
		// Write final eyaml file
		data, err := yaml.Marshal(&Eyaml)
		checkError(err)
		err = ioutil.WriteFile(userEymlFile, data, 0644)

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
