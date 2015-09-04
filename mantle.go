package main

import (
	//"crypto"
	//"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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
	// For reading in and out json and yaml data
	var EncodeJson interface{}
	var Eyaml map[string]interface{}
	// Read in the json to encode
	jsonFile, err := ioutil.ReadFile(encodeThis)
	checkError(err)
	err = json.Unmarshal(jsonFile, &EncodeJson)
	checkError(err)
	log.Debug("JSON mapped: ", EncodeJson)
	// Get just the env vars for parsing then create a new json map to dump just the keys in for convienience
	envVars := EncodeJson.(map[string]interface{})["env"]
	safejson := EncodeJson.(map[string]interface{})
	log.Debug("Safe JSON: ", safejson)
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
			encodekey := strings.Split(strings.Split(jsonvalue.(string), ":")[0], "[")[1]
			log.Debug("Encoding value: ", encodevalue)
			// Extract the PEM-encoded data block
			block, _ := pem.Decode(pemData)
			if block == nil {
				log.Error("bad key data: %s", "not PEM-encoded")
				os.Exit(1)
			}
			if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
				log.Error("unknown key type %q, want %q", got, want)
				os.Exit(1)
			}
			// Decode the RSA private key
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Error("bad private key: %s", err)
				os.Exit(1)
			}
			encodedvalue, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, []byte(encodevalue), []byte("userEymlFile"))
			checkError(err)
			// Add the encoded value to eyaml
			Eyaml[jsonkey] = string(encodedvalue)
			log.Debug(Eyaml)
			// Update the encoded value in the safejson for convienience
			//safejson["env"] = make(map[string]string)
			safejson["env"].(map[string]interface{})[jsonkey] = fmt.Sprintf("DEC[%s]", encodekey)
		}
	}
	// Write final eyaml file
	data, err := yaml.Marshal(&Eyaml)
	checkError(err)
	err = ioutil.WriteFile(userEymlFile, []byte(fmt.Sprintf("---\n%s\n\n", string(data))), 0644)
	checkError(err)
	// Dump the convience JSON to STDOUT
	json, err := json.Marshal(&safejson)
	checkError(err)
	log.Info(fmt.Sprintf("Safe JSON:\n%s", json))
}

func deployToMarathon(json2deploy string, c Config) {
	var jsondata map[string]interface{}
	jsonfile, err := ioutil.ReadFile(json2deploy)
	checkError(err)
	err = json.Unmarshal(jsonfile, &jsondata)
	checkError(err)
	log.Debug(fmt.Sprintf("JSON Data:\n%s", jsondata))
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
	if len(*deploy) > 0 {
		log.Info("Deploying ", *deploy)
		deployToMarathon(*deploy, config)
	}
}
