package main

import (
	//"crypto"
	"bytes"
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
	"net/http"
	"os"
	"os/user"
)

var un, _ = user.Current()
var home = un.HomeDir
var mantlehome = fmt.Sprintf("%s/.mantle", home)

// CLI Falgs
var configPath = flag.String("config", strings.Join([]string{home, "/.mantle/config.yaml"}, ""), "The path to the configuration file.")
var verbose = flag.Bool("v", false, "Log verbosity.")
var encode = flag.String("encode", "", "Encrypt JSON. Accepts /path/to/json.json.")
var decode = flag.String("decode", "", "Decode JSON. Accepts /path/to/json.json.")
var deploy = flag.String("deploy", "", "Deploy JSON to Marathon. Accepts /path/to/json.json.")
var gen = flag.Bool("generate", false, "Generate PKCS keys. Deposits keys in ~/.mantle/keys.")
var username = flag.String("u", un.Username, "Override user in config.yaml.")

// Config from YAML
type Config struct {
	Marathons      []string `yaml:"marathons"`
	KeyDirectory   string   `yaml:"key_directory"`
	EyamlDirectory string   `yaml:"eyaml_dir"`
	SafeDir        string   `yaml:"safe_dir"`
	Username       string   `yaml:"username"`
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
		log.Warn("config.yaml not found: ", cp)
		log.Warn("Generating base config: ", cp)
		var base Config
		base.KeyDirectory = fmt.Sprintf("%s/keys", mantlehome)
		base.EyamlDirectory = fmt.Sprintf("%s/eyaml", mantlehome)
		base.SafeDir = fmt.Sprintf("%s/safe", mantlehome)
		base.Marathons = []string{"http://my.marathon1.com", "http://my.marathon2.com"}
		base.Username = *username
		writeme, err := yaml.Marshal(&base)
		checkError(err)
		err = ioutil.WriteFile(cp, []byte(fmt.Sprintf("---\n%s", writeme)), 0644)
		if err != nil {
			log.Error("Issue writing base config file: ", cp)
			checkError(err)
		}
		log.Warn("Please update new base config file before deploying with Mantle.")
		log.Warn(fmt.Sprintf("Base configuration:\n%s", []byte(fmt.Sprintf("---\n%s", writeme))))
		log.Warn("Once updated, please run Mantle again. Exiting.")
		os.Exit(1)
	}
	err = yaml.Unmarshal(cf, &o)
	if err != nil {
		log.Error("Is the ", cp, " proper YAML format?")
		panic(err)
	}
	if len(*username) > 0 {
		o.Username = *username
	}
	// Check that directories exist, and if not create them.
	if _, err := os.Stat(o.KeyDirectory); err != nil {
		log.Warn(o.KeyDirectory, ": key directory specified in config.yaml does not exist. Creating with mode 0700.")
		err := os.Mkdir(o.KeyDirectory, 0700)
		checkError(err)
	}
	if _, err := os.Stat(o.EyamlDirectory); err != nil {
		log.Warn(o.EyamlDirectory, ": eyaml directory specified in config.yaml does not exist. Creating with mode 0644.")
		err := os.Mkdir(o.EyamlDirectory, 0755)
		checkError(err)
	}
	if _, err := os.Stat(o.SafeDir); err != nil {
		log.Warn(o.SafeDir, ": safe directory specified in config.yaml does not exist. Creating with mode 0644.")
		err := os.Mkdir(o.SafeDir, 0755)
		checkError(err)
	}
	return o, nil
}

func generateKeys(c Config) {
	keyPath := c.KeyDirectory
	username := c.Username
	privPath := fmt.Sprintf("%s/privatekey_%s.pem", keyPath, username)
	pubPath := fmt.Sprintf("%s/publickey_%s.pem", keyPath, username)
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
	// Create an interface for the safe data
	safejson := EncodeJson.(map[string]interface{})
	log.Debug("ENV: ", envVars)
	// Open users eyaml file and make one if it doesnt exist
	userEymlFile := fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.Username)
	if _, err := os.Stat(userEymlFile); os.IsNotExist(err) {
		log.Warn(fmt.Sprintf("%s does not exist, creating.", userEymlFile))
		err := ioutil.WriteFile(userEymlFile, []byte(fmt.Sprintf("---\nusername: %s", c.Username)), 0644)
		checkError(err)
	}
	efile, err := ioutil.ReadFile(fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.Username))
	checkError(err)
	log.Debug("eYaml File: ", fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.Username))
	log.Debug("File:\n", string(efile))
	// Unmarshal the yaml to something we can use later
	err = yaml.Unmarshal(efile, &Eyaml)
	checkError(err)

	// Get users' private key and decode
	//pemData, err := ioutil.ReadFile(fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.User))

	for jsonkey, jsonvalue := range envVars.(map[string]interface{}) {
		log.Debug(fmt.Sprintf("%s: %s", jsonkey, jsonvalue))
		match, err := regexp.Compile("^ENC\\[*")
		checkError(err)
		if match.MatchString(jsonvalue.(string)) {
			// Split the json match and encode the value
			log.Debug("Encrypting value: ", jsonvalue.(string))
			encodevalue := strings.Split(strings.Split(jsonvalue.(string), ":")[1], "]")[0]
			encodekey := strings.Split(strings.Split(jsonvalue.(string), ":")[0], "[")[1]
			encodedvalue, err := crypto("encrypt", c, encodevalue)
			checkError(err)
			// Add the encoded value to eyaml
			Eyaml[encodekey] = string(encodedvalue)
			// Update the encoded value in the safejson for convienience
			safejson["env"].(map[string]interface{})[jsonkey] = fmt.Sprintf("DEC[%s]", encodekey)
		}
	}
	// Write final eyaml file
	data, err := yaml.Marshal(&Eyaml)
	checkError(err)
	err = ioutil.WriteFile(userEymlFile, []byte(fmt.Sprintf("---\n%s\n\n", string(data))), 0644)
	checkError(err)
	// Dump Eyaml to STDOUT
	log.Info("eyaml saved: ", userEymlFile)
	// Dump the convience JSON to STDOUT
	jsonout, err := json.Marshal(&safejson)
	checkError(err)
	var out bytes.Buffer
	err = json.Indent(&out, []byte(jsonout), "", "\t")
	checkError(err)
	log.Info(fmt.Sprintf("Safe JSON:\n%s", string(out.Bytes())))
	// And write it to the safe
	safejsonname := strings.Split(encodeThis, "/")[len(strings.Split(encodeThis, "/"))-1]
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", c.SafeDir, safejsonname), out.Bytes(), 0644)
	checkError(err)
	log.Info("Saving safe JSON for decode: ", fmt.Sprintf("%s/%s", c.SafeDir, safejsonname))
}

func decodeJson(json2deploy string, c Config) []byte {
	// Some objects to dump data into
	var jsondata map[string]interface{}
	var eyamldata map[string]interface{}
	// Open the json and read it into our object
	jsonfile, err := ioutil.ReadFile(json2deploy)
	checkError(err)
	err = json.Unmarshal(jsonfile, &jsondata)
	checkError(err)
	log.Debug(fmt.Sprintf("JSON Data:\n%s", jsonfile))
	// Get some env data
	env := jsondata["env"]
	log.Debug("Env: ", env)
	// Open users' eyaml data and read it into the object
	usereyaml := fmt.Sprintf("%s/%s.yaml", c.EyamlDirectory, c.Username)
	log.Debug("Reading in eyaml: ", usereyaml)
	eyamlfile, err := ioutil.ReadFile(usereyaml)
	checkError(err)
	err = yaml.Unmarshal(eyamlfile, &eyamldata)
	checkError(err)
	log.Debug("eyaml:\n", string(eyamlfile))
	// Make unsafe json object
	unsafejson := jsondata
	// Range over json
	for jsondeckey, jsondecvalue := range env.(map[string]interface{}) {
		log.Debug("Testing for DEC: ", jsondecvalue, " ", jsondeckey)
		match, err := regexp.Compile("^DEC\\[*")
		checkError(err)
		if match.MatchString(jsondecvalue.(string)) {
			log.Debug("Matched DEC: ", jsondecvalue)
			jsondecvalue := strings.Split(strings.Split(jsondecvalue.(string), "[")[1], "]")[0]
			// Get value from yaml
			for eyamlkey, eyamlvalue := range eyamldata {
				log.Debug(fmt.Sprintf("Comparing %s and %s", eyamlkey, jsondecvalue))
				if eyamlkey == jsondecvalue {
					log.Debug("Found encrypted value in eyaml: ", eyamlkey)
					log.Debug("Byte stream of binary value: ", []byte(eyamlvalue.(string)))
					decrypted, err := crypto("decrypt", c, eyamlvalue.(string))
					checkError(err)
					log.Info("Decrypted ", eyamlkey, " to ", string(decrypted))
					unsafejson["env"].(map[string]interface{})[jsondeckey] = string(decrypted)
				}
			}
			if match.MatchString(unsafejson["env"].(map[string]interface{})[jsondeckey].(string)) {
				log.Warn(jsondecvalue, " was not found in ", usereyaml, ".")
				log.Warn("Please make sure you're decrypting with the correct user.")
			}
		}
	}
	// Marshal to JSON and print to STDOUT
	jsonout, err := json.Marshal(&unsafejson)
	checkError(err)
	var out bytes.Buffer
	err = json.Indent(&out, []byte(jsonout), "", "\t")
	checkError(err)
	log.Info(fmt.Sprintf("Decoded JSON:\n%s", string(out.Bytes())))
	return jsonout
	//postToMarathon(jsonout, c)
}

func postToMarathon(post []byte, c Config) {
	marathons := c.Marathons
	if len(marathons) < 1 {
		log.Error("No marathons found in config.yaml. Exiting.")
		os.Exit(1)
	}
	for _, uri := range marathons {
		log.Info("POSTing to ", uri)
		req, err := http.NewRequest("POST", uri, bytes.NewBuffer(post))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		checkError(err)
		defer resp.Body.Close()
		log.Debug("Response Status:", resp.Status)
		log.Debug("response Headers:", resp.Header)
		body, _ := ioutil.ReadAll(resp.Body)
		log.Info("Response Body:", string(body))
	}
}

func crypto(mode string, c Config, data string) ([]byte, error) {
	log.Debug("RSA to block cipher conversion started.")
	// Decrypt or encrypt
	if mode == "decrypt" {
		log.Debug("Decrypting...")
		// Open private key data or fail gracefully
		privPath := fmt.Sprintf("%s/privatekey_%s.pem", c.KeyDirectory, c.Username)
		pemData, err := ioutil.ReadFile(privPath)
		if err != nil {
			log.Error(privPath, " was not found. Try '-generate' first.")
			log.Error("Remember, keys are by-user. Ensure running this command with the key for the correct user.")
			log.Error("Ex: mantle -decode|-deploy /path/to/json -u some_user")
			log.Error("Or ensure the user specified in config.yaml has a key that exists.")
			checkError(err)
		}
		log.Debug("Private key file: ", privPath)
		log.Debug(string(pemData))
		checkError(err)
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
		decryptedvalue, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, []byte(data), []byte(">"))
		checkError(err)
		return decryptedvalue, nil

	} else if mode == "encrypt" {
		log.Debug("Encrypting...")
		// Open public key data or fail gracefully
		pubPath := fmt.Sprintf("%s/publickey_%s.pem", c.KeyDirectory, c.Username)
		pubData, err := ioutil.ReadFile(pubPath)
		if err != nil {
			log.Error(pubPath, " was not found. Try '-generate' first.")
			checkError(err)
		}
		log.Debug("Private key file: ", pubPath)
		log.Debug(string(pubData))
		// Create block cipher from RSA key
		block, _ := pem.Decode(pubData)
		if block == nil {
			log.Error("Bad key data: %s", "not PEM encoded")
			os.Exit(1)
		}
		if got, want := block.Type, "RSA PUBLIC KEY"; got != want {
			log.Error("Unknown key type %q, want %q", got, want)
			os.Exit(1)
		}
		pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
		checkError(err)
		//pubkey = *pubkey.(*rsa.PublicKey)
		encodedvalue, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubkey.(*rsa.PublicKey), []byte(data), []byte(string(">")))
		checkError(err)
		log.Debug("Not showing string value as contents are binary bytes can screw up terminal output.")
		log.Debug("Encoded value: ", encodedvalue)
		return encodedvalue, nil

	} else {
		log.Error("Not a known mode: ", mode)
		os.Exit(1)
	}
	return []byte("nope"), nil
}

func main() {
	fmt.Println(`   *                   )            (            `)
	fmt.Println(`  ( )        (       ( /(    *   )   )\ )        `)
	fmt.Println(`  )\))(      )\     )\())   )  /(  (()/(   (    `)
	fmt.Println(` ((_)()\  ((((_)(   ((_)\   ( )(_))  /(_))  )\   `)
	fmt.Println(` (_()((_)  )\ _ )\   _((_) (_(_())  (_))   ((_)  `)
	fmt.Println(` |  \/  |  (_)_\(_) | \| | |_   _|  | |    | __| `)
	fmt.Println(` | |\/| |   / _ \   | .  |   | |    | |__  | _|  `)
	fmt.Println(` |_|  |_|  /_/ \_\  |_|\_|   |_|    |____| |___| `)

	flag.Parse()
	// Set loglevel
	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Loglevel: Debug")
	} else {
		log.SetLevel(log.InfoLevel)
		log.Info("Loglevel: Info")
	}
	log.Debug("User data: ", un)
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
		log.Info("Decoding ", *decode)
		decodeJson(*decode, config)
	}
	if len(*encode) > 0 {
		log.Info("Encoding ", *encode)
		encodeToYaml(*encode, config)
	}
	if len(*deploy) > 0 {
		log.Info("Deploying ", *deploy)
		postToMarathon(decodeJson(*deploy, config), config)
	}
}
