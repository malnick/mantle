# Mantle
Mantle is an intermediary deployment stage for Mesosphere's Marathon utility that enables multi-user encrypted JSON.

Mantle enables operations teams to pass out public keys to developers to encode their cleartext ENV variables that are common in JSON POSTs to Marathon. The operations team can then decode with the associated private key and deploy, all in a single utility. 

## Available Commands

```mantle -deploy $somejson.json```: Decrypts all `DEC[$string]` statements and POSTs to Marathon(s).

```mantle -encode $somejson.json```: Encodes all `ENC[$key:$value]` statements and creates encrypted YAML file with the encoded k,v values for the user (defined in config.yaml)

```mantle -decode $somejson.json```: Decodes all `DEC[$string]` statements and returns it to STDOUT for the user in config.yaml.

## Configuration
All configuration is done via `~/.mantle/config.yaml`:

```yaml
---
# Username associated with eyaml and key
user: $your_name
# This config isn't necessary if not a user who is deploying
marathons:
  - http://my.marathon1.com
  - http://my.marathon2.com
# Directory where Mantle will store and look for your user's keys. 
key_directory: /Users/your_name/.mantle/keys
# Directory where Mantle will store the eyaml files
eyaml_dir: /Users/your_name/.mantle/eyaml
# Directory to store safe JSON 
safe_dir: /Users/your_name/.mantle/safe
```

Mantle will create the directories for you if they do not exist. However, it's recommended to use Git or another SCM utility for your eyaml and safe directories to enable streamlined sharing of new, encoded data.

## Options

#### -v | verbose
Verbose output. 

#### -generate | generate keys
Generates 1024 bit RSA public & private keys and places them in ```key_directory```

#### -u | user override
Override the default user in the config.yaml. This enables you to deploy, encode or decode with another users' keys. The key must be present in the key_directory with value of ```$ke_directory/privatekey_$user.pem``` and ```$key_directory/publickey_$user.pem```.

#### -deploy | deploy to Marathon
Accepts ```/path/to/json.json```. 

Reads JSON data and looks for ENV parameters for Docker container that has values of ```DEC[some_value]```. 

For each DEC[] statement, it searchs the $users' encrypted YAML file (```$eyaml_dir/$user.yaml```) for the encrypted value and replaces it with teh decrypted value. It then POSTs the decrypted value to Marathon(s) in config.yaml.

#### -encode | encode JSON
Accepts ```/path/to/json.json```. 

Reads JSON data and looks for ENV parameters for Docker container that has values of ```ENC[$key:$value]```. 

These are assumed to be the cleartext $value of the $key. The $value is encrypted with the users' public key, and updated in ```$eyaml_dir/$user.yaml``` for use by either -deploy or -decode later. If ```/$eyaml_dir/$user.yaml``` does not exist in $eyaml_dir, then that file is created. 

It's good practice to keep your .mantle/eyaml directory as a git repo for easy access by other users. In example, many developers be given their own encode keys. The eyaml repo could be updated as neccessary, and when ready to deploy containers, a master user with the private keys for each dev could do so.  

#### -decode | decode JSON 
Accepts ```/path/to/json.json```.

Reads JSON data and looks for ENV parameters for Docker container that has values of ```DEC[$eyaml_key]```.

This eyaml data is usually created via the ```-encode``` directive. 

# Common Patterns
Create private/public keys and eyaml data from cleartext in JSON for Marathon:

1. ```mantle -generate```: Generates keys for $user defined in config.yaml. User can be overridden with -u. Keys are stored in $key_directory specified in config.yaml.
1. ```vi cleartex_marathon_data.json```:

```json
{
  "container": {
    "type": "DOCKER",
    "docker": {
      "image": "some_repo/some_container_image",
      "network": "BRIDGE",
      "portMappings": [
        { "containerPort": 5050, "hostPort": 0, "protocol": "tcp" }
      ]
    }
  },
  "id": "my-service",
  "env": {
    "MY_LICENSE_KEY": "ENC[my_license_key:12345]",
    "MONGO_PASSWORD": "ENC[qa_mongo_pw:$ecretp@$$word]",
    "JEFFS_SECRET": "ENC[production_secret:13adfafd%^$^$&DFS]",
    "SAFE_DATA": "This is safe"
  },
  "instances": 1,
  "cpus": 0.5,
  "mem": 1024,
  "upgradeStrategy": {
    "minimumHealthCapacity": 0.8,
    "maximumOverCapacity": 0.4
  }
} 
```
