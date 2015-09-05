# Mantle
Mantle is an deployment method for Mesosphere's Marathon utility that enables multi-user encrypted JSON.

Mantle enables operations teams to pass out public keys to developers to encode their cleartext ENV variables that are common in JSON POSTs to Marathon. The operations team can then decode with the associated private key and deploy, all in a single utility. 

## Build & Install

1. ```go build mantle.go```
1. ```sudo ln -s /usr/local/bin/mantle /path/to/binary/mantle```
1. ```mkdir ~/.mantle```
1. ```touch ~/.mantle/config.yaml``` 

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

2. ```vi marathon_data.json```:

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

Add as many ```ENC[eyaml_key:cleartext_value]``` as you need. 

3. ```mantle -encode marathon_data.json```: Encodes the cleartext values in each ENC[] statement with the user's public key. 

Adds those key/values to the eyaml file, and saves the eyaml file to ```$eyaml_directory/$user.yaml``` as:

```yaml
---
my_license_key: !!binary |
  iFpLHn3wsr6/ZpoolepdT7uhp6hRq/2Tr+LyJXOpJAxkulMsb1pxE8GjKlR9iTTIV9IYnU
  JeIibAaDqfq0SZF8i8xjN6Tx6Ytx3d8BBu2pCT3nDuqpGEDqnZUZDkjp6eRScAtbsPzB8m
  taVfEO9j7zEpU/pWTr9x/awsK8gGp/E=
prod_caleb_secret: !!binary |
  IGpl8fRKGol+XHnCIsha0fTVIsTiq1sdbZ/l0PplAzBdPN+vmjn5Cg7fBeHKoT+7+RCyId
  Yu+7O/gUK1R5zGHJgXA9BV9I3Fh+/dCb3W+c3NFFQNfivHxoad8ggZIX1xk/EyJQAJHTRD
  WypeeyIswps1o5cv1DXj2rJbjBJ33hA=
production_secret: !!binary |
  Sc2D2DlrXf+rsZ6Yovr2/0AE5ZhwfRgKuHax3c3zxDIRvpCcfjqGvbXQUOpE/NwUAu/hNt
  km1vHJ3CgQIwr1Y8SD3WVQ1O2KO87bhcQHmB4HTFsLCtW6m0KsqI5okCSUnsR+yAhKYfqt
  2MBjh38IN3JQz3PbA2psfhrzAg8rt7M=
qa_mongo_pw: !!binary |
  sOOZCr1RsNQT56UZJVxqi39oSC6r5qazGsRncnHP4rdRIAELwW1qME+bBMqhlUh4enqYkM
  vIk6ebR5Oxt+luxAJR5yCfP4Ol7OZjCHIwOCnW5l50ekOuBnJWxhUEQMZe+4DMsK9G+ml0
  /W1mX71ogSK7Kxcn32Ttb2vK9jDfY/k=
user: some_user 
``` 

A new "safe" JSON is saved to ```$safe_dir/marathon_data.json``` as:

```yaml
{
        "container": {
                "docker": {
                        "image": "some_repo/some_container_image",
                        "network": "BRIDGE",
                        "portMappings": [
                                {
                                        "containerPort": 5050,
                                        "hostPort": 0,
                                        "protocol": "tcp"
                                }
                        ]
                },
                "type": "DOCKER"
        },
        "cpus": 0.5,
        "env": {
                "JEFFS_SECRET": "DEC[production_secret]",
                "MONGO_PASSWORD": "DEC[qa_mongo_pw]",
                "MY_LICENSE_KEY": "DEC[my_license_key]",
                "SAFE_DATA": "This is safe"
        },
        "id": "my-service",
        "instances": 1,
        "mem": 1024,
        "upgradeStrategy": {
                "maximumOverCapacity": 0.4,
                "minimumHealthCapacity": 0.8
        }
}
``` 

4. ```mantle -deploy ~/.mantle/safe/marathon_data.json```: Deploys the "safe" JSON data, first decrypting the DEC[] statements, then POSTing that decrypted JSON to each specified Marathon in your config.yaml. 

The final POST from our example, with decrypted data:

```json
{
        "container": {
                "docker": {
                        "image": "some_repo/some_container_image",
                        "network": "BRIDGE",
                        "portMappings": [
                                {
                                        "containerPort": 5050,
                                        "hostPort": 0,
                                        "protocol": "tcp"
                                }
                        ]
                },
                "type": "DOCKER"
        },
        "cpus": 0.5,
        "env": {
                "JEFFS_SECRET": "13adfafd%^$^$\u0026DFS",
                "MONGO_PASSWORD": "$ecretp@$$word",
                "MY_LICENSE_KEY": "12345",
                "SAFE_DATA": "This is safe"
        },
        "id": "my-service",
        "instances": 1,
        "mem": 1024,
        "upgradeStrategy": {
                "maximumOverCapacity": 0.4,
                "minimumHealthCapacity": 0.8
        }
}
```

## General Usage Guidelines
We developed Mantle as a way for developers to generate their own configuration. An operations person (or persons) hands out each user a public key, (generated with ``` mantle -generate -u sally```). When Sally gets her key, she can use Mantle to encode all her secret values. 

We keep Mantle eyaml_dir and safe_dir as Git repo's for our developers. When Sally need to deploy a new machine with secret data she can encode the JSON with her public key using ```Mantle -encode clear.json```. Sally then commits and pushes the updated eyaml_dir and safe_dir to git. 

An operations person with the private key can then double check the configuration, and deploy with her private key for Sally.


