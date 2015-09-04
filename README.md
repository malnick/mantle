# Mantle
Mantle is an intermediary deployment stage for Mesosphere's Marathon utility. It accepts the same JSON POSTs that Marathon accepts, but looks for environment variables with values of "ENV[valueLookup]". The "valueLookup" is an arbitrary value that corosponds to a key in encrypted YAML. 

Mantle decrypts the JSON and POSTs it to a single or multiple Marathon's. It then returns only "success" or "failure" to the POSTing client so the client never receives the decrypted data. 

## Available Commands

```mantle -deploy $somejson.json```: Decrypts all `DEC[$string]` statements and POSTs to Marathon(s).

```mantle -encode $somejson.json```: Encodes all `ENC[$key:$value]` statements and creates encrypted YAML file with the encoded k,v values for the user (defined in config.yaml)

```mantle -decode $somejson.json```: Decodes all `DEC[$string]` statements and returns it to STDOUT for the user in config.yaml.

## Configuration
All configuration is done via `~/.mantle/config.yaml`:

```yaml
---
user: $your_name
marathons:
  - http://my.marathon1.com
  - http://my.marathon2.com
# Directory where Mantle will store and look for your user's keys. 
key_directory: /Users/your_name/.mantle/keys
# Directory where Mantle will store the eyaml files
eyaml_dir: /Users/your_name/.mantle/eyaml
```

## Options

#### -v | verbose
Verbose output. 

#### -generate | generate keys
Generates 1024 bit RSA public & private keys and places them in ```key_directory```

#### -deploy | deploy to Marathon
Accepts ```/path/to/json.json```. Reads JSON data and looks for ENV parameters for Docker container that has values of ```DEC[some_value]```. For each DEC[] statement, it searchs the $users' encrypted YAML file (```$eyaml_dir/$user.yaml```) for the encrypted value and replaces it with teh decrypted value. It then POSTs the decrypted value to Marathon(s) in config.yaml.

#### -encode | encode JSON
Accepts ```/path/to/json.json```. Reads JSON data and looks for ENV parameters for Docker container that has values of ```ENC[$key:$value]```. These are assumed to be the cleartext $value of the $key. The $value is encrypted with the users' public key, and updated in ```$eyaml_dir/$user.yaml``` for use by either -deploy or -decode later. If ```/$eyaml_dir/$user.yaml``` does not exist in $eyaml_dir, then that file is created. 

It's good practice to keep your .mantle/eyaml directory as a git repo for easy access by other users. In example, many developers be given their own encode keys. The eyaml repo could be updated as neccessary, and when ready to deploy containers, a master user with the private keys for each dev could do so.  


