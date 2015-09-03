# Mantle
Mantle is an intermediary deployment stage for Mesosphere's Marathon utility. It accepts the same JSON POSTs that Marathon accepts, but looks for environment variables with values of "ENV[valueLookup]". The "valueLookup" is an arbitrary value that corosponds to a key in encrypted YAML. 

Mantle decrypts the JSON and POSTs it to a single or multiple Marathon's. It then returns only "success" or "failure" to the POSTing client so the client never receives the decrypted data. 

The only difference between the JSON for Mantle and the JSON for Marathon is all Mantle JSON must have a top level "user":"$name" attribute to signify which  user key to use. Mantle will return "Access denied" if the user can not decrypt the specified value. 

## Available Commands

```mantle deploy $somejson.json```: Decrypts all `DEC[$string]` statements and POSTs to Marathon(s).

```mantle encode $somejson.json```: Encodes all `ENC[$key:$value]` statements and updates git repo with encrypted YAML.

```mantle decode $somejson.json```: Decodes all `DEC[$string]` statements and returns it to STDOUT. 

## Configuration
All configuration is done via `~/.mantle/config.yaml`:

```yaml
---
marathons:
  - http://my.marathon1.com
  - http://my.marathon2.com
users:
  mary:/path/to/mary.pem
  john:/path/to/john.pem
# Git repo with eyaml 
eyaml_repo: git@github.com:mycompany/encrypted.git
```
