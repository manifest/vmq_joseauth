# VerneMQ JOSE Authentication Plugin

[![Build Status][travis-img]][travis]

The plugin for VerneMQ that is providing client authentication via JSON Web Tokens (JWT).



### Keys

Currently, only keys in PEM and DER formats are supported.
To be processed by the plugin, key files must follow the name convention:
- For PEM keys: `pem:issuer[:kid][:anything]`
- For DER keys: `der:issuer:[kid]:alg[:anything]`
Key files should be accessible for the application.
`keys_directory` application environment variable is pointing to the directory with keys.



### Process of authentication

- Key is chosen by token's `iss` claim (and also by its `kid` parameter if provided).
- Verification of token's signature is performed against the chosen key and its algorithm.
- Following token's claims will be verified `exp`, `nbf`, `iat` by default
	(the behavior can be changed by setting `verify_options` application environment variable).
- UserName is matched agains pattern (`[rest]` by default, matches any value;
	the pattern can be changed by setting `username_pattern` application environment variable).
- ClientId is matched agains pattern (`[rest]` by default, matches any value;
	the pattern can be changed by setting `client_id_pattern` application environment variable).



### Configuration

It's possible to rewrite plugin application environment variables when plugin is being enabled
by putting the `vernemq.conf` configuration file into the `etc` directory of VerneMQ release.
The path to configuration file can be changed by setting `config_file` application environment variable.




### How To Use

In the following example we will create a pair of keys.
The public key will be written to the directory accessible for the plugin application
and private one will be used to create an access token. 

```erlang
%% Generating a pair of keys
Iss = <<"example.org">>,
Alg = <<"ES256">>,
{Pub, Priv} = jose_jwa:generate_key(Alg).

%% Storing the public key into the file `pem:example.org`
file:write_file(<<"priv/keys/pem:", Iss/binary>>, jose_pem:key(Alg, Pub)).

%% Creating an access token
Token =
  jose_jws_compact:encode(
    #{iss => <<"example.org">>,
      aud => <<"app.example.org">>,
      sub => <<"joe">>,
      exp => 4607280000},
    Alg,
    Priv).
```

Now, we can use created access token to send messages.

```bash
## Sending a message to the broker (plugin should be enabled)
mosquitto_pub -h localhost -t topic -m hello -i joe -u joe -P 
```


### License

The source code is provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[travis]:https://travis-ci.org/manifest/vmq_joseauth?branch=master
[travis-img]:https://secure.travis-ci.org/manifest/vmq_joseauth.png

