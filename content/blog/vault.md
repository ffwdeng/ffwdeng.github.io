+++
author = "ffwde"
title = "Introduction to HashiCorp Vault"
date = "2022-08-25"
description = "Introduction to HashiCorp Vault"
tags = [
  "security",
  "applications",
  "vault",
  "sre"
]
categories = [
  "sre",
  "series"
]
+++

In FFWDE, we extensively use HashiCorp’s stack. It’s modular, easy to install, with a moderate learning curve, extensive documentation and community. If offers very interesting and mature solutions, from virtualization to secrets storage.

<!--more-->

Today, we will focus on one of the most well known and used tools of the HashiCorp stack: Vault. Vault is constantly evolving, and at the time of writing it has become literally a jack-of-all-trades for any web-based application you are working on. Do you need a quick and functional way to authenticate users via user and password? Vault offers that. Do you have an internal LDAP server that you need to use as source-of-truth for your authentication process? Vault offers that. Do you need advanced instrumentation, such as multi-factor authentication, OIDC authentication or an RBAC layer, relying over Vault’s services? Guess what, Vault has all of that too.

If you want to go deep dive into Vault’s possibilities, HashiCorp offers an extensive documentation right on their website at [this](https://www.vaultproject.io/docs) link.

## Spinning up a Vault development server
To start playing around with Vault, you just need a terminal and spin up a development server: such server will hold all of the configurations in memory, so everything will wipe up when restarting it, but it’s the absolute best way to get introduced in the technology.

This is really easy! Just grab the latest [Vault executable](https://learn.hashicorp.com/tutorials/vault/getting-started-install#install-vault) for your platform of choice and run:

```bash
$ vault server -dev

==> Vault server configuration:

             Api Address: http://127.0.0.1:8200
                     Cgo: disabled
         Cluster Address: https://127.0.0.1:8201
              Listener 1: tcp (addr: "127.0.0.1:8200", cluster address: "127.0.0.1:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
               Log Level: info
                   Mlock: supported: false, enabled: false
           Recovery Mode: false
                 Storage: inmem
                 Version: Vault v1.4.1

WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
and starts unsealed with a single unseal key. The root token is already
authenticated to the CLI, so you can immediately begin using Vault.

You may need to set the following environment variable:

    $ export VAULT_ADDR='http://127.0.0.1:8200'

The unseal key and root token are displayed below in case you want to
seal/unseal the Vault or re-authenticate.

Unseal Key: 1+yv+v5mz+aSCK67X6slL3ECxb4UDL8ujWZU/ONBpn0=
Root Token: s.XmpNPoi9sRhYtdKHaQhkHP6x

Development mode should NOT be used in production installations!

==> Vault server started! Log data will stream in below:
```

As you can see, Vault is now running on port 8200 of your machine. In order to reach it, as the logs recommended, you’ll need to export two environment variables:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN=s.XmpNPoi9sRhYtdKHaQhkHP6x # generated via the previous command
```

This way, your `vault` local binary will know where to reach the running dev server on your machine and will supply the root token in subsequent requests.

## What can Vault do for your application?
Modern web applications often come up with a plethora of requirements which require libraries hunting and/or custom implementations: user authentication and authorization, social authentication, high-level RBAC layer, secrets storage, etc. Here, we will explore some of the features that Vault offers that can be quickly integrated in your application by using Vault’s API layer.

Vault can be used standalone and within the HashiCorp’s stack context, and it offers extensive set of HTTP(S) APIs for each of the layers we’ll explore. 

### Userpass authentication
At the phase of designing and implementing a standard userpass authentication, a series of issues arise: which library should we use to safely encrypt passwords? Where should we safely store such passwords? How should I generate session tokens?

Vault offers an out of the box user pass authentication method, also offering a simple - but complete - user base management (create, update, delete, etc.)

First, we need to enable userpass authentication on the running Vault server. To do so:

```bash
$ vault auth enable userpass
```

Simple, isn’t it? This will mount the userpass engine on the Vault running server and expose the HTTP API layer, ready to be used.

Then, it’s possible to register users:
```bash
$ vault write auth/userpass/users/johndoe password=letmein123
```

Even more simple, and all of this is available though an easy to use [HTTP API](https://www.vaultproject.io/api-docs/auth/userpass) layer.

Now, our web application backend can easily perform the authentication API call towards Vault, for example when performing a standard and basic login. Via the following Go snippet, we’ll show how:
```go
func login(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var loginRequest LoginRequest
	err = json.Unmarshal(b, &loginRequest)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:8200/v1/auth/userpass/login/%s", loginRequest.Username),
		bytes.NewBuffer(b))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var vaultLoginResponse VaultLoginResponse

	err = json.Unmarshal(body, &vaultLoginResponse)

	...

}
```

The POST request will authenticate the user towards the Vault server.
In case the login is successful, Vault will return a client_token:
```json
{
   "request_id":"d477e52e-61a7-f53f-4666-071187193646",
   ...
   "auth":{
      "client_token":"hvs.CAESIEv8zalABFarS1FmH_auWob72-53MVuDZQ0nKrx02muhGh4KHGh2cy44aFlWeVNWUnhHUFJtaEl6N0tROTlTRUg",
      ...
   }
}
```

How to use such token? 

Vault can verify its validity and lifetime via the token lookup [API](https://www.vaultproject.io/api-docs/auth/token#lookup-a-token). This way, it is possible to verify that the user that has detached it has a valid session and is properly authenticated. Additionally, the token will have a series of metadata that we can use for other purposes, such as roles and available permissions.

## What else?
We will explore other Vault’s possibilities for your applications in future articles, such as multi-factor authentication, OIDC authentication, LDAP driver, secrets management, etc. Keep following us!
