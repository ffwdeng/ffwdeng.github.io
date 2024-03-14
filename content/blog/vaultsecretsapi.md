+++
author = "ffwde"
title = "Vault Secrets API"
date = "2023-03-21"
description = "Vault Secrets API"
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

Remember when we introduced the amazing capabilities of Vault in our [previous article]({{< relref "/blog/vault.md" >}})? As we mentioned back in the day, Vault comes with a plethora of tools that can leverage and help the developer in hooking and introducing common problem solvers in their software solution.

<!--more-->

In today’s article, we’re going to explore one very useful tool that can easily solve one of the biggest problems encountered during the definition of data exchange processes: the secrets API.

As usual, this article is meant to work as an introduction to the topic and the feature. For extensive and full professional documentation on the feature, please visit Vault’s official resources at [this link](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2).

## Why do you need secrets?
When developing a modern web application with middlewares/backends and such it’s often guaranteed that data exchange channels are established between software components, and such channel must be protected with encryption mechanisms. So, in no time, the developer will find himself with the task of managing the safety of private keys, client id/secrets, API keys, etc.

One common pitfall that can occur during this process is producing homemade solutions for the safety and privacy of such entities, which can lead to security leaks, uncovered channels, hardcoded values, and all of those bad practices that heavily decrease the quality of the software and its security level.

In these scenarios, Vault can act as a solid safe lock - a blackbox that holds the application secrets that can be safely accessed only under Vault’s secure channels. In the next paragraph, we’ll explore how.

The article refers to the KV (Key/Value) Secret Engine v2. 

How to enable and manage secrets in Vault
As per other Vault’s tools, each independent engine needs to be mounted before it can be used. But no fear: this is usually a one-liner, well documented and exposed on Vault’s official tutorials and documentation. In this case, to mount the secrets engine, it’s just needed to run the following command on a running Vault instance (to learn how to startup a Vault development instance you can check our previous article at [this link](https://blog.ffwde.com/2022/08/25/vault-protects-secrets/)):

```bash
$ vault secrets enable -version=2 kv
```
This has been easy! After performing this step and configuring the ACL policy to assess who can access the engine, storage and retrieval of secrets can begin.

Again, Vault’s excellent CLI makes this operation really easy as running:
```bash
$ vault kv put -mount=secret my-secret foo=a bar=b
```

As you can see and as the engine names suggest, the secret is stored with a name and with a series of key-value entries. It is important to note that key names must always be strings. Obviously, it is possible to store JSON and more advanced data formats by writing the key/value pairs to Vault from a JSON file or using the HTTP API.

Then, when it’s needed to read a secret, just run:
```bash
 vault kv get -mount=secret my-secret
====== Metadata ======
Key              Value
---              -----
created_time     2019-06-19T17:22:23.369372Z
custom_metadata  <nil>
deletion_time    n/a
destroyed        false
version          2

====== Data ======
Key         Value
---         -----
foo         aa
bar         bb
```

## Secrets versioning
One great feature which comes for free with Vault’s secret engine is secret versioning. When configuring the secrets engine out of the box, Vault is automatically configured to hold the last 10 versions of a secret, and this can be easily configured and tweaked. Vault automatically advances the versions of each secret with each update, so the mechanism is fully transparent to the developer.

This means that, if for any reason the developers need to recover a previous/older version of the secret, that will be an easy API call with the version parameter included:

```bash
vault kv get -mount=secret -version=3 my-secret
====== Metadata ======
Key              Value
---              -----
created_time     2019-06-19T17:20:22.985303Z
custom_metadata  <nil>
deletion_time    n/a
destroyed        false
version          3

====== Data ======
Key         Value
---         -----
foo         a
bar         b
```

HTTP API
As of now, we’ve played around with the CLI. But obviously, when running a real application and a backend, we’ll refer to the HTTP API layer to perform such operations.

The HTTP API is documented at this link. It’s easy to use and explore, and for example, the write operation of a secret is as simple as:
```bash
# create payload
$ cat <<EOF > payload.json
{
  "data": {
    "foo": "bar",
    "zip": "zap"
  }
}
EOF

# send request to Vault
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://127.0.0.1:8200/v1/secret/data/my-secret
```

While reading a secret is also performed via a simple GET HTTP request:
```bash
$ curl \
    --header "X-Vault-Token: ..." \
    https://127.0.0.1:8200/v1/secret/data/my-secret?version=2

{
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
     ...
  }
}
```

As you can see, the HTTP API uses a Vault token to perform the operations. The root token (generated at first Vault spin-up) can be used for this, but it is generally discouraged: it is better to generate a mid-privileges-level token and refer to that when working with this features layer.

## What else?
We’ve just scratched the surface of Vault’s secrets engine. The tool comes with a handy of useful features, such as upgrading from v1 to v2, saving metadata on the secrets over the data itself, restore of deleted versions, rollbacks, etc. Head over to [Vault’s website](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2) to explore all of the possibilities!


