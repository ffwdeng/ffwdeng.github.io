+++
author = "Arnar Ingason"
title = "Managing Docker registry credentials in production"
date = "2023-02-21"
description = "Managing Docker registry credentials in production"
tags = [
  "linux",
  "security",
  "docker",
  "containers",
  "sre"
]
categories = [
  "sre"
]
+++

When using docker in production eventually the time will come where manually distributing and rotating credentials becomes too cumbersome to deal with. In those situations better alternatives exist.

<!--more-->

## Credential stores and helpers

In its simplest form, when you run `docker login --username myuser --password mypassword docker.io` the following will be written in `~/.docker/config.json`:

```json
{
    "auths": {
        "docker.io": {
            "auth": "bXl1c2VyOm15cGFzc3dvcmQ="
        }
    }
}
```

Looking at the value stored in this file it may seem obfuscated somehow, great! But in reality this is just a base64 encoding of the string myuser:mypassword and base64 is as good as clear text.

And that’s where credential stores come in.

## Credential stores

Docker can be configured to use so called credential stores and offers open sourced implementations for Mac OS’s keychain, Windows Credential Manager, D-Bus Secret Service (to interact with various keyrings on linux) and pass (password manager), and those credential stores can be found [here](https://github.com/docker/docker-credential-helpers). What those credential stores offer is to securely store your credentials encrypted in your security solution of choice instead of (effectively) plain text in a JSON file.

To set it up you will need to download one of the available binaries from the releases page of the github repository and make sure it is available in your `$PATH` (`/usr/local/bin` is usually a good choice). After that you can write the following in `~/.docker/config.json`:

```json
{
  "credsStore": "pass"
}
```

In this example the pass implementation is chosen but the accepted values are `osxkeychain`, `wincred`, `secretservice` and `pass` depending on which binary was chosen.

After that is setup it will be required to still run `docker login` but this time, instead of storing the credentials in `~/.docker/config.json` it will communicate with the chosen security solution and store them there. When you then run `docker pull my.registry.io/myimage:latest` it will check if your credential store has any credentials for `my.registry.io` and if so return those to docker.

## But how does it work anyway?
Good question!

The credential stores are an external program that have to be available in `$PATH` of the docker client, follow a certain naming standard and offer a certain interface.

The name of the program has to start with `docker-credential-` and then follow with whatever you want but the rest of the name is what you put as `credsStore` in the docker config file. For example in the case of `pass` credential helper the program is called `docker-credential-pass`.

The interface is also quite simple. It has to support taking `store`, `get` and `erase` as its first argument and read the name of the registry from `stdin`. That way the credential store can be implemented in any programming language or even just a simple shell script.

That’s great and all, but we still need to do the initial login and rotating of credentials manually, which leads us to our next topic.

## Credential helpers
Docker also has a concept of credential helpers which is not really any different from the aforementioned credential stores but limits its usage to a single registry.

This is useful in cloud environments where you often don’t need to directly offer static credentials for registry authentication, like using a [managed identity](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) to authenticate to an [Azure Container Registry](https://azure.microsoft.com/en-us/products/container-registry/) or an [instance profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) to authenticate to [Amazon Elastic Container Registry](https://aws.amazon.com/ecr/). In those cases it’s possible to get credentials from simply running in a virtual machine with a managed identity or instance profile that has read access to the registry of choice.

So credential helpers are simply credential stores that only implement the get method and know how to get credentials in that one environment. Implementations exist for [Amazon’s ECR](https://github.com/awslabs/amazon-ecr-credential-helper), [Google’s GCR](https://github.com/GoogleCloudPlatform/docker-credential-gcr) and many more.

One also does exist for [Azure’s ACR](https://github.com/Azure/acr-docker-credential-helper) but it has been deprecated and requires to initiate the authentication flow with the Azure CLI. Recently we were in need of credential helper in an Azure environment that could simply use a virtual machine’s managed identity to authenticate with ACR and provide credentials, so we wrote our own and open sourced it!

Our credential helper can be found [here](https://github.com/ffwdeng/azure-acr-credential-helper/).

To set it up the following should be written in the docker config:

```json
{
  "credHelpers": {
    "<acr_id>.azurecr.io": "acr-login"
  }
}
```

Where `<acr_id>` is the `ID` of your Azure Container Registry.

After this docker can pull images in your Azure cloud environment without providing it with any credentials!

But what about cluster orchestrators?

## Clustered container orchestrators
When clustering many machines together to run your container workloads other methods may be necessary.

### Nomad
We have used Hashicorp’s Nomad extensively and when needing to provide credentials to pull docker images there are a couple of methods.

#### Providing credentials with the task
It’s possible to put the credentials directly in the task configuration:

```hcl
task "example" {
  driver = "docker"

  config {
    image = "secret/service"

    auth {
      username = "dockerhub_user"
      password = "dockerhub_password"
    }
  }
}
```

But this will be visible to anyone that can inspect the task configuration and is therefor not very secure.

#### Using a docker credential helper
Feels like we’ve come a full circle because Nomad’s docker driver can simply use a docker credential helper by reading a docker config file.

By putting the following in a Nomad agent’s config file:

```hcl
client {
  enabled = true
}

plugin "docker" {
  config {
    auth {
      config = "/path/to/docker/config.json"
    }
  }
}
```
It will now transparently use the credential helper configured in the docker config file to pull images for Nomad task workloads!

Further documentation can be found [here](https://developer.hashicorp.com/nomad/docs/drivers/docker#authentication).

### Kubernetes
There’s no denying that Kubernetes is immensely popular container orchestrator. And like with Nomad a couple of options for registry authenticating are possible.

#### Image pull secrets
The classic way that has been supported for a long time is image pull secrets.

What is needed is to create a Kubernetes secret containing the registry credentials:

```bash
kubectl create secret docker-registry regcred \
        --docker-server=<your-registry-server> \
        --docker-username=<your-name> \
        --docker-password=<your-pword> \
        --docker-email=<your-email>
```
And then in your pod definition provide it with the name of the secret to use for image pulling:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-reg
spec:
  containers:
  - name: private-reg-container
    image: <your-private-image>
  imagePullSecrets:
  - name: regcred
```
And this way the contents of the Kubernetes secret will be used for authenticating with the registry.

Further documentation can be found [here](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/).

#### Kubelet credential providers
With Kubernetes version 1.20 support for credential providers was added to Kubelets.

When configuring Kubelets you should now pass it the flags `--image-credential-provider-config` and `--image-credential-provider-bin-dir`, the first provides a path to a YAML file containing the following and the latter a directory containing a executable with the same name as the name of the provider in the aforementioned YAML file.

```yaml
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  # name is the required name of the credential provider. It must match the name of the
  # provider executable as seen by the kubelet. The executable must be in the kubelet's
  # bin directory (set by the --image-credential-provider-bin-dir flag).
  - name: ecr
    # Example values of matchImages:
    # - 123456789.dkr.ecr.us-east-1.amazonaws.com
    # - *.azurecr.io
    # - gcr.io
    # - *.*.registry.io
    # - registry.io:8080/path
    matchImages:
      - "*.dkr.ecr.*.amazonaws.com"
      - "*.dkr.ecr.*.amazonaws.cn"
      - "*.dkr.ecr-fips.*.amazonaws.com"
      - "*.dkr.ecr.us-iso-east-1.c2s.ic.gov"
      - "*.dkr.ecr.us-isob-east-1.sc2s.sgov.gov"
    defaultCacheDuration: "12h"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    # Arguments to pass to the command when executing it.
    # +optional
    args:
      - get-credentials
    # Env defines additional environment variables to expose to the process. These
    # are unioned with the host's environment, as well as variables client-go uses
    # to pass argument to the plugin.
    # +optional
    env:
      - name: AWS_PROFILE
        value: example_profile
```

Further documentation can be found [here](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/).

## Conclusion
As was made apparent in this post, when dealing with docker registry authentication there is a lot to consider depending on your runtime environment.

If you are running your workloads in Azure Virtual Machines and are in need of a credential helper you should give our [azure-acr-credential-helper](https://github.com/ffwdeng/azure-acr-credential-helper/) a try!
