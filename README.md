# AWS IAM Pulumi Component Provider

## Prerequisites

## Build and Test

```bash
# Build and install the provider (plugin copied to $GOPATH/bin)
make install_provider

# Regenerate SDKs
make generate

# Test Node.js SDK
$ make install_nodejs_sdk
$ cd examples/simple
$ yarn install
$ yarn link @pulumi/aws-iam
$ pulumi stack init test
$ pulumi config set aws:region us-west-2
$ pulumi up
```
