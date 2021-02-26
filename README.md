# iOS Signer CI

This is the Continuous Integration (CI) part of the [ios-signer-service](https://github.com/SignTools/ios-signer-service) project.
Using GitHub's Actions macOS [environment](https://docs.github.com/en/actions/reference/specifications-for-github-hosted-runners), this repository will pull, sign, and upload any iOS apps to the `ios-signer-service` that requested them.

## Setup

Fork this repo. Add the following [secrets](https://docs.github.com/en/actions/reference/encrypted-secrets) to your fork:

| Secret | Description                                            | Example                  |
| ------ | ------------------------------------------------------ | ------------------------ |
| URL    | Your iOS Signer Service's base URL                     | https://website.com      |
| KEY    | The workflow key configured in your iOS Signer Service | MY_SUPER_LONG_SECRET_KEY |

That is all. Make sure you set the correct repository owner and name in your `ios-signer-service` configuration.
