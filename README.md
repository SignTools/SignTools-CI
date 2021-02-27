# iOS Signer CI

This a free and easy builder implementation for [ios-signer-service](https://github.com/SignTools/ios-signer-service).
Using GitHub's Actions macOS [environment](https://docs.github.com/en/actions/reference/specifications-for-github-hosted-runners), this repository will pull, sign, and upload any iOS apps to the `ios-signer-service` that requested them.

## Setup

Fork this repo. Add the following [secrets](https://docs.github.com/en/actions/reference/encrypted-secrets) to your fork:

| Secret | Description                                            | Example                  |
| ------ | ------------------------------------------------------ | ------------------------ |
| URL    | Your iOS Signer Service's base URL                     | https://website.com      |
| KEY    | The workflow key configured in your iOS Signer Service | MY_SUPER_LONG_SECRET_KEY |

That is all. Make sure to set the correct workflow configuration in your `ios-signer-service` instance.
