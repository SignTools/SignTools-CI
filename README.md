# iOS Signer CI

This a free and simple builder implementation for [ios-signer-service](https://github.com/SignTools/ios-signer-service). It uses a Continous Integration (CI) service to pull, sign, and upload any iOS apps to the `ios-signer-service` that requested them.

Configuration for the following providers is included:

- GitHub Actions - [sign.yml](.github/workflows/sign.yml)
- Semaphore CI - [semaphore.yml](.semaphore/semaphore.yml)

## Setup

Fork this repo. If using a CI other than GitHub, set up the CI with the forked repo. Then, add the following secrets to your CI:

| Secret     | Description                                            | Example                  |
| ---------- | ------------------------------------------------------ | ------------------------ |
| SECRET_URL | Your iOS Signer Service's base URL                     | https://website.com      |
| SECRET_KEY | The workflow key configured in your iOS Signer Service | MY_SUPER_LONG_SECRET_KEY |

That is all. Make sure to set the correct workflow configuration in your `ios-signer-service` instance.
