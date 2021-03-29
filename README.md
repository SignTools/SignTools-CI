# iOS Signer CI

This is a free and simple builder for [ios-signer-service](https://github.com/SignTools/ios-signer-service). It uses a Continous Integration (CI) provider to pull, sign, and upload any iOS apps to your `ios-signer-service`.

The following providers are supported:

- [GitHub Actions](https://docs.github.com/en/actions)
- [Semaphore CI](https://semaphoreci.com/)

You only need to configure one provider.

> ### :warning: Developer accounts are only supported on GitHub Actions for now!

## Setup

1. Create a GitHub account
2. Click on the `Use this template` button at the top of this page
3. Give the new project a name and set the visibility to `Private`
4. Create the new project

Alternatively, you can also manually clone this repo into a new private repository.

You now need to configure a CI provider. You only need one of them:

### GitHub Actions

1. Open your GitHub [account settings](https://github.com/settings/profile)
2. Go to `Developer settings` and then `Personal access tokens`
3. Generate a new token with the `workflow` permission

This is the token you need for your `ios-signer-service`'s builder configuration.

### Semaphore CI

1. Register for [SemaphoreCI](https://semaphoreci.com/) and create an organization
2. At the top of the organization dashboard, click on `Create New`
3. On the page that opens, press `Choose repository`
4. Authorize SemaphoreCI's app to access your GitHub private repositories in order to see the builder you just created
5. Back on SemaphoreCI's new project page, you will see your builder repository - click on it
6. Proceed with `Continue to workflow setup`, then click `I will use the existing configuration`
7. Go to `Manage Settings` of that repository
8. At the bottom of the page that opens, set `What to build` to `Do not build this project (Pause project)`

At your SemaphoreCI profile settings, you will find your `API Token`. This is the token you need for your `ios-signer-service`'s builder configuration.
