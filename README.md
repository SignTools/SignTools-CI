# iOS Signer CI

This a free and simple builder implementation for [ios-signer-service](https://github.com/SignTools/ios-signer-service). It uses a Continous Integration (CI) provider to pull, sign, and upload any iOS apps to your `ios-signer-service`.

The following providers are supported:

- GitHub Actions - [sign.yml](.github/workflows/sign.yml)
- Semaphore CI - [semaphore.yml](.semaphore/semaphore.yml)

## Setup

Create a GitHub account if you don't have one already. Click on the `Use this template` button at the top of this page. Set the new project's visibility to `Private` and create it. Alternatively, manually clone this repo into a new private repository.

### GitHub Actions

From your GitHub account settings, go to `Developer settings` and then `Personal access tokens`. Create a new token with all permissions. This is the token you need for your `ios-signer-service`'s builder configuration.

### Semaphore CI

Register for [SemaphoreCI](https://semaphoreci.com/) and create an organization if you haven't already. At the top of the organization dashboard, click on `Create New`. On the page that opens, press `Choose repository`. You will have to authorize SemaphoreCI's app to access your GitHub private repositories in order to see the builder you just created. After that, you will see your newly created repository - click on it. Proceed with `Continue to workflow setup`, then click `I will use the existing configuration`. Finally, go to `Manage Settings` of that repository, and in the bottom of the new page set `What to build?` to `Do not build this project (Pause project)`. This prevents the builder from running (and failing) every time you update it.

From your SemaphoreCI profile settings, you will find the `API Token`. This is the token you need for your `ios-signer-service`'s builder configuration.

To get the project id, go to your project's page in SemaphoreCI and click `Project artifacts`. When the new page loads, look at the URL in your browser. It will be similar to this:

```
https://YOUR_ORG_NAME.semaphoreci.com/artifacts/projects/0c4071ec-a35f-4145-a5f9-08d25483c222
```

The id after the last forward slash is your project id.
