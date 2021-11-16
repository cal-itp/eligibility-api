# Getting started

The following commands should be run in a terminal program like `bash`.

## Clone the repository

```bash
git clone https://github.com/cal-itp/eligibility-api.git
```

## Develop with VS Code Remote Containers

This repository comes with a [VS Code Remote Containers](https://code.visualstudio.com/docs/remote/containers) configuration file.

Once you clone the repository locally, simply open it within VS Code, which will prompt you to re-open the repository within the Remote Container.

## Run and develop the Documentation

When running the [Devcontainer](#develop-with-vs-code-remote-containers), the server is automatically started.

Otherwise, manually start the docs container with

```bash
docker compose up docs
```

The site is served from `http://localhost` at a port dynamically assigned by Docker. See
[Docker dynamic ports](./docker-dynamic-ports.md) for more information.

The website is automatically rebuilt as changes are made to `docs/` files.

Read more on how to run the docs [here](https://docs.calitp.org/benefits/getting-started/documentation/).
