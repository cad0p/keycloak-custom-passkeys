Keycloak-Custom
===

Project Template
---

This project is based on the [custom Keycloak template](https://github.com/inventage/keycloak-custom). It is structured as a multi-module Maven build and contains the following top-level modules:

- `config`: provides the build stage configuration and the setup of Keycloak
- `container`: creates the custom docker image
- `docker-compose`: provides a sample for launching the custom docker image
- `extensions`: provides samples for Keycloak SPI implementations
- `helm`: provides a sample for installing the custom container image in Kubernetes using the Codecentric Helm Chart
- `server`: provides a Keycloak installation for local development & testing
- `themes`: provides samples for custom themes

Please see the tutorials [building a custom Keycloak container image](https://keycloak.ch/keycloak-tutorials/tutorial-custom-keycloak/) and [Configuring Passkey](https://keycloak.ch/keycloak-tutorials/tutorial-passkey/) for the details of this project.

Server admin guide: <https://www.keycloak.org/docs/latest/server_admin>

Installation
---

```sh
# set up
./mvnw clean package
# run postgres
docker compose -f ./docker-compose/postgres/docker-compose.yml up -d
# run keycloak
./server/run-keycloak.sh > debug.log
```

```sh
# in a different tab, set up keycloak
./server/run-keycloak-setup.sh
```

Then test it by going to the URL: <https://www.keycloak.org/app/#url=http://localhost:8080&realm=passkey&client=passkey>

Or <http://localhost:8080/realms/passkey/account>

Build Image
---

In order to use this Authorization Server in other places, building the image is necessary.

```sh
./mvnw clean install -DmultiArchBuild
```

Documentation
---

- [Server Development Guide (Old)](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_development/index.html)
- [Server Development Guide (New)](https://www.keycloak.org/docs/latest/server_development)
