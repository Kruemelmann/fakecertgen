# fake-certgen

fake-certgen is a small service to generate local certificates. In production the certs are generated by certbot and lets-encrypt. So to be as close as possible on the prod-setup I wrote this small service to do this while developing.

---
**NOTE**

This is for testing and developing only. NO PROD ... :)

---

## Installation

The installation is quite simple just add the service to your docker-compose file and you are good to go.

```yaml
version: "3.9"

services:
  fake-certgen:
    image: nasenbaerchen/cmd/fake-certgen:fakecertgen
    container_name: fakecertgen
    ports:
      - 9000:9000
```

## Usage

To get some help:
```bash
curl localhost:9000
```

To get the active cert just do:
```bash
curl localhost:9000/cert
```

To renew the cert do:
```bash
curl localhost:9000/renew
```

## License
[MIT](https://choosealicense.com/licenses/mit/)
