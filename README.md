# Threat Intel Check IP

## Stack

-Python

-SQLite

-Docker
## Install
```bash
git clone https://github.com/yorjjeartemitt/threat-intel.git && cd threat-intel
```
## Use

```bash

docker build -t threat-intel .

docker run --env-file .env threat-intel

```

## API

AbuseIPDB API key in '.env' file:
```
API_KEY=your_key #without " "
```

## How to get API

you need to register or login on this site: https://www.abuseipdb.com/
and create your API key on this url: https://www.abuseipdb.com/account/api/keys
