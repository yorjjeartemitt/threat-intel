# Threat Intel Check IP

## Overview

This tool fetches IP addresses from multiple threat intelligence blocklists 
and checks each one against AbuseIPDB. Results are stored in a local SQLite database.

## Stack

- Python

- SQLite

- Docker
## Install
```bash
git clone https://github.com/yorjjeartemitt/threat-intel.git && cd threat-intel
```
## Use

```bash

docker build -t threat-intel .

docker run --env-file .env threat-intel

```
## Example Output

```
8.8.8.8         | score: 0   | country: US
1.176.118.246   | score: 100 | country: KR
1.180.153.254   | score: 100 | country: CN
50.16.16.211    | score: 12  | country: US
```

## API

AbuseIPDB API key in '.env' file:
```
API_KEY=your_key #without " "
```

## How to get API

Register [here](https://www.abuseipdb.com/) and generate your key [here](https://www.abuseipdb.com/account/api/keys)
