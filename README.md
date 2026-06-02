# Threat Intel 

GUI app for checking IP reputation via AbuseIPDB API. Results are saved locally in SQLite.

## Screenshots

### GUI
![gui](Pictures/gui.png)

### DECODE/ENCODE

![decode_encode](Pictures/decode_encode.png)

### SQL
![sql](Pictures/sql.png)

### Network (Wireshark)
![wireshark](Pictures/wireshark.png)

## Stack

<div align="center">

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![GTK3](https://img.shields.io/badge/GTK3-215732?style=for-the-badge&logo=gtk&logoColor=white)
![libcurl](https://img.shields.io/badge/libcurl-073551?style=for-the-badge&logo=curl&logoColor=white)
![cJSON](https://img.shields.io/badge/cJSON-555555?style=for-the-badge&logoColor=white)
![SQLite3](https://img.shields.io/badge/SQLite3_-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

</div>

## Dependencies

**Arch Linux:**
```sh
sudo pacman -S gtk3 curl cjson sqlite cmake pkgconf
```

**Ubuntu/Debian:**
```sh
sudo apt install libgtk-3-dev libcurl4-openssl-dev libcjson-dev libsqlite3-dev cmake pkg-config
```

## Build & Run

```sh
git clone https://github.com/yorjjeartemitt/threat-intel.git
cd threat-intel
cp .env.example .env   # add your API key
mkdir -p build
./run gcc     # build with gcc and run
./run cmake   # build with cmake and run
./run docker  # run in docker
./run sql     # view saved results
```

---

## API Key

Register [here](https://www.abuseipdb.com) and get your key [here](https://www.abuseipdb.com/account/api/keys)

Add to `.env`
