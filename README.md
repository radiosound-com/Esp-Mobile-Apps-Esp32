# bleenky

Based on https://github.com/JoaoLopesF/Esp-Mobile-Apps-Esp32

See full README encompassing the entire demo:

https://gitlab.com/radiosound/derby-devops-spring-2020/readme

## Build and run

### Using esp-idf v4.0 locally installed

```sh
export ESPBAUD=2000000
export WIFI_SSID="MyNetwork"
export WIFI_PASSWORD="GreatPassword"
idf.py build flash monitor
```

#### If you need it to default to a specific environment for updates instead of production

Get the URL you need from the GitLab environments page or merge request ("View App" button)

Send this command from the mobile app:

```sh
91:some-long-complicated-url-here.bleenky.apps.radiosound.com/
```

### Building and running using IDF v4.0 docker image

It's not currently available from espressif/idf as they have not tagged v4.0 proper

#### Alias this long-ass docker run command

```sh
alias idf4-py='docker run --rm -it --env WIFI_SSID="MyNetwork" --env WIFI_PASSWORD="GreatPassword" --env ESPBAUD=2000000 -v $PWD:/project -w /project --device=/dev/ttyUSB0 registry.gitlab.com/radiosound/idf:v4-0 idf.py'
```

#### Then

```sh
idf4-py build flash monitor
```

## Message format

`nn:payload`

(where nn is code of message and payload is content, can be delimited too)

## Messages

### 01 Initial

### 10 Energy status(External or Battery?)

### 11 Informations about ESP32 device

### 70 Echo debug

### 71 Logging (to activate or not)

### 80 Feedback

### 90 Clear any stored firmware upgrade URLs (go back to production)

### 91 Set firmware upgrade URL

Don't include the https:// as it will be prepended automatically (the colon is interpreted as a delimiter)

e.g.

```
91:some-long-complicated-url-here.bleenky.apps.radiosound.com/
```

### 98 Restart (reset the ESP32)

### 99 Standby (enter in deep sleep)
