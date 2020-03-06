/**
 * bleenky - Bluetooth LE demo firmware for ESP32
 * See more details in README.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_event.h"
#include "esp_heap_trace.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "nvs_flash.h"
#include "soc/soc.h"

// C++

#include <string>
using namespace std;

// C

extern "C"
{
	int rom_phy_get_vdd33();
}

// Util

#include "util/log.h"
#include "util/esp_util.h"
#include "util/fields.h"

// Do projeto

#include "main.h"
#include "ble.h"
#include "peripherals.h"

////// Prototypes

static void ota_task(void *pvParameters);
static void main_Task(void *pvParameters);
static void standby(const char *cause, bool sendBLEMsg);
static void debugInitial();
static void sendInfo(Fields &fields);
static bool mLedStatusOn = true;

#ifdef HAVE_BATTERY
static void checkEnergyVoltage(bool sendingStatus);
#endif

////// Variables

#define NUM_RECORDS 100
//static heap_trace_record_t trace_record[NUM_RECORDS]; // This buffer must be in internal RAM

// Log

static const char *TAG = "main";

// Utility

static Esp_Util &mUtil = Esp_Util::getInstance();

// Times and intervals

uint32_t mTimeSeconds = 0; // Current time in seconds (for timeouts calculations)

uint32_t mLastTimeFeedback = 0; // Indicates the time of the last feedback message

uint32_t mLastTimeReceivedData = 0; // time of receipt of last line via

// Log active (debugging)?

bool mLogActive = false;
bool mLogActiveSaved = false;

// Connected?

bool mAppConnected = false; // Indicates connection when receiving message 01:
bool wifiConnected = false;

static nvs_handle_t my_handle;

////// FreeRTOS

// Task handles

static TaskHandle_t xTaskMainHandler = NULL;
static TaskHandle_t xTaskOTAHandler = NULL;
static TaskHandle_t xTaskWiFiHandler = NULL;

typedef enum
{
	fwPRODUCTION = 0, /* Production firmware URL is baked in */
	fwNVS = 1		  /* URL can be saved to NVS by a command from the mobile app */
} firmware_url_selection_t;

/* Try to get an update from the URL stored in NVS by default, fall back if not set or 404 */
static firmware_url_selection_t my_firmware = fwNVS;

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about 3 events:
 * - we are connected to the AP with an IP
 * - we have lost the connection
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define WIFI_DISCONNECTED_BIT BIT2

static int s_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
							   int32_t event_id, void *event_data)
{
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
	{
		esp_wifi_connect();
	}
	else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
	{
		if (s_retry_num < CONFIG_ESP_MAXIMUM_RETRY)
		{
			esp_wifi_connect();
			s_retry_num++;
			if (wifiConnected)
			{
				xEventGroupSetBits(s_wifi_event_group, WIFI_DISCONNECTED_BIT);
			}
		}
		else
		{
			xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
		}
		ESP_LOGI(TAG, "couldn't connect to %s\n", WIFI_SSID);
	}
	else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
	{
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		s_retry_num = 0;
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
		xEventGroupClearBits(s_wifi_event_group, WIFI_DISCONNECTED_BIT);
	}
}

////// Main

extern "C"
{
	void app_main();
}

static const char le_x3_cert[] = R"(-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----)";

static const char le_x4_cert[] = R"(-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAJObmZ6kjhYNW0JZtD0gE9owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0NDM0
WhcNMjExMDA2MTU0NDM0WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhJHRCe7eRMdlz/ziq2M5EXLc5
CtxErg29RbmXN2evvVBPX9MQVGv3QdqOY+ZtW8DoQKmMQfzRA4n/YmEJYNYHBXia
kL0aZD5P3M93L4lry2evQU3FjQDAa/6NhNy18pUxqOj2kKBDSpN0XLM+Q2lLiSJH
dFE+mWTDzSQB+YQvKHcXIqfdw2wITGYvN3TFb5OOsEY3FmHRUJjIsA9PWFN8rPba
LZZhUK1D3AqmT561Urmcju9O30azMdwg/GnCoyB1Puw4GzZOZmbS3/VmpJMve6YO
lD5gPUpLHG+6tE0cPJFYbi9NxNpw2+0BOXbASefpNbUUBpDB5ZLiEP1rubSFAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBTF
satOTLHNZDCTfsGEmQWr5gPiJTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AF4tI1yGjZgld9lP01+zftU3aSV0un0d2GKUMO7GxvwTLWAKQz/eT+u3J4+GvpD+
BMfopIxkJcDCzMChjjZtZZwJpIY7BatVrO6OkEmaRNITtbZ/hCwNkUnbk3C7EG3O
GJZlo9b2wzA8v9WBsPzHpTvLfOr+dS57LLPZBhp3ArHaLbdk33lIONRPt9sseDEk
mdHnVmGmBRf4+J0Wy67mddOvz5rHH8uzY94raOayf20gzzcmqmot4hPXtDG4Y49M
oFMMT2kcWck3EOTAH6QiGWkGJ7cxMfSL3S0niA6wgFJtfETETOZu8AVDgENgCJ3D
S0bz/dhVKvs3WRkaKuuR/W0nnC2VDdaFj4+CRF8LGtn/8ERaH48TktH5BDyDVcF9
zfJ75Scxcy23jAL2N6w3n/t3nnqoXt9Im4FprDr+mP1g2Z6Lf2YA0jE3kZalgZ6l
NHu4CmvJYoOTSJw9X2qlGl1K+B4U327rG1tRxgjM76pN6lIS02PMECoyKJigpOSB
u4V8+LVaUMezCJH9Qf4EKeZTHddQ1t96zvNd2s9ewSKx/DblXbKsBDzIdHJ+qi6+
F9DIVM5/ICdtDdulOO+dr/BXB+pBZ3uVxjRANvJKKpdxkePyluITSNZHbanWRN07
gMvwBWOL060i4VrL9er1sBQrRjU9iNpZQGTnLVAxQVFu
-----END CERTIFICATE-----)";

esp_err_t dummy_http_event_handler(esp_http_client_event_t *e)
{
	return 0;
}

void wifi_task(void *pvParameters)
{
	s_wifi_event_group = xEventGroupCreate();

	esp_wifi_set_ps(WIFI_PS_NONE);

	tcpip_adapter_init();

	ESP_ERROR_CHECK(esp_event_loop_create_default());

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

	wifi_config_t wifi_config;
	strcpy((char *)wifi_config.sta.ssid, WIFI_SSID);
	strcpy((char *)wifi_config.sta.password, WIFI_PASSWORD);
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_LOGI(TAG, "wifi_init_sta finished.");

	for (;;)
	{
		/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
		* number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
		EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
											   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT | WIFI_DISCONNECTED_BIT,
											   pdFALSE,
											   pdFALSE,
											   portMAX_DELAY);

		/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
		* happened. */
		if (bits & WIFI_CONNECTED_BIT)
		{
			ESP_LOGI(TAG, "connected to %s\n", WIFI_SSID);
			wifiConnected = true;
			xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
		}

		if (bits & WIFI_DISCONNECTED_BIT)
		{
			ESP_LOGI(TAG, "disconnected from %s\n", WIFI_SSID);
			wifiConnected = false;
			xEventGroupClearBits(s_wifi_event_group, WIFI_DISCONNECTED_BIT);
		}

		if (bits & WIFI_FAIL_BIT)
		{
			ESP_LOGI(TAG, "Failed to connect to wifi too many times, giving up");
			xEventGroupClearBits(s_wifi_event_group, WIFI_FAIL_BIT);
			/* Do something different for failure here? */
		}
	}

	ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler));
	ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler));
	vEventGroupDelete(s_wifi_event_group);
}

/**
 * @brief app_main of ESP-IDF 
 */
void app_main()
{
	//ESP_ERROR_CHECK( heap_trace_init_standalone(trace_record, NUM_RECORDS) );

	mLogActive = true; // To show initial messages

	logI("Initializing");

	// Initialize the Esp32

	mUtil.esp32Initialize();

	// Initialize Peripherals

	peripheralsInitialize();

	// Initialize Ble Server

	bleInitialize();

	// Initialize NVS
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
	{
		// NVS partition was truncated and needs to be erased
		// Retry nvs_flash_init
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);

	// Open
	ESP_LOGE(TAG, "Opening Non-Volatile Storage (NVS) handle...\n");
	err = nvs_open("storage", NVS_READWRITE, &my_handle);
	if (err != ESP_OK)
	{
		ESP_LOGE(TAG, "Error (%s) opening NVS handle!\n", esp_err_to_name(err));
	}
	else
	{
		xTaskCreate(&wifi_task,
					"wifi_task", TASK_STACK_MEDIUM, NULL, TASK_PRIOR_HIGH, &xTaskWiFiHandler);
		xTaskCreate(&ota_task,
					"ota_task", TASK_STACK_MEDIUM, NULL, TASK_PRIOR_LOW, &xTaskOTAHandler);
		xTaskCreatePinnedToCore(&main_Task,
								"main_Task", TASK_STACK_LARGE, NULL, TASK_PRIOR_HIGH, &xTaskMainHandler, TASK_CPU);
	}

	// Logging

#ifdef HAVE_BATTERY
	//mLogActive = mGpioVEXT; // Activate only if plugged in Powered by external voltage (USB or power supply) - comment it to keep active
#endif

	return;
}

void http_utils_trim_whitespace(char **str)
{
    char *end, *start;
    if (str == NULL) {
        return;
    }
    start = *str;
    if (start == NULL) {
        return;
    }
    // Trim leading space
    while (isspace((unsigned char)*start)) start ++;

    if (*start == 0) {  // All spaces?
        **str = 0;
        return;
    }

    // Trim trailing space
    end = (char *)(start + strlen(start) - 1);
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    // Write new null terminator
    *(end + 1) = 0;
    memmove(*str, start, strlen(start) + 1);
}

static void ota_task(void *pvParameters)
{
	logI("Starting OTA Task");
	const TickType_t xTicks = (30000u / portTICK_RATE_MS);

	uint32_t notification; // Notification variable

	for (;;)
	{
		//logI ("zzz");
		xTaskNotifyWait(0, 0xffffffff, &notification, xTicks);
		// return value of xTaskNotifyWait is pdPASS if a notification was received to wake up instantly, otherwise pdFAIL if the wait time elapsed

		if (wifiConnected)
		{
			esp_err_t err;
			static const size_t url_buffer_size = 256;
			char base_url[url_buffer_size];
			size_t url_len;

			logI("Check for update");

#if 0
			printf("\n-------------------------\nTotal RAM available:\n");
			heap_caps_print_heap_info(MALLOC_CAP_DEFAULT);
			printf("\n-------------------------\nSPI RAM\n");
			heap_caps_print_heap_info(MALLOC_CAP_SPIRAM);
			printf("\n-------------------------\nInternal RAM\n");
			heap_caps_print_heap_info(MALLOC_CAP_DMA);
			printf("\n-------------------------\n32-bit aligned RAM\n");
			heap_caps_print_heap_info(MALLOC_CAP_32BIT);
			printf("\n-------------------------\n8-bit aligned RAM\n");
			heap_caps_print_heap_info(MALLOC_CAP_8BIT);
#endif

			/* Check for OTA update */
			switch (my_firmware)
			{
			case fwNVS:
				err = nvs_get_str(my_handle, "ota_url", base_url, &url_len);
				switch (err)
				{
				case ESP_OK:
					/* Security note: Probably don't want to allow the user to
							input their own URL unless you're signing app images and
							requiring signatures for OTA updates. For demo purposes
							thisisfine.gif */
					ESP_LOGD(TAG, "Upgrade URL stored in flash: %s\n", base_url);
					break;
				default:
					/* fall through */
				case ESP_ERR_NVS_NOT_FOUND:
					ESP_LOGE(TAG, "Read upgrade URL: %s", esp_err_to_name(err));
					my_firmware = fwPRODUCTION;
					strcpy(base_url, CONFIG_PRODUCTION_FIRMWARE_UPGRADE_URL_BASE);
					break;
				}
				break;
			case fwPRODUCTION:
				strcpy(base_url, CONFIG_PRODUCTION_FIRMWARE_UPGRADE_URL_BASE);
				ESP_LOGE(TAG, "Using production default %s\n", base_url);
				break;
			}

			char version_url[url_buffer_size];
			int last_char_index = strlen(base_url) - 1;
			if (last_char_index < url_buffer_size - 20)
			{
				/* Slight sanity check */

				if (base_url[last_char_index] != '/')
				{
					/* Make sure it ends with a slash */
					strcat(base_url, "/");
				}
				strcpy(version_url, base_url);
				strcat(version_url, "version.txt");

				logV("Checking for version at %s\n", version_url);

				{
					/* https://github.com/willson556/esp32-simple-ota/blob/master/esp32_simple_ota.cpp */
					/* Do version check like this but for txt file instead of json */
					//ESP_ERROR_CHECK( heap_trace_start(HEAP_TRACE_LEAKS) );

					esp_http_client_config_t version_config{};
					version_config.cert_pem = (char *)le_x3_cert;
					version_config.event_handler = dummy_http_event_handler;
					version_config.url = version_url;

					esp_http_client_handle_t client = esp_http_client_init(&version_config);

					err = esp_http_client_perform(client);

					if (err == ESP_OK)
					{
						const int status_code = esp_http_client_get_status_code(client);
						const int content_length = esp_http_client_get_content_length(client);
						logI("HTTP GET Status = %d, content_length = %d", status_code, content_length);
						if (status_code == 404)
						{
							ESP_LOGD(TAG, "This environment doesn't seem to exist anymore.\n");

							switch (my_firmware)
							{
							case fwNVS:
								nvs_erase_key(my_handle, "ota_url");
								nvs_commit(my_handle);
								my_firmware = fwPRODUCTION;
								break;
							default:
								/* nothing */
								ESP_LOGD(TAG, "No production environment? thisisfine.gif\n");
								break;
							}
							esp_http_client_cleanup(client);
						}
						else if (status_code == 200)
						{
							char buffer[50]; // version string should never be longer than 50 bytes
							char *p_buffer = &buffer[0];
							if (content_length < 50)
							{
								const esp_app_desc_t *p_app_desc;
								int read_len = esp_http_client_read(client, buffer, content_length);
								esp_http_client_cleanup(client);
								buffer[read_len] = 0;
								http_utils_trim_whitespace(&p_buffer);
								p_app_desc = esp_ota_get_app_description();
								if (strcmp(p_buffer, p_app_desc->version))
								{
									ESP_LOGD(TAG, "Installed: %s, available: %s\n", p_app_desc->version, p_buffer);
									char update_url[url_buffer_size];
									strcpy(update_url, base_url);
									strcat(update_url, p_app_desc->project_name);
									strcat(update_url, ".bin");
									{
										esp_http_client_config_t update_config{};
										update_config.url = update_url;
										update_config.cert_pem = (char *)le_x3_cert;
										update_config.event_handler = dummy_http_event_handler;
										err = esp_https_ota(&update_config);
										switch (err)
										{
										case ESP_OK:
											logI("Ready to install update! Hold onto your butts...");
											esp_restart();
											break;
										default:
											ESP_LOGE(TAG, "Update failed: %s", esp_err_to_name(err));
											break;
										}
									}
								}
							}
							else
							{
								ESP_LOGE(TAG, "Version check failed, string is too long\n");
								esp_http_client_cleanup(client);
							}
							
						}
					}
					else
					{
						ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
						esp_http_client_cleanup(client);
					}

					//ESP_ERROR_CHECK( heap_trace_stop() );
					//heap_trace_dump();
				}
			}
		}
	}

	vTaskDelete(NULL);
	xTaskOTAHandler = NULL;
}

/**
 * @brief Main Task - main processing 
 * Is a second timer to process, adquiry data, send responses to mobile App, control timeouts, etc.
 */
static void main_Task(void *pvParameters)
{
	logI("Starting main Task");

	/////// Variables

	// Init the time

	mTimeSeconds = 0;

	/////// Initializations

	// Initializes app

	appInitialize(false);

	// Sensors values

#if defined HAVE_BATTERY && defined PIN_SENSOR_CHARGING
	// Use this to verify changes on this sensor
	// Due debounce logic
	bool lastChgBattery = mGpioChgBattery;
#endif

	////// FreeRTOS

	// Timeout - task - 1 second

	const TickType_t xTicks = (1000u / portTICK_RATE_MS);

	////// Loop

	uint32_t notification; // Notification variable

	for (;;)
	{

		// Wait for the time or something notified (seen in the FreeRTOS example)

		if (xTaskNotifyWait(0, 0xffffffff, &notification, xTicks) == pdPASS)
		{

			// Action by task notification

			logD("Notification received -> %u", notification);

			bool reset_timer = false;

			switch (notification)
			{

			case MAIN_TASK_ACTION_RESET_TIMER: // Reset timer
				reset_timer = true;
				break;

			case MAIN_TASK_ACTION_STANDBY_BTN: // Enter in standby - to deep sleep not run in ISR
				standby("Pressed button standby", true);
				break;

			case MAIN_TASK_ACTION_STANDBY_MSG: // Enter in standby - to deep sleep not run in ISR
				standby("99 code msg - standby", false);
				break;
#ifdef HAVE_BATTERY
			case MAIN_TASK_ACTION_SEN_VEXT: // Sensor of Powered by external voltage (USB or power supply) is changed - to not do it in ISR

				checkEnergyVoltage(true);
				break;

#ifdef MAIN_TASK_ACTION_SEN_CHGR
			case MAIN_TASK_ACTION_SEN_CHGR: // Sensor of battery charging is changed - to not do it in ISR

				checkEnergyVoltage(true);
				break;
#endif
#endif
				// TODO: see it! If need put here your custom notifications

			default:
				break;
			}

			// Resets the time variables and returns to the beginning of the loop ?
			// Usefull to initialize the time (for example, after App connection)

			if (reset_timer)
			{

				// Clear variables

				mTimeSeconds = 0;
				mLastTimeFeedback = 0;
				mLastTimeReceivedData = 0;

				// TODO: see it! put here custom reset timer code

				// Debug

				logD("Reseted time");

				continue; // Returns to loop begin
			}
		}

		////// Processes every second

		// Time counter

		mTimeSeconds++;

#ifdef PIN_LED_STATUS
		// Blink the led of status (board led of Esp32 or external)

		// gpioBlinkLedStatus();
#endif

		// Sensors readings by ADC

		adcRead();

		// TODO: see it! Put here your custom code to run every second

		// Debug

		if (mLogActive)
		{

			if (mTimeSeconds % 5 == 0)
			{ // Debug each 5 secs

#ifdef HAVE_BATTERY
				logD("* Secs=%d | sensors: vext=%c charging=%c vbat=%d | mem=%d",
					 mTimeSeconds,
					 ((mGpioVEXT) ? 'Y' : 'N'),
					 ((mGpioChgBattery) ? 'Y' : 'N'),
					 mAdcBattery,
					 esp_get_free_heap_size());
#else
				logD("* Time seconds=%d", mTimeSeconds);
#endif
			}
			else
			{   // Verbose //TODO: see it! put here that you want see each second
				// If have, please add our variables and uncomment it
				// logV("* Time seconds=%d", mTimeSeconds);
			}
		}

#if defined MAX_TIME_INACTIVE && defined HAVE_S

		////// Auto power off (standby)
		// If it has been inactive for the maximum time allowed, it goes into standby (soft off)

#ifdef HAVE_BATTERY
		bool verifyInactive = !mGpioVEXT; // Only if it is not powered by external voltage (USB or power supply) - to not abort debuggings;
#else
		bool verifyInactive = true;
#endif
		if (verifyInactive)
		{ // Verify it ?

			bool inactive = false;

			if (bleConnected())
			{
				inactive = ((mTimeSeconds - mLastTimeReceivedData) >= MAX_TIME_INACTIVE);
			}
			else
			{
				inactive = (mTimeSeconds >= MAX_TIME_INACTIVE);
			}

			if (inactive)
			{

				// Set to standby (soft off)

				standby("Attained maximum time of inactivity", true);
				return;
			}
		}
#endif
		/////// BLE connected ?

		if (!bleConnected())
		{
			continue;
		}

		/////// Routines with only if BLE is connected

#if HAVE_BATTERY

		// Check the voltage of battery/charging

#ifdef PIN_SENSOR_CHARGING
		// Verify if it is changed (due debounce logic when no battery plugged)
		if (mGpioChgBattery != lastChgBattery)
		{
			checkEnergyVoltage(true);
		}
#endif

		if ((mTimeSeconds % 60) == 0)
		{ // Each minute

			checkEnergyVoltage(false);
		}
#endif

#ifdef MAX_TIME_WITHOUT_FB
		// If not received feedback message more than the allowed time

		if (!mLogActive)
		{ // Only if it is not debugging

			if ((mTimeSeconds - mLastTimeFeedback) >= MAX_TIME_WITHOUT_FB)
			{

				// Enter in standby (soft off)

				standby("No feedback received in time");
				return;
			}
		}
#endif

		// Sensors values saving

#if defined HAVE_BATTERY && defined PIN_SENSOR_CHARGING

		lastChgBattery = mGpioChgBattery;
#endif

		// TODO: see it! put here custom routines for when BLE is connected
	}

	////// End

	// Delete this task

	vTaskDelete(NULL);
	xTaskMainHandler = NULL;
}

/**
 * @brief Initializes the app
 */
void appInitialize(bool resetTimerSeconds)
{

	// Restore logging ?

	if (mLogActiveSaved && !mLogActive)
	{
		mLogActive = true; // Restore state
	}

	logD("Initializing ...");

	///// Initialize the variables

	// Initialize times

	mLastTimeReceivedData = 0;
	mLastTimeFeedback = 0;

	// TODO: see it! Please put here custom global variables or code for init

	// Debugging

	logD("Initialized");
}

/**
 * @brief Process the message received from BLE
 * Note: this routine is in main.cc due major resources is here
 */
void processBleMessage(const string &message)
{

	// This is to process ASCII (text) messagens - not binary ones

	string response = ""; // Return response to mobile app

	// --- Process the received line

	// Check the message

	if (message.length() < 2)
	{

		error("Message length must have 2 or more characters");
		return;
	}

	// Process fields of the message

	Fields fields(message, ":");

	// Code of the message

	uint8_t code = 0;

	if (!fields.isNum(1))
	{ // Not numerical
		error("Non-numeric message code");
		return;
	}

	code = fields.getInt(1);

	if (code == 0)
	{ // Invalid code
		error("Invalid message code");
		return;
	}

	logV("Code -> %u Message -> %s", code, mUtil.strExpand(message).c_str());

	// Considers the message received as feedback also

	mLastTimeFeedback = mTimeSeconds;

	// Process the message

#ifdef HAVE_BATTERY
	bool sendEnergy = false; // Send response with the energy situation too?
#endif

	switch (code)
	{ // Note: the '{' and '}' in cases, is to allow to create local variables, else give an error cross definition ...

		// --- Initial messages

	case 1: // Start
	{
		const esp_app_desc_t *p_app_desc;

		// Initial message sent by the mobile application, to indicate start of the connection

		if (mLogActive)
		{
			debugInitial();
		}

		// Reinicialize the app - include timer of seconds

		appInitialize(true);

		// Indicates connection initiated by the application

		mAppConnected = true;

		// Inform to mobile app, if this device is battery powered and sensors
		// Note: this is important to App works with differents versions or models of device

#ifdef HAVE_BATTERY

		// Yes, is a battery powered device

		string haveBattery = "Y";

#ifdef PIN_SENSOR_CHARGING

		// Yes, have a sensor of charging
		string sensorCharging = "Y";

#else
		// No have a sensor of charging
		string sensorCharging = "N";
#endif
		// Send energy status (also if this project not have battery, to mobile app know it)

		sendEnergy = true;

#else

		// No, no is a battery powered device

		string haveBattery = "N";
		string sensorCharging = "N";

#endif
		// Debug

		bool turnOnDebug = false;

#ifdef HAVE_BATTERY

		// Turn on the debugging (if the USB is connected)

		if (mGpioVEXT && !mLogActive)
		{
			turnOnDebug = true;
		}
#else

		// Turn on debugging

		turnOnDebug = !mLogActive;

#endif

		// Turn on the debugging (if the USB cable is connected)

		if (turnOnDebug)
		{

			mLogActive = true;
			debugInitial();
		}

		// Reset the time in main_Task

		notifyMainTask(MAIN_TASK_ACTION_RESET_TIMER);

		// Returns status of device, this firware version and if is a battery powered device

		p_app_desc = esp_ota_get_app_description();

		response = "01:";
		response.append(p_app_desc->version);
		response.append(1u, ':');
		response.append(haveBattery);
		response.append(1u, ':');
		response.append(sensorCharging);
	}
	break;

#ifdef HAVE_BATTERY
	case 10: // Status of energy: battery or external (USB or power supply)
	{
		sendEnergy = true;
	}
	break;
#endif

	case 11: // Request of ESP32 informations
	{
		// Example of passing fields class to routine process

		sendInfo(fields);
	}
	break;

	case 70: // Echo (for test purpose)
	{
		response = message;
	}
	break;

	case 71: // Logging - activate or desactivate debug logging - save state to use after
	{
		switch (fields.getChar(2)) // Process options
		{
		case 'Y': // Yes

			mLogActiveSaved = mLogActive; // Save state
			mLogActive = true;			  // Activate it

			logV("Logging activated now");
			break;

		case 'N': // No

			logV("Logging deactivated now");

			mLogActiveSaved = mLogActive; // Save state
			mLogActive = false;			  // Deactivate it
			break;

		case 'R': // Restore

			mLogActive = mLogActiveSaved; // Restore state
			logV("Logging state restored now");
			break;
		}
	}
	break;

	case 80: // Feedback
	{
		// Message sent by the application periodically, for connection verification

		logV("Feedback received");

		// Response it (put here any information that needs)

		response = "80:";
	}
	break;

	case 90: // Clear firmware update URL
		nvs_erase_key(my_handle, "ota_url");
		nvs_commit(my_handle);
		my_firmware = fwPRODUCTION;
		response = "90:OK";
		break;
	case 91: // Set firmware update URL
	{
		auto newUrl = fields.getString(2);
		ESP_LOGD(TAG, "New URL: %s\n", newUrl.c_str());
		if (newUrl.length() > 200)
		{
			/* This probably won't fit the max URL size */
			response = "91:You sly dog, you got me monologuing";
		}
		else if (newUrl.find(CONFIG_PRODUCTION_FIRMWARE_UPGRADE_URL_BASE) == string::npos)
		{
			response = "91:Not right now you don't";
		}
		else
		{
			newUrl = string("https://").append(newUrl);
			esp_err_t err = nvs_set_str(my_handle, "ota_url", newUrl.c_str());
			switch (err)
			{
			case ESP_OK:
				/* Security note: Probably don't want to allow the user to
					input their own URL unless you're signing app images and
					requiring signatures for OTA updates. For demo purposes
					thisisfine.gif */
				ESP_LOGD(TAG, "Upgrade URL stored in flash: %s\n", newUrl.c_str());
				response = "91:Success";
				nvs_commit(my_handle);
				my_firmware = fwNVS;
				notifyOTATask(OTA_TASK_ACTION_CHECK_NOW);
				break;
			default:
			{
				char info[300];
				snprintf(info, sizeof(info), "91:%s", esp_err_to_name(err));
				ESP_LOGE(TAG, "%s\n", info);
				response = info;
				break;
			}
			}
		}
	}
	break;

	case 98: // Reinicialize the app
	{
		logI("Reinitialize");

		// End code placed at the end of this routine to send OK before
	}
	break;

	case 99: // Enter in standby
	{
		logI("Entering in standby");

		// End code placed at the end of this routine to send OK before
	}
	break;

	default:
	{
		string errorMsg = "Code of message invalid: ";
		errorMsg.append(mUtil.intToStr(code));
		error(errorMsg.c_str());
		return;
	}
	}

	// return

	if (response.size() > 0)
	{

		// Return -> Send message response

		if (bleConnected())
		{
			bleSendData(response);
		}
	}

#ifdef HAVE_BATTERY
	// Return energy situation too?

	if (sendEnergy)
	{

		checkEnergyVoltage(true);
	}
#endif

	// Mark the mTimeSeconds of the receipt

	mLastTimeReceivedData = mTimeSeconds;

	// Here is processed messages that have actions to do after response sended

	switch (code)
	{

	case 98: // Restart the Esp32

		// Wait 500 ms, to give mobile app time to quit

		if (mAppConnected)
		{
			delay(500);
		}

		restartESP32();
		break;

	case 99: // Standby - enter in deep sleep

#ifdef HAVE_STANDBY

		// Wait 500 ms, to give mobile app time to quit

		if (mAppConnected)
		{
			delay(500);
		}

		// Soft Off - enter in standby by main task to not crash or hang on finalize BLE
		// Notify main_Task to enter standby

		notifyMainTask(MAIN_TASK_ACTION_STANDBY_MSG);

#else

		// No have standby - restart

		restartESP32();

#endif

		break;
	}
}

#ifdef HAVE_BATTERY
/**
 * @brief Check the voltage of the power supply (battery or charging via usb) 
 */
static void checkEnergyVoltage(bool sendingStatus)
{

	string energy = "";

	static int16_t lastReadingVBAT = 0;

	// Volts in the power supply (battery) of the ESP32 via the ADC pin
	// There is one resistive divider

	uint16_t readVBAT = mAdcBattery; // Read in adc.cc

	// Send the status to the application

	int16_t diffAnalog = (readVBAT - lastReadingVBAT);
	if (diffAnalog < 0)
		diffAnalog *= -1;

	// Send the status of the application when requested or when there were alterations

	if (bleConnected() && // Only if connected
		(sendingStatus || // And sending status
		 (!mGpioVEXT && diffAnalog > 20)))
	{ // Or significative diff

		logD("vbat=%u diff=%u", readVBAT, diffAnalog);

		// Message to App

		energy = "10:";
		energy.append((mGpioVEXT) ? "EXT:" : "BAT:");
		energy.append((mGpioChgBattery) ? "Y:" : "N:");
		energy.append(mUtil.intToStr(readVBAT));
		energy.append(1u, ':');
	}

	// Send it to app ?

	if (energy.size() > 0)
	{

		bleSendData(energy);
	}

	// Save last readings

	lastReadingVBAT = readVBAT;
}
#endif

/**
 * @brief Standby - enter in deep sleep
 */
static void standby(const char *cause, bool sendBLEMsg)
{

	// Enter in standby (standby off is reseting ESP32)
	// Yet only support a button to control it, touchpad will too in future

	// Debug

	logD("Entering standby, cause -> %s", cause);

#ifdef PIN_BUTTON_STANDBY

	// Disable interrupt on gpio

	gpioDisableISR(PIN_BUTTON_STANDBY);

	// Send message to app mobile ?

	if (sendBLEMsg && mAppConnected && bleConnected())
	{

		// Send the cause of the standby

		string message = "99:";
		message.append(cause);

		if (bleConnected())
		{

			bleSendData(message);

			delay(500);
		}
	}

#ifdef PIN_GROUND_VBAT
	// Pin to ground resistor divider to measure voltage of battery
	// To consume nothing more during deep sleep

	gpioSetLevel(PIN_GROUND_VBAT, 0); // Not ground this more
#endif

	////// Entering standby

	// Debug

	logD("Finalizing ...");

	// Finalize BLE

	bleFinalize();

	// Finalize the peripherals

	peripheralsFinalize();

	// A delay time

	delay(200);

	// Waiting for button to be released

	logD("Waiting for button to be released ...");

	while (gpioIsHigh(PIN_BUTTON_STANDBY))
	{
		delay(10);
	}

	// Enter the Deep Sleep of ESP32, and exit only if the button is pressed

	esp_sleep_enable_ext0_wakeup(PIN_BUTTON_STANDBY, 1); // 1 = High, 0 = Low

	logI("Entering deep sleep ...");

	esp_deep_sleep_start(); // TODO: hibernate ???

#else

	logI("Do not enter deep-sleep - pin not set - rebooting ...");

	appInitialize(true);
#endif
}

/**
 * @brief Show error and notifies the application error occurred
 */
void error(const char *message, bool fatal)
{

	// Debug

	logE("Error -> %s", message);

	// Send the message

	if (bleConnected())
	{
		string error = "-1:"; // -1 is a code of error messages
		error.append(message);
		bleSendData(error);
	}

	// Fatal ?

	if (fatal)
	{

		// Wait a time

		delay(200);

		// Restart ESP32

		restartESP32();
	}
}

/**
 * @brief Reset the ESP32
 */
void restartESP32()
{

	// TODO: see it! if need, put your custom code here

	// Reinitialize

	esp_restart();
}

/**
 * @brief Process informations request
 */
static void sendInfo(Fields &fields)
{

	// Note: the field 1 is a code of message

	// Type

	string type = fields.getString(2);

	logV("type=%s", type.c_str());

	// Note: this is a example of send large message

	const uint16_t MAX_INFO = 300;
	char info[MAX_INFO];

	// Return response (can bem more than 1, delimited by \n)

	string response = "";

	if (type == "ESP32" || type == "ALL")
	{ // Note: For this example string type, but can be numeric

		// About the ESP32 // based on Kolban GeneralUtils
		// With \r as line separator

		esp_chip_info_t chipInfo;
		esp_chip_info(&chipInfo);

		const uint8_t *macAddr = bleMacAddress();

		char deviceName[30] = BLE_DEVICE_NAME;

		uint8_t size = strlen(deviceName);

		if (size > 0 && deviceName[size - 1] == '_')
		{ // Put last 2 of mac address in the name

			char aux[7];
			sprintf(aux, "%02X%02X", macAddr[4], macAddr[5]);

			strcat(deviceName, aux);
		}

#if !CONFIG_FREERTOS_UNICORE
		const char *uniCore = "No";
#else
		const char *uniCore = "Yes";
#endif

		// Note: the \n is a message separator and : is a field separator
		// Due this send # and ; (this will replaced in app mobile)

		snprintf(info, MAX_INFO, "11:ESP32:"
								 "*** Chip Info#"
								 "* Model; %d#"
								 "* Revision; %d#"
								 "* Cores; %d#"
								 "* FreeRTOS unicore ?; %s#"
								 "* ESP-IDF;#  %s#"
								 "*** BLE info#"
								 "* Device name; %s#"
								 "* Mac-address; %02X;%02X;%02X;%02X;%02X;%02X#"
								 "\n",
				 chipInfo.model,
				 chipInfo.revision,
				 chipInfo.cores,
				 uniCore,
				 esp_get_idf_version(),
				 deviceName,
				 macAddr[0], macAddr[1],
				 macAddr[2], macAddr[3],
				 macAddr[4], macAddr[5]);

		response.append(info);
	}

	if (type == "FMEM" || type == "ALL")
	{

		// Free memory of ESP32

		snprintf(info, MAX_INFO, "11:FMEM:%u\n", heap_caps_get_free_size(MALLOC_CAP_8BIT));

		response.append(info);
	}

	if (type == "VDD33" || type == "ALL")
	{

		// Voltage of ESP32

		int read = rom_phy_get_vdd33();
		logV("rom_phy_get_vdd33=%d", read);

		snprintf(info, MAX_INFO, "11:VDD33:%d\n", read);

		response.append(info);
	}

#ifdef HAVE_BATTERY

	// VEXT and VBAT is update from energy message type

	if (type == "VBAT" || type == "VEXT" || type == "ALL")
	{

		checkEnergyVoltage(true);
	}
#endif

	//	logV("response -> %s", response.c_str());

	// Send

	bleSendData(response);
}

/**
 * @brief Initial Debugging 
 */
static void debugInitial()
{
	const esp_app_desc_t *p_app_desc = esp_ota_get_app_description();

	logV("Debugging is on now");

	logV("Firmware device version: %s", p_app_desc->version);
}

/**
 * @brief Cause an action on main_Task by task notification
 */
void IRAM_ATTR notifyMainTask(uint32_t action, bool fromISR)
{

	// Main Task is alive ?

	if (xTaskMainHandler == NULL)
	{
		return;
	}

	// Debug (for non ISR only)

	if (!fromISR)
	{
		logD("action=%u", action);
	}

	// Notify the main task

	if (fromISR)
	{ // From ISR
		BaseType_t xHigherPriorityTaskWoken;
		xTaskNotifyFromISR(xTaskMainHandler, action, eSetValueWithOverwrite, &xHigherPriorityTaskWoken);
	}
	else
	{
		xTaskNotify(xTaskMainHandler, action, eSetValueWithOverwrite);
	}
}

/**
 * @brief Cause an action on ota_task by task notification
 */
void IRAM_ATTR notifyOTATask(uint32_t action, bool fromISR)
{

	if (xTaskOTAHandler == NULL)
	{
		return;
	}

	// Debug (for non ISR only)

	if (!fromISR)
	{
		logD("action=%u", action);
	}

	// Notify the main task

	if (fromISR)
	{ // From ISR
		BaseType_t xHigherPriorityTaskWoken;
		xTaskNotifyFromISR(xTaskOTAHandler, action, eSetValueWithOverwrite, &xHigherPriorityTaskWoken);
	}
	else
	{
		xTaskNotify(xTaskOTAHandler, action, eSetValueWithOverwrite);
	}
}

//////// End
