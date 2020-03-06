set(COMPONENT_SRCDIRS ". util")
set(COMPONENT_ADD_INCLUDEDIRS ". util")
register_component()

component_compile_definitions(WIFI_SSID="$ENV{WIFI_SSID}" WIFI_PASSWORD="$ENV{WIFI_PASSWORD}" )
if (NOT "$ENV{ENV_FIRMWARE_UPGRADE_URL_BASE}" STREQUAL "")
    component_compile_definitions(ENV_FIRMWARE_UPGRADE_URL_BASE="$ENV{ENV_FIRMWARE_UPGRADE_URL_BASE}")
endif()
