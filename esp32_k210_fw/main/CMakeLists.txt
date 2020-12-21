idf_component_register(SRCS "app_main.c" "spi_master.c" "spi_common" "adc.c" "keypad.c" "uart.c" "wifi" "file_server.c" "ota.c"
                    INCLUDE_DIRS "."
                    EMBED_FILES "favicon.ico" "upload_script.html" "logo.png")
