//==============================================================
// PROJECT
// Circuit Analyzer: sample data manager
// ESP32-WROOM-32
// ESP-IDF
//==============================================================
//==============================================================
// STANDARD LIBRARIES
//==============================================================
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
//==============================================================
// ESP-IDF LIBRARIES
//==============================================================
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c.h"
#include "esp_adc/adc_oneshot.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "freertos/queue.h"
#include "esp_netif.h"
#include "driver/ledc.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_attr.h"
//==============================================================
// SYSTEM CONSTANTS
//==============================================================
// CPU
// Timing
//==============
#define STM32_PING_INTERVAL_MS      20
#define LIVE_POLL_INTERVAL_MS       78 // placeholder. I need to determine the ask rate when testing
#define I2C_MASTER_FREQ_HZ          100000
#define SPI_CLOCK_SPEED_HZ          2000000 //testing rate: raise after nothing else is wrong, we're eliminating clockrate as a variable
#define STATUS_REPORT_INTERVAL_MS   1000
#define DMM_REPORT_INTERVAL_MS       250
#define STM32_SAMPLE_RATE_HZ         2400000U
//TCP Packet Types
//==============
#define PACKET_TYPE_LIVE            0x01
#define PACKET_TYPE_ANOMALY         0x02
#define PACKET_TYPE_DMM             0x03
#define PACKET_TYPE_STATUS          0x04
#define PACKET_TYPE_HEARTBEAT       0x05
#define PACKET_TYPE_I2C_MAP         0x06
#define TCP_FRAME_HEADER_SIZE       20U
#define TCP_FRAME_MAGIC             "ECW1"
// Buffer size
//==============================================================
// 2.4 MSPS capture window, 4ms: 2,400,000 * 0.004 = 9600 samples,
// 16-bit right-aligned ADC words -> 9600 * 2 bytes = 19200 bytes
// 12-bit ADC words are right-aligned in 16-bit words, so the buffer size is still 19200 bytes
#define STM32_CAPTURE_BUFFER_SIZE   19200
#define CAPTURE_BUFFER_COUNT        2


//verify IP in Rpi
#define TCP_RECOVERY_DELAY_MS       2000 // if socket drops delay
#define TCP_SERVER_PORT             5005 //verify port in Rpi
#define WIFI_AP_SSID                "Chaotix"
#define WIFI_AP_PASSWORD            "redbull#11"
#define TCP_SERVER_IP               "10.42.0.1"
//PIN2 LED
//=================
#define STATUS_LED                  GPIO_NUM_2
#define STATUS_LED_FREQ_HZ          5000
#define STATUS_LED_MAX_DUTY         1023
#define STATUS_LED_BREATH_STEP_MS   25
#define STATUS_LED_BLIP_ON_MS       200
#define STATUS_LED_BLIP_GAP_MS      400
#define STATUS_LED_BLIP_LONG_MS     1000
//I2C INA219
//==============
#define INA219_ADDR                 0x44 // A1 bridged to V+
#define INA219_REG_CONFIG           0x00
#define INA219_REG_SHUNT_VOLTAGE    0x01
#define INA219_REG_BUS_VOLTAGE      0x02
#define INA219_REG_POWER            0x03
#define INA219_REG_CURRENT          0x04
#define INA219_REG_CALIBRATION      0x05
#define INA219_CAL_VALUE            4096 // figure out max- current value later
#define INA219_CURRENT_LSB          0.0001f
#define INA219_POWER_LSB            0.002f
//SPI STM32
//==============
#define STM32_CMD_GET_LIVE          0x01
#define STM32_CMD_GET_ANOMALY       0x02
#define STM32_ONLINE_RESPONSE       0xA5
#define STM32_OFFLINE_RESPONSE      0x00
#define SPI_RESPONSE_TIMEOUT_MS     10
//==============================================================
//==============================================================
// GPIO DEFINITIONS
//==================
// Hall Sensor
#define HALL_SENSOR_ADC_CHANNEL ADC_CHANNEL_4 //Test: confirm
// this maps to your actual wired GPIO (commonly GPIO on ADC1_CH6)
// INA219
#define I2C_MASTER_SDA_IO       21 //confirm against actual wiring
#define I2C_MASTER_SCL_IO       22 //confirm against actual wiring
#define I2C_MASTER_NUM          I2C_NUM_0 
// STM32 SPI
#define SPI_MOSI_IO             13
#define SPI_MISO_IO             25
#define SPI_SCLK_IO             26
#define SPI_CS_IO               27
#define SPI_HOST_USED           SPI3_HOST
// STM32 Interrupt
#define STM32_DATA_READY_GPIO   34
//==============================================================
//==============================================================
// GLOBAL HANDLES
//========
// I2C
//no handle needed
// ADC
static adc_oneshot_unit_handle_t adc1_handle; //KY-035 or other hall
// effect
// SPI
static spi_device_handle_t stm32_spi_handle; //STM32F411 communication
// GPIO
//no handle needed
// Queue (ISR -> task handoff)
static QueueHandle_t anomaly_queue; //ISR ---> task handoff for anomaly
// events
static QueueHandle_t status_led_queue;
static QueueHandle_t uplink_queue;
static QueueHandle_t free_capture_queue;
// WiFi/TCP
static int tcp_sock = -1;
static SemaphoreHandle_t spi_mutex;
static SemaphoreHandle_t measurement_mutex;
//==============================================================
//==============================================================
// GLOBAL VARIABLES
//================
// System State
static bool wifi_connected = false; //TEST: set true once anomaly
// buffer works
// Event Flags (e.g. anomaly_interrupt_fired)
static bool tcp_connected = false;
//Device State
static uint8_t stm32_status = STM32_OFFLINE_RESPONSE;
static bool ina219_connected = false;
// Buffers
typedef struct {
    uint8_t packet_type;
    uint8_t buffer_index;
    uint16_t reserved;
    uint32_t payload_length;
} uplink_message_t;

/* SPI DMA buffers must be in internal DMA-capable RAM and 32-bit aligned. */
DMA_ATTR static uint8_t capture_buffers[CAPTURE_BUFFER_COUNT]
                                           [STM32_CAPTURE_BUFFER_SIZE];
static uint32_t tcp_sequence = 1;
_Static_assert(sizeof(float) == 4, "ECW1 DMM payload requires 32-bit float");
typedef enum {
STATUS_LED_EVENT_WIFI = 1,
STATUS_LED_EVENT_SPI,
STATUS_LED_EVENT_I2C,
STATUS_LED_EVENT_INTERRUPT
} status_led_event_t;
static float last_voltage = 0,
last_current = 0, last_power = 0;
static int last_hall_value = 0;
//==============================================================
//==============================================================
// FUNCTION PROTOTYPES
//==============================================================
static esp_err_t i2c_master_init(void);
static bool i2c_send_map_to_pi(void);
static esp_err_t adc_hall_init(void);
static esp_err_t spi_stm32_init(void);
static uint8_t stm32_check_online(void);
static void gpio_interrupt_init(void);
static esp_err_t system_init(void);
static esp_err_t wifi_init(void);
static esp_err_t ina219_read(float *voltage, float *current, float
*power);
static esp_err_t spi_pull_stm32_buffer(uint8_t command, uint8_t *destination);
static esp_err_t tcp_connect(void);
static bool tcp_send_data(const uint8_t *data, size_t len);
static bool tcp_send_frame(uint8_t packet_type, uint8_t flags,
                           uint32_t sample_rate, const uint8_t *payload,
                           uint32_t payload_length);
static void data_ready_isr(void*arg);
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
int32_t event_id, void* event_data);
static void status_led_init(gpio_num_t pin);
static void status_led_task(void *arg);
static void status_led_notify(status_led_event_t event);
static void status_led_notify_from_isr(status_led_event_t event);
static void live_poll_task(void *arg);
static void i2c_read_task(void *arg);
static void hall_read_task(void *arg);
static void anomaly_task(void *arg);
static void wifi_uplink_task(void *arg);
static void tcp_send_status(void);
//==============================================================
// SYSTEM INITIALIZATION
//==============================================================
static esp_err_t system_init(void) {
 esp_err_t ret = nvs_flash_init();
 if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret ==
ESP_ERR_NVS_NEW_VERSION_FOUND){
 ESP_ERROR_CHECK(nvs_flash_erase());
 ret = nvs_flash_init();
 }
 return ret;}
//==============================================================
// GPIO INITIALIZATION +OPERATIONS
//==============================================================
static void gpio_interrupt_init(void) {
 gpio_config_t io_conf =
 {
 .pin_bit_mask = (1ULL << STM32_DATA_READY_GPIO),
 .mode = GPIO_MODE_INPUT,
 .intr_type = GPIO_INTR_POSEDGE, //TEST: confirm STM32 drives this
// high to signal data ready
 };
 gpio_config(&io_conf);
 gpio_install_isr_service(0);
 gpio_isr_handler_add(STM32_DATA_READY_GPIO, data_ready_isr, NULL);
}
static void status_led_init(gpio_num_t pin)
{
 ledc_timer_config_t timer_conf = {
 .speed_mode = LEDC_LOW_SPEED_MODE,
 .timer_num = LEDC_TIMER_0,
 .duty_resolution = LEDC_TIMER_10_BIT,
 .freq_hz = STATUS_LED_FREQ_HZ,
 .clk_cfg = LEDC_AUTO_CLK,
 };
 ledc_timer_config(&timer_conf);
 ledc_channel_config_t chan_conf = {
 .gpio_num = pin,
 .speed_mode = LEDC_LOW_SPEED_MODE,
 .channel = LEDC_CHANNEL_0,
 .intr_type = LEDC_INTR_DISABLE,
 .timer_sel = LEDC_TIMER_0,
 .duty = 0,
 .hpoint = 0,
 };
 ledc_channel_config(&chan_conf);
 status_led_queue = xQueueCreate(8, sizeof(status_led_event_t));}
//==============================================================
// I2C INITIALIZATION + OPERATIONS
//==============================================================
static esp_err_t i2c_master_init(void) {
 i2c_config_t conf = {
 .mode = I2C_MODE_MASTER,
 .sda_io_num = I2C_MASTER_SDA_IO,
 .scl_io_num = I2C_MASTER_SCL_IO,
 .sda_pullup_en = GPIO_PULLUP_ENABLE,
 .scl_pullup_en = GPIO_PULLUP_ENABLE,
 .master.clk_speed = I2C_MASTER_FREQ_HZ,
 };
 i2c_param_config(I2C_MASTER_NUM, &conf);
 return i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0);
}
static esp_err_t ina219_calibrate(void) {
 uint8_t cal_data[3] = {
 INA219_REG_CALIBRATION,
 (INA219_CAL_VALUE >> 8) & 0xFF,
 INA219_CAL_VALUE & 0XFF
 };
 return i2c_master_write_to_device(I2C_MASTER_NUM, INA219_ADDR,
 cal_data, sizeof(cal_data),
 pdMS_TO_TICKS(100));
}
static esp_err_t ina219_read(float *voltage, float *current, float *power)
{
    uint8_t reg, raw[2];
    esp_err_t ret;

    reg = INA219_REG_BUS_VOLTAGE;
    ret = i2c_master_write_read_device(
        I2C_MASTER_NUM,
        INA219_ADDR,
        &reg,
        1,
        raw,
        2,
        pdMS_TO_TICKS(100)
    );

    if (ret != ESP_OK) return ret;

    uint16_t bus_raw =
        ((uint16_t)((raw[0] << 8) | raw[1])) >> 3;

    *voltage = bus_raw * 0.004f;


    reg = INA219_REG_CURRENT;
    ret = i2c_master_write_read_device(
        I2C_MASTER_NUM,
        INA219_ADDR,
        &reg,
        1,
        raw,
        2,
        pdMS_TO_TICKS(100)
    );

    if (ret != ESP_OK) return ret;

    int16_t current_raw =
        (int16_t)((raw[0] << 8) | raw[1]);

    *current = current_raw * INA219_CURRENT_LSB;


    reg = INA219_REG_POWER;
    ret = i2c_master_write_read_device(
        I2C_MASTER_NUM,
        INA219_ADDR,
        &reg,
        1,
        raw,
        2,
        pdMS_TO_TICKS(100)
    );

    if (ret != ESP_OK) return ret;

    uint16_t power_raw =
        (uint16_t)((raw[0] << 8) | raw[1]);

    *power = power_raw * INA219_POWER_LSB;


    /*
     * TEMPORARY INA219 DIAGNOSTIC
     *
     * Reads:
     *  - raw shunt voltage
     *  - calibration register
     *  - configuration register
     *
     * This does NOT alter the normal V/A/W output.
     */

    static uint32_t diag_count = 0;

    if (++diag_count >= 30)
    {
        diag_count = 0;

        int16_t shunt_raw = 0;
        uint16_t cal_raw = 0;
        uint16_t config_raw = 0;

        bool shunt_ok = false;
        bool cal_ok = false;
        bool config_ok = false;


        // ------------------------------
        // SHUNT VOLTAGE REGISTER
        // ------------------------------

        reg = INA219_REG_SHUNT_VOLTAGE;

        if (i2c_master_write_read_device(
                I2C_MASTER_NUM,
                INA219_ADDR,
                &reg,
                1,
                raw,
                2,
                pdMS_TO_TICKS(100)
            ) == ESP_OK)
        {
            shunt_raw =
                (int16_t)((raw[0] << 8) | raw[1]);

            shunt_ok = true;
        }


        // ------------------------------
        // CALIBRATION REGISTER
        // ------------------------------

        reg = INA219_REG_CALIBRATION;

        if (i2c_master_write_read_device(
                I2C_MASTER_NUM,
                INA219_ADDR,
                &reg,
                1,
                raw,
                2,
                pdMS_TO_TICKS(100)
            ) == ESP_OK)
        {
            cal_raw =
                (uint16_t)((raw[0] << 8) | raw[1]);

            cal_ok = true;
        }


        // ------------------------------
        // CONFIGURATION REGISTER
        // ------------------------------

        reg = INA219_REG_CONFIG;

        if (i2c_master_write_read_device(
                I2C_MASTER_NUM,
                INA219_ADDR,
                &reg,
                1,
                raw,
                2,
                pdMS_TO_TICKS(100)
            ) == ESP_OK)
        {
            config_raw =
                (uint16_t)((raw[0] << 8) | raw[1]);

            config_ok = true;
        }


        // ------------------------------
        // SERIAL DIAGNOSTIC
        // ------------------------------

        ESP_LOGI(
            "INA219",
            "V=%.4fV BUSraw=%u  "
            "I=%.6fA Iraw=%d  "
            "P=%.6fW Praw=%u  "
            "SHUNTraw=%d (%s)  "
            "CAL=0x%04X (%s)  "
            "CFG=0x%04X (%s)",

            (double)*voltage,
            (unsigned)bus_raw,

            (double)*current,
            (int)current_raw,

            (double)*power,
            (unsigned)power_raw,

            (int)shunt_raw,
            shunt_ok ? "OK" : "ERR",

            (unsigned)cal_raw,
            cal_ok ? "OK" : "ERR",

            (unsigned)config_raw,
            config_ok ? "OK" : "ERR"
        );


        if (cal_ok &&
            cal_raw != INA219_CAL_VALUE)
        {
            ESP_LOGW(
                "INA219",
                "Calibration mismatch: expected 0x%04X, read 0x%04X",

                (unsigned)INA219_CAL_VALUE,
                (unsigned)cal_raw
            );
        }
    }

    return ESP_OK;
}
static bool i2c_send_map_to_pi(void)
{
 char map[640];
 size_t used = 0;
 bool ina219_found = false;
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "    0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\r\n"
 );
 for (uint8_t row = 0; row < 8; row++) {
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "%02x: ",
 row << 4
 );
 for (uint8_t col = 0; col < 16; col++) {
 uint8_t addr = (row << 4) | col; /* Reserved I2C addresses */
 if (addr < 0x03 || addr > 0x77) {
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "   "
 );
 continue;
 }
 i2c_cmd_handle_t cmd = i2c_cmd_link_create();
 i2c_master_start(cmd);
 i2c_master_write_byte(
 cmd,
 (addr << 1) | I2C_MASTER_WRITE,
 true
 );
 i2c_master_stop(cmd);
 esp_err_t ret = i2c_master_cmd_begin(
 I2C_MASTER_NUM,
 cmd,
 pdMS_TO_TICKS(20)
 );
 i2c_cmd_link_delete(cmd);
 if (ret == ESP_OK) {
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "%02x ",
 addr
 );
 if (addr == INA219_ADDR) {
 ina219_found = true;
 }
 } else {
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "-- "
 );
 }
 }
 used += snprintf(
 map + used,
 sizeof(map) - used,
 "\r\n"
 );
 }
 if (measurement_mutex != NULL &&
     xSemaphoreTake(measurement_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
 ina219_connected = ina219_found;
 xSemaphoreGive(measurement_mutex);
 }

 tcp_send_frame(
     PACKET_TYPE_I2C_MAP,
     0,
     0,
     (const uint8_t *)map,
     (uint32_t)used
 );
return ina219_found;
}
//==============================================================
// ADC INITIALIZATION + OPERATIONS
//==============================================================
static esp_err_t adc_hall_init(void)
{
 adc_oneshot_unit_init_cfg_t init_config =
 {
 .unit_id = ADC_UNIT_1,
 };
 adc_oneshot_new_unit(&init_config,&adc1_handle);
 adc_oneshot_chan_cfg_t chan_config = { .bitwidth = ADC_BITWIDTH_DEFAULT,
 .atten = ADC_ATTEN_DB_12, 
 }; //Test: confirms full 0-3V3 range readable; adjust if readings clip
 return adc_oneshot_config_channel(adc1_handle,
HALL_SENSOR_ADC_CHANNEL,
 &chan_config);
 }
 static esp_err_t hall_sensor_read(int *raw_value){
 return adc_oneshot_read(adc1_handle, HALL_SENSOR_ADC_CHANNEL,
raw_value);
 }
//==============================================================
// SPI INITIALIZATION + OPERATIONS
//==============================================================
static esp_err_t spi_stm32_init(void) {
 spi_bus_config_t buscfg = {
 .mosi_io_num = SPI_MOSI_IO,
 .miso_io_num = SPI_MISO_IO,
 .sclk_io_num = SPI_SCLK_IO,
 .quadwp_io_num = -1,
 .quadhd_io_num = -1,
 .max_transfer_sz = STM32_CAPTURE_BUFFER_SIZE + 64, // headroom above the
 // 19200-byte STM32 sample buffer transfer
 };
 esp_err_t ret = spi_bus_initialize(SPI_HOST_USED, &buscfg,
SPI_DMA_CH_AUTO);
 if (ret != ESP_OK) {
 return ret;
 }
 spi_device_interface_config_t devcfg = {
 .clock_speed_hz = SPI_CLOCK_SPEED_HZ,
 .mode = 0,
 .spics_io_num = SPI_CS_IO,
 .queue_size = 1,
 };
 return spi_bus_add_device(SPI_HOST_USED, &devcfg, &stm32_spi_handle);
}
static uint8_t stm32_check_online(void)
{
    uint8_t tx_byte = 0x00;
    uint8_t rx_byte = STM32_OFFLINE_RESPONSE;

    spi_transaction_t transaction = {
        .length = 8,
        .tx_buffer = &tx_byte,
        .rx_buffer = &rx_byte,
    };

    esp_err_t ret = spi_device_transmit(
        stm32_spi_handle,
        &transaction
    );

    if (ret != ESP_OK) {
        ESP_LOGE("SPI",
                 "Handshake SPI transaction failed: %s",
                 esp_err_to_name(ret));

        stm32_status = STM32_OFFLINE_RESPONSE;
        return stm32_status;
    }

    ESP_LOGW("SPI",
             "HANDSHAKE TX=0x%02X RX=0x%02X EXPECTED=0x%02X",
             tx_byte,
             rx_byte,
             STM32_ONLINE_RESPONSE);

    if (rx_byte == STM32_ONLINE_RESPONSE) {
        stm32_status = STM32_ONLINE_RESPONSE;
        return stm32_status;
    }

    stm32_status = STM32_OFFLINE_RESPONSE;
    return stm32_status;
}

//==============================================================
// WIFI INITIALIZATION + OPERATIONS
//==============================================================
static esp_err_t wifi_init(void) {
 esp_netif_init();
 esp_event_loop_create_default();
 esp_netif_create_default_wifi_sta();
 wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
 esp_wifi_init(&cfg);
 esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
&wifi_event_handler, NULL, NULL);
 esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
&wifi_event_handler, NULL, NULL);
 wifi_config_t wifi_config = {
 .sta = {
 .ssid = WIFI_AP_SSID,
 .password = WIFI_AP_PASSWORD,
 },
 };
 esp_wifi_set_mode(WIFI_MODE_STA);
 esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
 return esp_wifi_start();
}
static esp_err_t tcp_connect(void) {
 struct sockaddr_in server_addr ={0};

 if (tcp_sock >= 0) {
 close(tcp_sock);
 tcp_sock = -1;
 }
 
 tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 if (tcp_sock < 0) {
 tcp_connected = false;
 return ESP_FAIL;
 }
 server_addr.sin_family = AF_INET;
 server_addr.sin_port = htons(TCP_SERVER_PORT);
 inet_pton(AF_INET, TCP_SERVER_IP, &server_addr.sin_addr);
 struct timeval send_timeout = {
 .tv_sec = 2,
 .tv_usec = 0,
 };
 setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO,
            &send_timeout, sizeof(send_timeout));
 if (connect(tcp_sock, (struct sockaddr *)&server_addr,
 sizeof(server_addr)) < 0) { close(tcp_sock);
 tcp_sock = -1;
 return ESP_FAIL;
 }
 tcp_connected = true;
 return ESP_OK;
}
 static bool tcp_send_data(const uint8_t *data, size_t len)
{
 size_t total_sent = 0;

 if (!tcp_connected || tcp_sock < 0) {
 return false;
 }

 while (total_sent < len) {
 int sent = send(
 tcp_sock,
 data + total_sent,
 len - total_sent,
 0
 );

 if (sent <= 0) {
 close(tcp_sock);
 tcp_sock = -1;
 tcp_connected = false;
 return false;
 }

 total_sent += (size_t)sent;
 }
 return true;
}

static void put_u16_le(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)((value >> 8) & 0xffU);
}

static void put_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)((value >> 8) & 0xffU);
    dst[2] = (uint8_t)((value >> 16) & 0xffU);
    dst[3] = (uint8_t)((value >> 24) & 0xffU);
}

static bool tcp_send_frame(uint8_t packet_type, uint8_t flags,
                           uint32_t sample_rate, const uint8_t *payload,
                           uint32_t payload_length)
{
    uint8_t header[TCP_FRAME_HEADER_SIZE];
    uint32_t sequence = tcp_sequence++;

    if (payload_length > 0 && payload == NULL) {
        ESP_LOGE("TCP", "Frame payload is NULL");
        return false;
    }

    memcpy(&header[0], TCP_FRAME_MAGIC, 4);
    header[4] = packet_type;
    header[5] = flags;
    put_u16_le(&header[6], TCP_FRAME_HEADER_SIZE);
    put_u32_le(&header[8], sequence);
    put_u32_le(&header[12], sample_rate);
    put_u32_le(&header[16], payload_length);

    if (!tcp_send_data(header, sizeof(header))) {
        return false;
    }
    if (payload_length == 0) {
        return true;
    }
    return tcp_send_data(payload, payload_length);
}

static void tcp_send_status(void)
{
    char status[160];
    bool ina_online;

    if (xSemaphoreTake(measurement_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        ina_online = ina219_connected;
        xSemaphoreGive(measurement_mutex);
    } else {
        ina_online = false;
    }

    int length = snprintf(
        status,
        sizeof(status),
        "{\"wifi\":%s,\"tcp\":%s,\"stm32\":%s,\"ina219\":%s,"
        "\"adc\":%s,\"hall\":%s}",
        wifi_connected ? "true" : "false",
        tcp_connected ? "true" : "false",
        (stm32_status == STM32_ONLINE_RESPONSE) ? "true" : "false",
        ina_online ? "true" : "false",
        (stm32_status == STM32_ONLINE_RESPONSE) ? "true" : "false",
        "true"
    );
    if (length > 0 && length < (int)sizeof(status)) {
        tcp_send_frame(PACKET_TYPE_STATUS, 0, 0,
                       (const uint8_t *)status, (uint32_t)length);
    }
}
//==============================================================
// INTERRUPT INITIALIZATION
//==============================================================
//gpio already configured, leaving placeholder for future expansion
//==============================================================
// TASK INITIALIZATION
//==============================================================
static esp_err_t spi_pull_stm32_buffer(uint8_t command, uint8_t *destination)
{
    if (destination == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (stm32_check_online() != STM32_ONLINE_RESPONSE)
    {
    stm32_status = STM32_OFFLINE_RESPONSE;
    ESP_LOGW("SPI", "STM32 handshake failed");
    return ESP_ERR_NOT_FOUND;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
 /*
 * Transaction 1:
 * Physically request the buffer from the STM32. `command` selects
 * whether this is a routine live poll (STM32_CMD_GET_LIVE) or an
 * anomaly-triggered pull (STM32_CMD_GET_ANOMALY).
 */
 spi_transaction_t command_transaction = {
 .length = 8,
 .tx_buffer = &command,
 .rx_buffer = NULL,
 };
 esp_err_t ret = spi_device_transmit(
 stm32_spi_handle,
 &command_transaction
 );
 if (ret != ESP_OK) {
    stm32_status = STM32_OFFLINE_RESPONSE;
 ESP_LOGE(
 "SPI",
 "STM32 request (cmd 0x%02x) failed: %s",
 command,
 esp_err_to_name(ret)
 );
 return ret;
 }
 /*
 * Temporary allowance for the STM32 to select its completed
 * ADC/DMA buffer before the ESP32 begins clocking it out.
 */
 vTaskDelay(pdMS_TO_TICKS(2));
 /*
 * Transaction 2:
 * Clock the real STM32 buffer into the DMA buffer owned by this request.
 */
 spi_transaction_t payload_transaction = {
 .length = STM32_CAPTURE_BUFFER_SIZE * 8,
 .tx_buffer = NULL,
 .rx_buffer = destination,
 };
 ret = spi_device_transmit(
 stm32_spi_handle,
 &payload_transaction
 );
 if (ret == ESP_OK) {
 ESP_LOGI(
 "SPI",
 "Received %u bytes from STM32 (cmd 0x%02x)",
 (unsigned)STM32_CAPTURE_BUFFER_SIZE,
 command
 );
 } else {
    stm32_status = STM32_OFFLINE_RESPONSE;
 ESP_LOGE(
 "SPI",
 "STM32 buffer receive failed: %s",
 esp_err_to_name(ret)
 );
 }
 return ret;
}
static void live_poll_task(void *arg) {
 for (;;) {
 esp_err_t ret = ESP_ERR_TIMEOUT;
 uint8_t buffer_index;

 if (xQueueReceive(free_capture_queue, &buffer_index, 0) != pdTRUE) {
 ESP_LOGW("SPI", "No free capture buffer; dropping live poll");
 vTaskDelay(pdMS_TO_TICKS(LIVE_POLL_INTERVAL_MS));
 continue;
 }

 if (xSemaphoreTake(
 spi_mutex,
 pdMS_TO_TICKS(SPI_RESPONSE_TIMEOUT_MS)
 ) == pdTRUE) {
 ret = spi_pull_stm32_buffer(
     STM32_CMD_GET_LIVE,
     capture_buffers[buffer_index]
 );
 xSemaphoreGive(spi_mutex);
 } else {
 ESP_LOGW(
 "SPI",
 "Timeout waiting for SPI mutex"
 );
 }
 if (ret == ESP_OK) {
 uplink_message_t message = {
     .packet_type = PACKET_TYPE_LIVE,
     .buffer_index = buffer_index,
     .reserved = 0,
     .payload_length = STM32_CAPTURE_BUFFER_SIZE,
 };
 if (xQueueSend(
 uplink_queue,
&message,
pdMS_TO_TICKS(20)) != pdTRUE) {
 ESP_LOGW(
 "TCP",
"Uplink queue full, dropping message"
 );
 xQueueSend(free_capture_queue, &buffer_index, 0);
 }
 } else {
 xQueueSend(free_capture_queue, &buffer_index, 0);
 ESP_LOGE(
 "SPI",
 "Failed to pull STM32 buffer: %s",
 esp_err_to_name(ret)
 );
 }
 vTaskDelay(
 pdMS_TO_TICKS(LIVE_POLL_INTERVAL_MS)
 );
 }
}
static void i2c_read_task(void *arg) {
 float voltage, current, power;
 for (;;) {
 if (ina219_read(&voltage, &current, &power) == ESP_OK){
 if (xSemaphoreTake(measurement_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
 ina219_connected = true;
 last_voltage = voltage;
 last_current = current;
 last_power = power;
 xSemaphoreGive(measurement_mutex);
 }
 status_led_notify(STATUS_LED_EVENT_I2C);
} else {
 if (xSemaphoreTake(measurement_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
 ina219_connected = false;
 xSemaphoreGive(measurement_mutex);
 }
}
 vTaskDelay(pdMS_TO_TICKS(LIVE_POLL_INTERVAL_MS));
 }
}
static void hall_read_task(void *arg) {
 int raw_value;
 for (;;){
 if(hall_sensor_read(&raw_value) == ESP_OK) {
 last_hall_value = raw_value;
 }
 vTaskDelay(pdMS_TO_TICKS(LIVE_POLL_INTERVAL_MS));
 }
 
}
static void anomaly_task(void *arg) {
 int dummy;
 for (;;) {
 if(xQueueReceive(anomaly_queue, &dummy, portMAX_DELAY) == pdTRUE){
 uint8_t buffer_index;
 if (xQueueReceive(
     free_capture_queue,
     &buffer_index,
     pdMS_TO_TICKS(100)) != pdTRUE) {
     ESP_LOGW("SPI", "No free capture buffer; dropping anomaly");
     continue;
 }
 if(xSemaphoreTake(
 spi_mutex,
pdMS_TO_TICKS(100)) == pdTRUE) {
 if(spi_pull_stm32_buffer(
        STM32_CMD_GET_ANOMALY,
        capture_buffers[buffer_index]) == ESP_OK) {
 uplink_message_t message = {
     .packet_type = PACKET_TYPE_ANOMALY,
     .buffer_index = buffer_index,
     .reserved = 0,
     .payload_length = STM32_CAPTURE_BUFFER_SIZE,
 };
 if (xQueueSend(uplink_queue, &message, pdMS_TO_TICKS(20)) != pdTRUE) {
     ESP_LOGW("TCP", "Uplink queue full, dropping anomaly");
     xQueueSend(free_capture_queue, &buffer_index, 0);
 }
 } else {
 xQueueSend(free_capture_queue, &buffer_index, 0);
 }
 xSemaphoreGive(spi_mutex);
 } else {
 xQueueSend(free_capture_queue, &buffer_index, 0);
 }
 }
 }
}
static void wifi_uplink_task(void *arg)
{
 uplink_message_t message;
 TickType_t last_status_report = xTaskGetTickCount();
 TickType_t last_dmm_report = xTaskGetTickCount();
 for (;;) {
 if (!wifi_connected) {
 vTaskDelay(pdMS_TO_TICKS(500));
 continue;
 }
 if (!tcp_connected) {
 ESP_LOGI("TCP", "Searching for Pi TCP server");
 if (tcp_connect() != ESP_OK) {
 ESP_LOGW("TCP", "TCP connection failed");
 vTaskDelay(pdMS_TO_TICKS(TCP_RECOVERY_DELAY_MS));
 continue;
 } ESP_LOGI("TCP", "ESP32 connected to Pi");
 tcp_send_status();
 last_status_report = xTaskGetTickCount();
 i2c_send_map_to_pi();
 ESP_LOGI("TCP", "Preparing packets");
 }
 if ((xTaskGetTickCount() - last_status_report) >=
    pdMS_TO_TICKS(STATUS_REPORT_INTERVAL_MS)) {

    tcp_send_status();
    last_status_report = xTaskGetTickCount();
}

 if ((xTaskGetTickCount() - last_dmm_report) >=
     pdMS_TO_TICKS(DMM_REPORT_INTERVAL_MS)) {
     float dmm_values[3];
     bool dmm_ready = false;

     if (xSemaphoreTake(measurement_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
         if (ina219_connected &&
             isfinite(last_voltage) &&
             isfinite(last_current) &&
             isfinite(last_power)) {
             dmm_values[0] = last_voltage;
             dmm_values[1] = last_current;
             dmm_values[2] = last_power;
             dmm_ready = true;
         }
         xSemaphoreGive(measurement_mutex);
     }

     if (dmm_ready) {
         tcp_send_frame(
             PACKET_TYPE_DMM,
             0,
             0,
             (const uint8_t *)dmm_values,
             sizeof(dmm_values)
         );
     }
     last_dmm_report = xTaskGetTickCount();
 }

 if (xQueueReceive(
 uplink_queue,
 &message,
 pdMS_TO_TICKS(50)) != pdTRUE) {
 continue;
 }

 if (message.buffer_index >= CAPTURE_BUFFER_COUNT ||
     message.payload_length > STM32_CAPTURE_BUFFER_SIZE) {
 ESP_LOGE("TCP", "Invalid uplink descriptor");
 if (message.buffer_index < CAPTURE_BUFFER_COUNT) {
     xQueueSend(free_capture_queue, &message.buffer_index, 0);
 }
 continue;
 }
 ESP_LOGI(
 "TCP",
 "Packet ready; sending %u bytes",
 (unsigned)message.payload_length
 );
 tcp_send_frame(
     message.packet_type,
     0,
     STM32_SAMPLE_RATE_HZ,
     capture_buffers[message.buffer_index],
     message.payload_length
 );
 if (xQueueSend(free_capture_queue, &message.buffer_index, 0) != pdTRUE) {
     ESP_LOGE("SPI", "Could not return capture buffer to pool");
 }
 }
}

//==============================================================
// CALLBACKS / INTERRUPTS
//==============================================================
static void IRAM_ATTR data_ready_isr(void*arg)
{
 int dummy = 1;
 BaseType_t woken = pdFALSE;
 xQueueSendFromISR(anomaly_queue, &dummy, &woken);
 status_led_notify_from_isr(STATUS_LED_EVENT_INTERRUPT);
 
 if(woken) portYIELD_FROM_ISR();
}
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
int32_t
event_id, void* event_data){
 if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START){
 esp_wifi_connect();
 } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
 wifi_connected = true;
 } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
 wifi_connected = false;
 tcp_connected = false;
 esp_wifi_connect();
 }
}
 static void status_led_task(void *arg)
{
 static float phase = 0.0f;
 const float phase_step = (2.0f * (float)M_PI) / 170.0f;
 status_led_event_t event;
 for (;;) {
 if (xQueueReceive(status_led_queue, &event, 0) == pdTRUE) {
 int blips = (event == STATUS_LED_EVENT_WIFI) ? 1
 : (event == STATUS_LED_EVENT_SPI) ? 2
 : (event == STATUS_LED_EVENT_I2C) ? 3 : 1;
 int on_ms = (event == STATUS_LED_EVENT_INTERRUPT) ? STATUS_LED_BLIP_LONG_MS : STATUS_LED_BLIP_ON_MS;
 for (int i = 0; i < blips; i++) {
 ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0,
STATUS_LED_MAX_DUTY);
 ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
 vTaskDelay(pdMS_TO_TICKS(on_ms));
 ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
 ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
 vTaskDelay(pdMS_TO_TICKS(STATUS_LED_BLIP_GAP_MS));
 }
 phase = 0.0f;
 continue;
 }
 
float t = phase / (2.0f * (float)M_PI);
float level;

if (t < 0.25f) {
    // Main pulse: dim -> bright
    float x = t / 0.25f;
    level = 0.5f - 0.5f * cosf((float)M_PI * x);

} else if (t < 0.50f) {
    // Main pulse fading: bright -> half dim
    float x = (t - 0.25f) / 0.25f;
    level = 0.75f + 0.25f * cosf((float)M_PI * x);

} else if (t < 0.60f) {
    // Second heartbeat: half dim -> bright quickly
    float x = (t - 0.50f) / 0.10f;
    level = 0.75f - 0.25f * cosf((float)M_PI * x);

} else {
    // Second heartbeat fades completely
    float x = (t - 0.60f) / 0.40f;
    level = 0.5f + 0.5f * cosf((float)M_PI * x);
}
 ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0,
(uint32_t)(level * STATUS_LED_MAX_DUTY));
 ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
 phase += phase_step;
 if (phase >= 2.0f * (float)M_PI) phase -= 2.0f * (float)M_PI;
 vTaskDelay(pdMS_TO_TICKS(STATUS_LED_BREATH_STEP_MS));
 }
}
static void status_led_notify(status_led_event_t event)
{
 xQueueSend(status_led_queue, &event, 0);
}
static void status_led_notify_from_isr(status_led_event_t event)
{
 BaseType_t woken = pdFALSE;
 xQueueSendFromISR(status_led_queue, &event, &woken);
 if (woken) portYIELD_FROM_ISR();
}
//==============================================================
// APPLICATION ENTRY
//==============================================================
void app_main(void)
{
 ESP_ERROR_CHECK(system_init());
 ESP_ERROR_CHECK(i2c_master_init());
 esp_err_t ina_calibration_result = ina219_calibrate();
 if (ina_calibration_result != ESP_OK) {
     ESP_LOGW("I2C", "INA219 calibration failed at startup: %s",
              esp_err_to_name(ina_calibration_result));
 }
 ESP_ERROR_CHECK(adc_hall_init());
 ESP_ERROR_CHECK(spi_stm32_init());
 anomaly_queue = xQueueCreate(4, sizeof(int));
 uplink_queue = xQueueCreate(4, sizeof(uplink_message_t));
 free_capture_queue = xQueueCreate(CAPTURE_BUFFER_COUNT, sizeof(uint8_t));
 spi_mutex = xSemaphoreCreateMutex();
 measurement_mutex = xSemaphoreCreateMutex();
 status_led_init(STATUS_LED);

 configASSERT(anomaly_queue != NULL);
 configASSERT(uplink_queue != NULL);
 configASSERT(free_capture_queue != NULL);
 configASSERT(spi_mutex != NULL);
 configASSERT(measurement_mutex != NULL);
 configASSERT(status_led_queue != NULL);

 for (uint8_t i = 0; i < CAPTURE_BUFFER_COUNT; ++i) {
     configASSERT(xQueueSend(free_capture_queue, &i, 0) == pdTRUE);
 }

 if (stm32_check_online() == STM32_ONLINE_RESPONSE) {
    status_led_notify(STATUS_LED_EVENT_SPI);
}

 gpio_interrupt_init();
 
 wifi_init();
 xTaskCreate(status_led_task, "status_led_task", 2048, NULL, 1, NULL);
 xTaskCreate(live_poll_task, "live_poll_task", 4096, NULL, 5, NULL);
 xTaskCreate(i2c_read_task, "i2c_read_task", 4096, NULL, 5, NULL);
 xTaskCreate(anomaly_task, "anomaly_task", 4096, NULL, 10, NULL);
 xTaskCreate(wifi_uplink_task, "wifi_uplink_task", 4096, NULL, 6,
NULL);
 xTaskCreate(hall_read_task, "hall_read_task", 4096, NULL, 5, NULL);
}