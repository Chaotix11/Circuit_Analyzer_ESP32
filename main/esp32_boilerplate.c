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
//==============================================================
// SYSTEM CONSTANTS
//==============================================================
// CPU
// Timing
//==============
#define STM32_PING_INTERVAL_MS      20
#define LIVE_POLL_INTERVAL_MS       33 // placeholder. I need to determine the ask rate when testing
#define I2C_MASTER_FREQ_HZ          100000
#define SPI_CLOCK_SPEED_HZ          2000000 //testing rate: raise after nothing else is wrong, we're eliminating clockrate as a variable
#define STATUS_REPORT_INTERVAL_MS   1000
//TCP Packet Types
//==============
#define PACKET_TYPE_STATUS          0x01
#define PACKET_TYPE_LIVE            0x02
#define PACKET_TYPE_ANOMALY         0x03
#define PACKET_TYPE_I2C_MAP         0x04
//Packet Values
//==============
#define DEVICE_OFFLINE              0x00
#define DEVICE_ONLINE               0x01
// Buffer size
//==============================================================
// 2.4 MSPS capture window, 4ms: 2,400,000 * 0.004 = 9600 samples,
// 16-bit right-aligned ADC words -> 9600 * 2 bytes = 19200 bytes
// 12-bit ADC words are right-aligned in 16-bit words, so the buffer size is still 19200 bytes
#define STM32_CAPTURE_BUFFER_SIZE   19200


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
// WiFi/TCP
static int tcp_sock = -1;
static SemaphoreHandle_t spi_mutex;
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
typedef struct {
    uint8_t packet_type;
    uint8_t wifi;
    uint8_t tcp;
    uint8_t stm32;
    uint8_t ina219;
} status_packet_t;
// Buffers
static uint8_t anomaly_buffer[STM32_CAPTURE_BUFFER_SIZE];
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
static esp_err_t spi_pull_stm32_buffer(uint8_t command);
static esp_err_t tcp_connect(void);
static void tcp_send_data(const uint8_t *data, size_t len);
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
static esp_err_t ina219_read(float *voltage, float *current, float
*power){
 uint8_t reg, raw[2];
 esp_err_t ret;
 reg = INA219_REG_BUS_VOLTAGE;
 ret = i2c_master_write_read_device(I2C_MASTER_NUM, INA219_ADDR, &reg,
1, raw, 2,
pdMS_TO_TICKS(100));
 if (ret != ESP_OK) return ret;
 int16_t bus_raw = ((raw[0] << 8) | raw[1]) >> 3;
 *voltage = bus_raw * 0.004f;

 reg = INA219_REG_CURRENT;
 ret = i2c_master_write_read_device(I2C_MASTER_NUM, INA219_ADDR, &reg,
1, raw, 2, pdMS_TO_TICKS(100));
 if (ret!= ESP_OK) return ret;
 int16_t current_raw = ((raw[0] << 8) | raw[1]);
 *current = current_raw * INA219_CURRENT_LSB;

 reg = INA219_REG_POWER;
 ret = i2c_master_write_read_device(I2C_MASTER_NUM, INA219_ADDR, &reg,
1, raw, 2, pdMS_TO_TICKS(100));
 if (ret != ESP_OK) return ret;
 uint16_t power_raw = (raw[0] << 8) | raw [1];
 *power = power_raw * INA219_POWER_LSB;
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
 ina219_connected = ina219_found;

 uint8_t packet_type = PACKET_TYPE_I2C_MAP;

uint8_t length_bytes[2] = {
    (uint8_t)((used >> 8) & 0xFF),
    (uint8_t)(used & 0xFF)
};

tcp_send_data(
    &packet_type,
    sizeof(packet_type)
);

tcp_send_data(
    length_bytes,
    sizeof(length_bytes)
);

tcp_send_data(
    (const uint8_t *)map,
    used
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
 stm32_status = STM32_OFFLINE_RESPONSE;
 return stm32_status;
 }

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
 
 tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 if (tcp_sock < 0) {
 tcp_connected = false;
 return ESP_FAIL;
 }
 server_addr.sin_family = AF_INET;
 server_addr.sin_port = htons(TCP_SERVER_PORT);
 inet_pton(AF_INET, TCP_SERVER_IP, &server_addr.sin_addr);
 if (connect(tcp_sock, (struct sockaddr *)&server_addr,
 sizeof(server_addr)) < 0) { close(tcp_sock);
 tcp_sock = -1;
 return ESP_FAIL;
 }
 tcp_connected = true;
 return ESP_OK;
}
 static void tcp_send_data(const uint8_t *data, size_t len)
{
 size_t total_sent = 0;

 if (!tcp_connected || tcp_sock < 0) {
 return;
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
 return;
 }

 total_sent += (size_t)sent;
 }
}
static void tcp_send_status(void)
{
    status_packet_t status = {
        .packet_type = PACKET_TYPE_STATUS,
        .wifi = wifi_connected ? DEVICE_ONLINE : DEVICE_OFFLINE,
        .tcp = tcp_connected ? DEVICE_ONLINE : DEVICE_OFFLINE,
        .stm32 = (stm32_status == STM32_ONLINE_RESPONSE)
                 ? DEVICE_ONLINE
                 : DEVICE_OFFLINE,
        .ina219 = ina219_connected
                  ? DEVICE_ONLINE
                  : DEVICE_OFFLINE,
    };

    tcp_send_data(
        (const uint8_t *)&status,
        sizeof(status)
    );
}
//==============================================================
// INTERRUPT INITIALIZATION
//==============================================================
//gpio already configured, leaving placeholder for future expansion
//==============================================================
// TASK INITIALIZATION
//==============================================================
static esp_err_t spi_pull_stm32_buffer(uint8_t command)
{
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
 * Clock the real STM32 buffer into anomaly_buffer.
 * The name can be cleaned up later; do not rename it now.
 */
 spi_transaction_t payload_transaction = {
 .length = STM32_CAPTURE_BUFFER_SIZE * 8,
 .tx_buffer = NULL,
 .rx_buffer = anomaly_buffer,
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
 if (xSemaphoreTake(
 spi_mutex,
 pdMS_TO_TICKS(SPI_RESPONSE_TIMEOUT_MS)
 ) == pdTRUE) {
 ret = spi_pull_stm32_buffer(STM32_CMD_GET_LIVE);
 xSemaphoreGive(spi_mutex);
 } else {
 ESP_LOGW(
 "SPI",
 "Timeout waiting for SPI mutex"
 );
 }
 if (ret == ESP_OK) {
uint8_t packet_type = PACKET_TYPE_LIVE;
 if (xQueueSend(
 uplink_queue,
&packet_type,
pdMS_TO_TICKS(20)) != pdTRUE) {
 ESP_LOGW(
 "TCP",
"Uplink queue full, dropping message"
 ); }
 } else {
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
 ina219_connected = true;
 status_led_notify(STATUS_LED_EVENT_I2C);
 last_voltage = voltage;
 last_current = current;
 last_power = power;
} else {
 ina219_connected = false;
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
 if(xSemaphoreTake(
 spi_mutex,
pdMS_TO_TICKS(100)) == pdTRUE) {
 if(spi_pull_stm32_buffer(STM32_CMD_GET_ANOMALY) == ESP_OK) {
 uint8_t packet_type = PACKET_TYPE_ANOMALY;
xQueueSend(uplink_queue, &packet_type, 0);
 }
 xSemaphoreGive(spi_mutex);
 }
 }
 }
}
static uint8_t uplink_local_buffer[STM32_CAPTURE_BUFFER_SIZE]; // moved off the
// task stack: at 19200 bytes this would overflow wifi_uplink_task's
// 4096-byte stack if left as a local array
static void wifi_uplink_task(void *arg)
{
uint8_t packet_type;
 uint8_t *local_buffer = uplink_local_buffer;
 TickType_t last_status_report = xTaskGetTickCount();
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
 if (xQueueReceive(
 uplink_queue,
 &packet_type,
 pdMS_TO_TICKS(1000)) != pdTRUE) {
 ESP_LOGI("TCP", "No packets to send");
 continue;
 }
 if (xSemaphoreTake(
 spi_mutex,
 pdMS_TO_TICKS(SPI_RESPONSE_TIMEOUT_MS)) != pdTRUE) {
 ESP_LOGW("TCP", "Could not lock STM32 buffer");
 continue;
 }
 memcpy(
 local_buffer,
 anomaly_buffer,
 STM32_CAPTURE_BUFFER_SIZE
 );
 xSemaphoreGive(spi_mutex);
 ESP_LOGI(
 "TCP",
 "Packet ready; sending %u bytes",
 (unsigned)STM32_CAPTURE_BUFFER_SIZE
 );
 tcp_send_data(
 &packet_type,
 sizeof(packet_type)
);
 tcp_send_data(
 local_buffer,
 STM32_CAPTURE_BUFFER_SIZE
 ); if (tcp_connected) {
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
 i2c_master_init();
 ina219_calibrate();
 adc_hall_init();
 spi_stm32_init();
 anomaly_queue = xQueueCreate(4, sizeof(int));
 uplink_queue = xQueueCreate(4, sizeof(uint8_t));
 spi_mutex = xSemaphoreCreateMutex();
 status_led_init(STATUS_LED);
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