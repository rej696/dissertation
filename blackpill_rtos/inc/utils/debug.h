#ifndef DEBUG_H_
#define DEBUG_H_

#include "hal/uart.h"
#include "utils/status.h"

/* Stringification macros for __LINE__ */
#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)

/* Debug Macros for printing file and line */
#define DEBUG(msg, status) debug_status(__FILE__ ":" STRINGIZE(__LINE__) ": " msg, (status))
#define DEBUG_INT(msg, value) debug_int(__FILE__ ":" STRINGIZE(__LINE__) ": " msg, (value))
#define DEBUG_HEX(msg, size, buf) debug_hex(__FILE__ ":" STRINGIZE(__LINE__) ": " msg, (size), (buf))
#define DEBUG_STR(msg) debug_str(__FILE__ ":" STRINGIZE(__LINE__) ": " msg)

/* Setup the debug log with a uart peripheral and baud rate */
void debug_init(uart_id_t const uart_id, uint32_t const baud);

/* Print a (null terminated) message with a status code (displayed in hex), Appending newline characters */
void debug_status(char const *const msg, status_t status);

/* Print a (null terminated) message, appending newline characters */
void debug_str(char const *const msg);

/* Print an array of bytes as space seperated hex characters */
void debug_hex(char const *const msg, uint32_t const size, uint8_t const buf[size]);

/* Print an integer value (32-bit) */
void debug_int(char const *const msg, uint32_t value);

#endif /* DEBUG_H_ */
