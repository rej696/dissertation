#ifndef STATUS_H_
#define STATUS_H_

typedef enum status {
    STATUS_OK,
    STATUS_ERROR,
    STATUS_BUFFER_OVERFLOW,
    STATUS_CBUF_FULL,
    STATUS_CBUF_EMPTY,
} status_t;

#endif /* STATUS_H_ */
