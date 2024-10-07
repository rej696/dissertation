#ifndef RTOS_THREAD_H
#define RTOS_THREAD_H

#include <stdint.h>

typedef struct {
    void *sp; /* Stack Pointer */
    /* ... */
} rtos_thread_t;

typedef void (*rtos_thread_handler_t)(void);

void rtos_init(void);

void rtos_on_startup(void);

/* This function requires interrupts be disabled */
void rtos_schedule(void);

void rtos_thread_create(
    rtos_thread_t *self,
    rtos_thread_handler_t handler,
    void *stack,
    uint32_t stack_size);

void rtos_run(void);

#endif /* RTOS_THREAD_H */
