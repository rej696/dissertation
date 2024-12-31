#ifndef RTOS_THREAD_H
#define RTOS_THREAD_H

#include <stdint.h>

typedef struct {
    void *sp; /* Stack Pointer */
    uint32_t timeout;
    /* ... */
} rtos_thread_t;

typedef void (*rtos_thread_handler_t)(void);

/* idle thread callback (define in application) */
void rtos_on_idle(void);

/* rtos startup callback (define in application) */
void rtos_on_startup(void);

/* Initialise the rtos and idle thread */
void rtos_init(void *const idle_thread_stack, uint32_t const idle_thread_stack_size);

/* This function requires interrupts be disabled */
void rtos_schedule(void);

/* Run the rtos */
void rtos_run(void);

/* Process thread timeouts */
void rtos_tick(void);

/* Blocking delay */
void rtos_delay(uint32_t ticks);

/* Register a thread with the rtos */
void rtos_thread_create(
    rtos_thread_t *const self,
    rtos_thread_handler_t const handler,
    void *const stack,
    uint32_t const stack_size);

#endif /* RTOS_THREAD_H */
