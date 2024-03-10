#ifndef SYSTICK_H_
#define SYSTICK_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct systick {
    volatile uint32_t CTRL;
    volatile uint32_t LOAD;
    volatile uint32_t VAL;
    volatile uint32_t CALIB;
} systick_t;

#define SYSTICK ((systick_t *) 0xe000e010)
#define CLOCK_FREQ (16000000) /* HSI (internal) clock for black pill is 16MHz */

void systick_init(uint32_t const ticks);
uint32_t systick_get_ticks(void);
bool systick_timer_expired(uint32_t *const timer, uint32_t const period, uint32_t const now);
void SysTick_Handler(void);

#endif /* SYSTICK_H_ */
