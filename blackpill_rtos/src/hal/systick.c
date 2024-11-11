#include "hal/systick.h"

#include "hal/pinutils.h"
#include "hal/rcc.h"
#include "hal/stm32f4_blackpill.h"
#include "hal/uart.h"
#include "rtos/thread.h"

#include <stdbool.h>
#include <stdint.h>

static volatile uint32_t s_ticks; /* tick counter */

void systick_init(uint32_t const ticks)
{
    if ((ticks - 1) > 0xffffff)
        return;  // Systick timer is 24 bit
    SYSTICK->LOAD = ticks - 1;
    SYSTICK->VAL = 0;
    SYSTICK->CTRL = BIT(0) | BIT(1) | BIT(2); /* Enable Systick */
    RCC->APB2ENR |= BIT(14);                  /* SYSCFG enable */
}

uint32_t systick_get_ticks(void) { return s_ticks; }

bool systick_timer_expired(uint32_t *const timer, uint32_t const period, uint32_t const now)
{
    /* reset timer if wrapped */
    if ((now + period) < (*timer)) {
        *timer = 0;
    }
    /* set expiration if first poll */
    if (*timer == 0) {
        *timer = now + period;
    }
    /* Return if not expired yet */
    if (*timer > now) {
        return false;
    }
    /* Set the next expiration time */
    if ((now - *timer) > period) {
        *timer = now + period;
    } else {
        *timer = *timer + period;
    }
    return true;
}

void rtos_on_startup(void)
{
    /* tick every ms */
    systick_init(CLOCK_FREQ / 1000);
}

void rtos_on_idle(void)
{
#if 0
    /* Wait for interrupt (not sure if this works with unicorn */
    __WFI();
#else
    (void)0;
#endif
}

void SysTick_Handler(void)
{
    s_ticks++;
    rtos_tick();

    disable_irq();
    rtos_schedule();
    enable_irq();
}
