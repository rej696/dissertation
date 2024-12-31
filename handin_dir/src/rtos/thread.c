
#include "rtos/thread.h"

#include "hal/stm32f4_blackpill.h"
#include "utils/dbc_assert.h"

#include <stddef.h>
#include <stdint.h>

/* Interrupt Priority Registers */
#define NVIC_SHPR2_REG (*((volatile uint32_t *)0xE000ED1C))
#define NVIC_SHPR3_REV (*((volatile uint32_t *)0xE000ED20))

/* Pointer to current/next thread for scheduling */
rtos_thread_t *volatile rtos_current;
rtos_thread_t *volatile rtos_next;

rtos_thread_t *rtos_threads[32 + 1] = {NULL};
uint8_t rtos_thread_num = 0;
uint8_t rtos_thread_idx = 0;
uint32_t rtos_thread_ready_mask = 0;

rtos_thread_t idle_thread = {0};
void idle_thread_handler()
{
    for (;;) {
        rtos_on_idle();
    }
}

void rtos_init(void *const idle_thread_stack, uint32_t const idle_thread_stack_size)
{
    /* Set PendSV Interrupt to have lowest Priority
     * Equivilent of `NVIC_setPriority(PendSV_IRQn, 0xFFU)` */
    NVIC_SHPR3_REV |= (0xFFU << 16U);

    /* create idle thread */
    rtos_thread_create(
        &idle_thread,
        idle_thread_handler,
        idle_thread_stack,
        idle_thread_stack_size);
}

void rtos_schedule(void)
{
    /* No threads are ready to run, so set to Idle thread */
    if (rtos_thread_ready_mask == 0U) {
        rtos_thread_idx = 0U;
    } else {
        /* Find next thread to run */
        do {
            ++rtos_thread_idx;
            if (rtos_thread_idx == rtos_thread_num) {
                rtos_thread_idx = 1U;
            }
        } while ((rtos_thread_ready_mask & (1U << (rtos_thread_idx - 1U))) == 0U);
    }
    rtos_thread_t *const next = rtos_threads[rtos_thread_idx];

    if (next != rtos_current) {
        /* raise pendsv irq by setting "set pending" bit of interrupt and control state register
         * (ICSR) */
        rtos_next = next;
        *(volatile uint32_t *)0xE000ED04 = (1U << 28U);
    }
}
void rtos_run(void)
{
    rtos_on_startup();

    disable_irq();
    rtos_schedule();
    enable_irq();

    /* the following should never execute */
    DBC_ERROR();
}

void rtos_tick(void)
{
    for (uint8_t n = 1U; n < rtos_thread_num; ++n) {
        if (rtos_threads[n]->timeout != 0U) {
            --rtos_threads[n]->timeout;
            if (rtos_threads[n]->timeout == 0U) {
                rtos_thread_ready_mask |= (1U << (n - 1U));
            }
        }
    }
}

void rtos_delay(uint32_t ticks)
{
    disable_irq();

    /* never call rtos_delay from the idle thread */
    DBC_REQUIRE(rtos_current != rtos_threads[0]);

    rtos_current->timeout = ticks;
    rtos_thread_ready_mask &= ~(1U << (rtos_thread_idx - 1));
    rtos_schedule();

    enable_irq();
}

void rtos_thread_create(
    rtos_thread_t *const self,
    rtos_thread_handler_t const handler,
    void *const stack_base,
    uint32_t const stack_size)
{
    /* get stack pointer and ensure aligned at the 8 byte boudary */
    uint32_t *sp = (uint32_t *)((((uint32_t)stack_base + stack_size) / 8U) * 8U);

    /* Setup stack according to Arm procedure call standard */
    *(--sp) = (1U << 24); /* xPSR, set 24'th bit for thumb mode (invalid if not set on cortex-m
                             chips) */
    *(--sp) = (uint32_t)handler; /* PC (Program Counter) */
    *(--sp) = 0x0000000EU;       /* LR (Link Register) */
    *(--sp) = 0x0000000CU;       /* R12 */
    *(--sp) = 0x00000003U;       /* R3 */
    *(--sp) = 0x00000002U;       /* R2 */
    *(--sp) = 0x00000001U;       /* R1 */
    *(--sp) = 0x00000000U;       /* R0 */

    /* Initialise Additional Registers on Stack */
    *(--sp) = 0x0000000BU; /* R11 */
    *(--sp) = 0x0000000AU; /* R10 */
    *(--sp) = 0x00000009U; /* R9 */
    *(--sp) = 0x00000008U; /* R8 */
    *(--sp) = 0x00000007U; /* R7 */
    *(--sp) = 0x00000006U; /* R6 */
    *(--sp) = 0x00000005U; /* R5 */
    *(--sp) = 0x00000004U; /* R4 */

    /* Save current stack pointer into self */
    self->sp = sp;

    /* Get aligned bottom of stack */
    uint32_t *stack_limit = (uint32_t *)(((((uint32_t)stack_base - 1U) / 8U) + 1U) * 8U);

    /* pre-fill rest of stack with stack paint */
    for (sp = (sp - 1U); sp >= stack_limit; --sp) {
        *sp = 0xBABECAFE;
    }

    DBC_ASSERT(rtos_thread_num < (sizeof(rtos_threads) / sizeof(rtos_threads[0U])));

    /* Register thread with OS */
    rtos_threads[rtos_thread_num] = self;
    /* Mark thread as ready to run */
    if (rtos_thread_num > 0U) {
        rtos_thread_ready_mask |= (1U << (rtos_thread_num - 1U));
    }
    ++rtos_thread_num;
}

void PendSV_Handler(void)
{
    asm volatile(
        /* disable interrupts */
        "    cpsid i\n\t"
        /* if {rtos_current != (rtos_thread_t *)0U) { */
        "    ldr   r1,=rtos_current\n\t"
        "    ldr   r1,[r1,#0]\n\t"
        "    cbz   r1,PendSV_restore\n\t"
        /* push r4-r11 onto the stack */
        "    push  {r4-r11}\n\t"
        "    ldr   r1,=rtos_current\n\t"
        "    ldr   r1,[r1,#0]\n\t"
        /* rtos_current->sp = sp; */
        "    str   sp,[r1,#0]\n\t"
        /* } */

        "PendSV_restore:\n\t"
        /* sp = rtos_next->sp; */
        "    ldr   r1,=rtos_next\n\t"
        "    ldr   r1,[r1,#0]\n\t"
        "    ldr   sp,[r1,#0]\n\t"
        /* rtos_current = rtos_next; */
        "    ldr   r1,=rtos_next\n\t"
        "    ldr   r1,[r1,#0]\n\t"
        "    ldr   r2,=rtos_current\n\t"
        "    str   r1,[r2,#0]\n\t"
        /* pop registers r4-r11 */
        "    pop   {r4-r11}\n\t"
        "    cpsie i\n\t"
        "    bx    lr\n\t");

#if 0
    void *sp = NULL;

    __enable_irq();
    if (rtos_thread_current != (rtos_thread_t *)0U) {
        /* Push registers r4-r11 onto the stack */
        rtos_thread_current->sp = sp;
    }
    sp = rtos_thread_next->sp;
    rtos_thread_current = rtos_thread_next;
    /* Pop registers r4-r11 from stack */
    __disable_irq();
#endif
}
