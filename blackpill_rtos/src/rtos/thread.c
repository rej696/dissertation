
#include "rtos/thread.h"
#include <stdint.h>
#include <stddef.h>

#include "hal/stm32f4_blackpill.h"

/* Interrupt Priority Registers */
#define NVIC_SHPR2_REG (*((volatile uint32_t *)0xE000ED1C))
#define NVIC_SHPR3_REV (*((volatile uint32_t *)0xE000ED20))

/* Pointer to current/next thread for scheduling */
rtos_thread_t *volatile rtos_current;
rtos_thread_t *volatile rtos_next;

rtos_thread_t *rtos_threads[32 + 1] = {NULL};
uint8_t rtos_thread_num = 0;
uint8_t rtos_thread_idx = 0;

void rtos_init(void)
{
    /* Set PendSV Interrupt to have lowest Priority
     * Equivilent of `NVIC_setPriority(PendSV_IRQn, 0xFFU)` */
    NVIC_SHPR3_REV |= (0xFFU << 16U);
}

void rtos_schedule(void)
{
    ++rtos_thread_idx;
    if (rtos_thread_idx >= rtos_thread_num) {
        rtos_thread_idx = 0U;
    }
    rtos_next = rtos_threads[rtos_thread_idx];

    if (rtos_next != rtos_current) {
        /* raise pendsv irq by setting "set pending" bit of interrupt and control state register (ICSR) */
        *(uint32_t volatile *)0xE000ED04 = (1U << 28U);
    }
}

void rtos_thread_create(
    rtos_thread_t *self,
    rtos_thread_handler_t handler,
    void *stack_base,
    uint32_t stack_size)
{
    /* get stack pointer and ensure aligned at the 8 byte boudary */
    uint32_t *sp = (uint32_t *)((((uint32_t)stack_base + stack_size) / 8U) * 8U);

    /* Setup stack according to Arm procedure call standard */
    *(--sp) = (1U << 24); /* xPSR, set 24'th bit for thumb mode (invalid if not set on cortex-m chips) */
    *(--sp) = (uint32_t)handler; /* PC (Program Counter) */
    *(--sp) = 0x0000000EU; /* LR (Link Register) */
    *(--sp) = 0x0000000CU; /* R12 */
    *(--sp) = 0x00000003U; /* R3 */
    *(--sp) = 0x00000002U; /* R2 */
    *(--sp) = 0x00000001U; /* R1 */
    *(--sp) = 0x00000000U; /* R0 */

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

#if 0 /* TODO implement assertion macros */
    assert(rtos_thread_head < sizeof(rtos_threads));
#endif

    rtos_threads[rtos_thread_num] = self;
    ++rtos_thread_num;
}

void rtos_run(void)
{
    rtos_on_startup();

    __disable_irq();
    rtos_schedule();
    __enable_irq();

    /* the following should never execute */
#if 0 /* TODO resolve assertions */
    assert(false);
#endif

}

void PendSV_Handler(void)
{
    asm volatile (
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
        "    bx    lr\n\t"
    );

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
