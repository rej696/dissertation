#ifndef STM32F4_BLACKPILL_H
#define STM32F4_BLACKPILL_H

/* TODO These would be defined in the stm32f4xx.h header file e.g.
 * https://github.com/wangyeee/STM32F4-FreeRTOS/blob/master/Libraries/CMSIS/Device/ST/STM32F4xx/Include/stm32f4xx.h
 * Consider including this header */
/* The blackpill is an stm32F411xC/xE */
#define STM32F411xE
#define __CM4_REV 0x0001
#define __FPU_PRESENT 1
#define __MPU_PRESENT 1
#define __NVIC_PRIO_BITS 4U
typedef enum {
/* -------------------  Cortex-M4 Processor Exceptions Numbers  ------------------- */
  Reset_IRQn                    = -15,              /*!<   1  Reset Vector, invoked on Power up and warm reset                 */
  NonMaskableInt_IRQn           = -14,              /*!<   2  Non maskable Interrupt, cannot be stopped or preempted           */
  HardFault_IRQn                = -13,              /*!<   3  Hard Fault, all classes of Fault                                 */
  MemoryManagement_IRQn         = -12,              /*!<   4  Memory Management, MPU mismatch, including Access Violation
                                                         and No Match                                                          */
  BusFault_IRQn                 = -11,              /*!<   5  Bus Fault, Pre-Fetch-, Memory Access Fault, other address/memory
                                                         related Fault                                                         */
  UsageFault_IRQn               = -10,              /*!<   6  Usage Fault, i.e. Undef Instruction, Illegal State Transition    */
  SVCall_IRQn                   =  -5,              /*!<  11  System Service Call via SVC instruction                          */
  DebugMonitor_IRQn             =  -4,              /*!<  12  Debug Monitor                                                    */
  PendSV_IRQn                   =  -2,              /*!<  14  Pendable request for system service                              */
  SysTick_IRQn                  =  -1,              /*!<  15  System Tick Timer                                                */
/* -------------------  TODO Specific Interrupt Numbers  ------------------ */

/* Selected STM32F411xE IRQn values */
  USART1_IRQn = 37,
  USART2_IRQn = 38,
  USART6_IRQn = 71,

} IRQn_Type;

#include "core_cm4.h"

static inline void enable_irq(void) {
    asm volatile ("cpsie i\n\t");
}

static inline void disable_irq(void) {
    asm volatile ("cpsid i\n\t");
}

#endif /* STM32F4_BLACKPILL_H */
