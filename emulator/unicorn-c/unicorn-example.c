#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>

#define X86_CODE32 ("\x41\x4a") /* INC exc; DEC edx */

#define ADDRESS (0x10000000)

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    printf("Emulate i386 code\n");

    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return EXIT_FAILURE;
    }

    /* map 4KB at address with rwx permissions */
    uc_mem_map(uc, ADDRESS, 0x1000, UC_PROT_ALL);

    /* write code to mapped memory */
    err = uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);
    if (err != UC_ERR_OK) {
        printf("Failed to write emulation code to memory: %u\n", err);
        return EXIT_FAILURE;
    }

    /* init registers */
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    /* emulate code in infinite time with unlimited restrictions */
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
        return EXIT_FAILURE;
    }

    /* print the results */
    printf("Emulation Complete:\n");
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf("\tECX=0x%x\n", r_ecx);
    printf("\tEDX=0x%x\n", r_edx);

    uc_close(uc);

    return EXIT_SUCCESS;
}
