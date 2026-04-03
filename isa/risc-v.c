/*
 * RVX (RISC-V eXtended) - Hybrid ISA + Double Ratchet
 *
 * Adds double ratchet encryption support for secure channels.
 *
 * This file extends RVX with:
 * - Ratchet key state
 * - DH ratchet operations
 * - Symmetric key encryption/decryption
 * - ISA instructions for RVX double ratchet
 */

#ifndef RVX_ISA_H
#define RVX_ISA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>  // for memcpy

#define RVX_GPR_COUNT 32
#define RVX_VEC_COUNT 32

/* =========================
 * REGISTER DEFINITIONS
 * ========================= */

typedef struct {
    uint64_t gpr[RVX_GPR_COUNT];   // General-purpose registers
    double   fpr[RVX_GPR_COUNT];   // Floating-point registers
    uint8_t  vreg[RVX_VEC_COUNT][64];  // Vector registers
    uint64_t pc;   // Program counter
    uint64_t sp;   // Stack pointer
    uint64_t flags;
} rvx_cpu_t;

/* =========================
 * MEMORY MODEL
 * ========================= */
typedef enum { RVX_MEM_STRONG, RVX_MEM_WEAK } rvx_mem_model_t;

/* =========================
 * OPCODE DEFINITIONS
 * ========================= */

typedef enum {

    /* --- Base Instructions --- */
    RVX_NOP,
    RVX_MOV, RVX_LOAD, RVX_STORE, RVX_LMUL, RVX_SMUL,
    RVX_ADD, RVX_SUB, RVX_MUL, RVX_DIV, RVX_FMA,
    RVX_AND, RVX_OR, RVX_XOR, RVX_NOT,
    RVX_CLZ, RVX_POPCNT, RVX_ROTATE,
    RVX_JMP, RVX_BRANCH_EQ, RVX_BRANCH_NE, RVX_CALL, RVX_RET,
    RVX_PUSH, RVX_POP,
    RVX_VADD, RVX_VMUL, RVX_VCMP, RVX_VSHUFFLE,
    RVX_FADD, RVX_FSUB, RVX_FMUL, RVX_FDIV,
    RVX_ATOMIC_ADD, RVX_CAS,
    RVX_FENCE, RVX_DMB,
    RVX_SYSCALL, RVX_HALT, RVX_WFI,
    RVX_AES_ENC, RVX_AES_DEC, RVX_SHA256,
    RVX_MEMCPY, RVX_MEMSET, RVX_MEMCMP,
    RVX_RDTIME, RVX_RDPMC,
    RVX_LOAD_ADD_STORE, RVX_PREFETCH, RVX_CACHELOCK,
    RVX_MATMUL,

    /* --- Double Ratchet Instructions --- */
    RVX_DR_INIT,       // Initialize ratchet state
    RVX_DR_DHRATCHET,  // Perform DH ratchet (public key exchange)
    RVX_DR_ENCRYPT,    // Symmetric ratchet encryption
    RVX_DR_DECRYPT,    // Symmetric ratchet decryption
    RVX_DR_ADVANCE     // Advance ratchet forward

} rvx_opcode_t;

/* =========================
 * INSTRUCTION FORMAT
 * ========================= */
typedef struct {
    rvx_opcode_t opcode;
    uint8_t rd;   // destination register
    uint8_t rs1;  // source 1
    uint8_t rs2;  // source 2
    uint64_t imm; // immediate / memory address
} rvx_instr_t;

/* =========================
 * DOUBLE RATCHET STATE
 * ========================= */
#define RVX_DR_KEY_LEN 32   // 256-bit symmetric key
#define RVX_DR_PUBKEY_LEN 32

typedef struct {
    uint8_t root_key[RVX_DR_KEY_LEN];   // Root key
    uint8_t send_chain_key[RVX_DR_KEY_LEN];
    uint8_t recv_chain_key[RVX_DR_KEY_LEN];
    uint8_t dh_private[RVX_DR_KEY_LEN];
    uint8_t dh_public[RVX_DR_PUBKEY_LEN];
    uint64_t send_counter;
    uint64_t recv_counter;
} rvx_dr_state_t;

/* =========================
 * CPU EXTENDED STRUCTURE
 * ========================= */
typedef struct {
    rvx_cpu_t cpu;
    rvx_dr_state_t dr;
} rvx_extended_cpu_t;

/* =========================
 * EXECUTION FUNCTION
 * ========================= */
void rvx_execute(rvx_extended_cpu_t *cpu, rvx_instr_t instr);

/* =========================
 * HELPER MACROS
 * ========================= */
#define RVX_REG(cpu, r) ((cpu)->cpu.gpr[(r)])

/* =========================
 * EXAMPLE EXECUTOR IMPLEMENTATION
 * ========================= */
static inline void rvx_execute(rvx_extended_cpu_t *cpu, rvx_instr_t instr) {

    switch(instr.opcode) {

        /* --- Arithmetic Example --- */
        case RVX_ADD:
            RVX_REG(cpu, instr.rd) = RVX_REG(cpu, instr.rs1) + RVX_REG(cpu, instr.rs2);
            break;

        case RVX_SUB:
            RVX_REG(cpu, instr.rd) = RVX_REG(cpu, instr.rs1) - RVX_REG(cpu, instr.rs2);
            break;

        /* --- Memory Example --- */
        case RVX_LOAD:
            RVX_REG(cpu, instr.rd) = *((uint64_t*)(instr.imm));
            break;

        case RVX_STORE:
            *((uint64_t*)(instr.imm)) = RVX_REG(cpu, instr.rs1);
            break;

        /* --- Double Ratchet Examples (high-level placeholder) --- */
        case RVX_DR_INIT:
            memset(cpu->dr.root_key, 0, RVX_DR_KEY_LEN);
            memset(cpu->dr.send_chain_key, 0, RVX_DR_KEY_LEN);
            memset(cpu->dr.recv_chain_key, 0, RVX_DR_KEY_LEN);
            cpu->dr.send_counter = 0;
            cpu->dr.recv_counter = 0;
            break;

        case RVX_DR_DHRATCHET:
            /* Perform DH ratchet key exchange */
            /* Placeholder: call crypto library here */
            break;

        case RVX_DR_ENCRYPT:
            /* Encrypt register or memory using current send_chain_key */
            /* Placeholder: call AES-GCM or ChaCha20-Poly1305 here */
            cpu->dr.send_counter++;
            break;

        case RVX_DR_DECRYPT:
            /* Decrypt register or memory using current recv_chain_key */
            cpu->dr.recv_counter++;
            break;

        case RVX_DR_ADVANCE:
            /* Advance ratchet to next key */
            /* Placeholder for HKDF-based derivation */
            break;

        case RVX_HALT:
            while(1) {}
            break;

        default:
            break;
    }

    cpu->cpu.pc += sizeof(rvx_instr_t);
}

#endif