/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include <stddef.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "spinlock.h"

static spinlock_t g_thread_list_lock = INIT_SPINLOCK_UNLOCKED;
DEFINE_LISTP(pal_handle_thread);
static LISTP_TYPE(pal_handle_thread) g_thread_list = LISTP_INIT;

struct thread_param {
    int (*callback)(void*);
    void* param;
};
struct thread_meta_map_t {
    void* thread_meta;
    void* tcs;
    bool ready;     //set by parent thread
    bool running;  //set by child thread
};

#define THREAD_META_SIZE (SSA_FRAME_NUM * SSA_FRAME_SIZE + PAGE_SIZE + PAGE_SIZE + ENCLAVE_STACK_SIZE + ENCLAVE_SIG_STACK_SIZE)


static struct thread_meta_map_t* g_thread_meta_map = NULL;
static size_t g_thread_meta_num  = 0;
static size_t g_thread_meta_size = 0;
static spinlock_t g_thread_meta_lock = INIT_SPINLOCK_UNLOCKED;

#define CP_MMAP_FLAGS    (MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL)



    /* Layout for the new thread meta looks like this
     *
     * high        +--> +-------------------+
     *                  |  SSA              | SSA_FRAME_NUM * SSA_FRAME_SIZE
     *         SSA +--> +-------------------+
     *                  |  TCS              | PAGE_SIZE
     *         TCS +--> +-------------------+
     *                  |  TCB              | PAGE_SIZE
     *         TCB +--> +-------------------+
     *                  |  stack            | THREAD_STACK_SIZE
     *       stack +--> +-------------------+
     *                  |  sig_stack        | THREAD_STACK_SIZE
     *   sig_stack +--> +-------------------+
     *
     */

typedef void (*entry_t)(void);
extern entry_t  enclave_entry;

extern uintptr_t g_enclave_base;

static int init_thread_meta(void* data) {
    uint64_t sig_stack = (uint64_t)data;
    uint64_t stack = sig_stack + ENCLAVE_SIG_STACK_SIZE;
    struct pal_enclave_tcb* gs = (struct pal_enclave_tcb*)(stack + ENCLAVE_STACK_SIZE);
    sgx_arch_tcs_t* tcs = (void*)gs + PAGE_SIZE;
    void* ssa = (void*)tcs + PAGE_SIZE;

    assert(sizeof(*gs) <= PAGE_SIZE);
    gs->common.self = (PAL_TCB*)gs;
    gs->common.stack_protector_canary = STACK_PROTECTOR_CANARY_DEFAULT;
    gs->enclave_size = GET_ENCLAVE_TCB(enclave_size);
    gs->tcs_offset = (uint64_t)tcs - g_enclave_base;
    gs->initial_stack_addr = stack + ENCLAVE_STACK_SIZE;
    gs->sig_stack_low = sig_stack;
    gs->sig_stack_high = sig_stack + ENCLAVE_SIG_STACK_SIZE;
    gs->ssa = ssa;
    gs->gpr = ssa + SSA_FRAME_SIZE - sizeof(sgx_pal_gpr_t);
    gs->manifest_size = GET_ENCLAVE_TCB(manifest_size);
    gs->heap_min = GET_ENCLAVE_TCB(heap_min);
    gs->heap_max = GET_ENCLAVE_TCB(heap_max);
    gs->thread = NULL;

    // .ossa, .oentry, .ofs_base and .ogs_base are offsets from enclave base, not VAs.
    tcs->ossa      = (uint64_t)ssa - g_enclave_base;
    tcs->nssa      = SSA_FRAME_NUM;
    tcs->oentry    = (uint64_t)&enclave_entry - g_enclave_base;
    tcs->ofs_base  = 0;
    tcs->ogs_base  = (uint64_t)gs - g_enclave_base;
    tcs->ofs_limit = 0xfff;
    tcs->ogs_limit = 0xfff;

    return 0;
}

static int get_dynamic_tcs(void** out_addr) {
    int ret;
    spinlock_lock(&g_thread_meta_lock);
    for (size_t i = 0; i < g_thread_meta_num; i++) {
        if (!g_thread_meta_map[i].running && g_thread_meta_map[i].ready) {
            /* found allocated and unused stack -- use it */
            //g_thread_meta_map[i].running = true;
            //*out_addr = g_thread_meta_map[i].thread_meta;
            *out_addr = NULL;
            ret = 0;
            log_error("get_dynamic_tcs() found free TCS %ld: %p.\n", i, g_thread_meta_map[i].tcs);
            goto out;
        }
    }

    if (g_thread_meta_num == g_thread_meta_size) {
        /* realloc g_thread_meta_map to accommodate more objects (includes the very first time) */
        g_thread_meta_size += 8;
        struct thread_meta_map_t* tmp = malloc(g_thread_meta_size * sizeof(*tmp));
        if (!tmp) {
            ret = -1;
            goto out;
        }

        memcpy(tmp, g_thread_meta_map, g_thread_meta_num * sizeof(*tmp));
        free(g_thread_meta_map);
        g_thread_meta_map = tmp;
    }

    void* addr;
    ret = pal_internal_memory_alloc(THREAD_META_SIZE, &addr);
    if (ret)
        goto out;


    void * tcs = addr + ENCLAVE_SIG_STACK_SIZE + ENCLAVE_STACK_SIZE + PAGE_SIZE;

    g_thread_meta_map[g_thread_meta_num].thread_meta = addr;
    g_thread_meta_map[g_thread_meta_num].tcs = tcs;
    g_thread_meta_map[g_thread_meta_num].ready  = false;
    g_thread_meta_map[g_thread_meta_num].running  = false;
    g_thread_meta_num++;
    *out_addr = tcs;
    
    ret = init_thread_meta(addr);
        
    spinlock_unlock(&g_thread_meta_lock);
    
            log_error("get_dynamic_tcs() new TCS %ld: %p.\n", g_thread_meta_num, tcs);
    ret = sgx_edmm_convert_tcs_pages((uint64_t)tcs, 1);
    return ret;

out:
    spinlock_unlock(&g_thread_meta_lock);
    return ret;
}

/* Initialization wrapper of a newly-created thread. This function finds a newly-created thread in
 * g_thread_list, initializes its TCB/TLS, and jumps into the callback-to-run. Gramine uses GCC's
 * stack protector that looks for a canary at gs:[0x8], but this function starts with a default
 * canary and then updates it to a random one, so we disable stack protector here. */
__attribute_no_stack_protector
void pal_start_thread(void) {
    struct pal_handle_thread* new_thread = NULL;
    struct pal_handle_thread* tmp;

    spinlock_lock(&g_thread_list_lock);
    //TODO set new_thread->tcs from TCB, 
    LISTP_FOR_EACH_ENTRY(tmp, &g_thread_list, list)
        if (!tmp->tcs) {
            new_thread = tmp;
            __atomic_store_n(&new_thread->tcs,
                             (void*)(g_enclave_base + GET_ENCLAVE_TCB(tcs_offset)),
                             __ATOMIC_RELEASE);
            break;
        }
    spinlock_unlock(&g_thread_list_lock);

    if (!new_thread)
        return;

    spinlock_lock(&g_thread_meta_lock);
    for (size_t i = 0; i < g_thread_meta_num; i++) {
        if (g_thread_meta_map[i].tcs == new_thread->tcs) {
            g_thread_meta_map[i].running = true;
            
            log_error("TCS page: %p, g_thread_meta_map[%lu].running = true\n", g_thread_meta_map[i].tcs, i);
            break;
        }
    }
    spinlock_unlock(&g_thread_meta_lock);

    struct thread_param* thread_param = (struct thread_param*)new_thread->param;
    int (*callback)(void*) = thread_param->callback;
    const void* param = thread_param->param;
    free(thread_param);
    new_thread->param = NULL;

    SET_ENCLAVE_TCB(thread, new_thread);
    SET_ENCLAVE_TCB(ready_for_exceptions, 1UL);

    /* each newly-created thread (including the first thread) has its own random stack canary */
    uint64_t stack_protector_canary;
    int ret = _PalRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_PalRandomBitsRead() failed: %s", pal_strerror(ret));
        _PalProcessExit(1);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);
    PAL_TCB* pal_tcb = pal_get_tcb();
    memset(&pal_tcb->libos_tcb, 0, sizeof(pal_tcb->libos_tcb));
    callback((void*)param);
    _PalThreadExit(/*clear_child_tid=*/NULL);
    /* UNREACHABLE */
}

int _PalThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), void* param) {
    int ret;
    PAL_HANDLE new_thread = calloc(1, HANDLE_SIZE(thread));
    if (!new_thread)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(new_thread, PAL_TYPE_THREAD);

    new_thread->thread.tcs = NULL;

    //Set a dynamic tcs here, in order to pass it to tcb->tcs in pal_thread_init
    void* tcs = NULL;

    if (g_pal_linuxsgx_state.edmm_enabled) {
        ret = get_dynamic_tcs(&tcs);
        if (ret < 0) {
            goto out_err;
        }
    }
    INIT_LIST_HEAD(&new_thread->thread, list);
    struct thread_param* thread_param = malloc(sizeof(struct thread_param));
    if (!thread_param) {
        ret = -PAL_ERROR_NOMEM;
        goto out_err;
    }
    thread_param->callback = callback;
    thread_param->param    = param;
    new_thread->thread.param = (void*)thread_param;

    spinlock_lock(&g_thread_list_lock);
    LISTP_ADD_TAIL(&new_thread->thread, &g_thread_list, list);
    spinlock_unlock(&g_thread_list_lock);

    ret = ocall_clone_thread(tcs);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        spinlock_lock(&g_thread_list_lock);
        LISTP_DEL(&new_thread->thread, &g_thread_list, list);
        spinlock_unlock(&g_thread_list_lock);
        goto out_err;
    }

    if (tcs) {
        spinlock_lock(&g_thread_meta_lock);
        for (size_t i = 0; i < g_thread_meta_num; i++) {
            if (g_thread_meta_map[i].tcs == tcs) {
                g_thread_meta_map[i].ready = true;
                break;
            }
        }
        spinlock_unlock(&g_thread_meta_lock);
    }

    /* There can be subtle race between the parent and child so hold the parent until child updates
     * its tcs. */
    while ((__atomic_load_n(&new_thread->thread.tcs, __ATOMIC_ACQUIRE)) == 0)
        CPU_RELAX();

    *handle = new_thread;
    return 0;
out_err:
    free(thread_param);
    free(new_thread);
    return ret;
}

/* PAL call PalThreadYieldExecution. Yield the execution of the current thread. */
void _PalThreadYieldExecution(void) {
    ocall_sched_yield();
}

/* _PalThreadExit for internal use: Thread exiting */
noreturn void _PalThreadExit(int* clear_child_tid) {
    struct pal_handle_thread* exiting_thread = GET_ENCLAVE_TCB(thread);

    /* thread is ready to exit, must inform LibOS by erasing clear_child_tid;
     * note that we don't do it now (because this thread still occupies SGX
     * TCS slot) but during handle_thread_reset in assembly code */
    SET_ENCLAVE_TCB(clear_child_tid, clear_child_tid);
    static_assert(sizeof(*clear_child_tid) == 4, "unexpected clear_child_tid size");
    if (exiting_thread->tcs) {
        spinlock_lock(&g_thread_meta_lock);
        for (size_t i = 0; i < g_thread_meta_num; i++) {
            if (g_thread_meta_map[i].tcs == exiting_thread->tcs) {
                g_thread_meta_map[i].running = false;
                
            log_error("TCS page: %p, g_thread_meta_map[%lu].running = false\n", g_thread_meta_map[i].tcs, i);
                break;
            }
        }
        spinlock_unlock(&g_thread_meta_lock);
    }
    /* main thread is not part of the g_thread_list */
    if (exiting_thread != &g_pal_public_state.first_thread->thread) {
        spinlock_lock(&g_thread_list_lock);
        LISTP_DEL(exiting_thread, &g_thread_list, list);
        spinlock_unlock(&g_thread_list_lock);
    }

    ocall_exit(0, /*is_exitgroup=*/false);
}

int _PalThreadResume(PAL_HANDLE thread_handle) {
    int ret = ocall_resume_thread(thread_handle->thread.tcs);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

int _PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int ret = ocall_sched_setaffinity(thread->thread.tcs, cpu_mask, cpu_mask_len);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

int _PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int ret = ocall_sched_getaffinity(thread->thread.tcs, cpu_mask, cpu_mask_len);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    /* Verify that the CPU affinity mask contains only online cores. */
    size_t threads_count = g_pal_public_state.topo_info.threads_cnt;
    for (size_t i = 0; i < cpu_mask_len; i++) {
        for (size_t j = 0; j < BITS_IN_TYPE(__typeof__(*cpu_mask)); j++) {
            size_t thread_idx = i * BITS_IN_TYPE(__typeof__(*cpu_mask)) + j;
            if (thread_idx >= threads_count) {
                break;
            }
            if ((cpu_mask[i] & (1ul << j))
                    && !g_pal_public_state.topo_info.threads[thread_idx].is_online) {
                return -PAL_ERROR_INVAL;
            }
        }
    }

    return 0;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
