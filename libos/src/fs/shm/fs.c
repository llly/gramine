/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Li Xun <xun.li@intel.com>
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'shm' filesystem. The shm files `mmap` to shared
   memory range, and accessible by its child, another Gramine or native process. 
 */

#include <errno.h>

#include "libos_flags_conv.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_lock.h"
#include "libos_vma.h"
#include "perm.h"
#include "stat.h"
#include "toml_utils.h"

#define HOST_PERM(perm) ((perm) | PERM_r________)

static int shm_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(params);
    __UNUSED(mount_data);
    return 0;
}


static int shm_mmap(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                       uint64_t offset) {
    assert(hdl->type == TYPE_SHM);
    assert(addr);

    pal_prot_flags_t pal_prot = LINUX_PROT_TO_PAL(prot, flags);

    if (flags & MAP_ANONYMOUS)
        return -EINVAL;

    void* actual_addr = addr;
    int ret = PalStreamMap(hdl->pal_handle, &actual_addr, pal_prot, offset, size);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    assert(actual_addr == addr);
    return 0;
}

static int shm_truncate(struct libos_handle* hdl, file_off_t size) {
    assert(hdl->type == TYPE_SHM);

    int ret;

    lock(&hdl->inode->lock);
    ret = PalStreamSetLength(hdl->pal_handle, size);
    if (ret == 0) {
        hdl->inode->size = size;
    } else {
        ret = pal_to_unix_errno(ret);
    }
    unlock(&hdl->inode->lock);
    return ret;
}

/* Open a PAL handle, and associate it with a LibOS handle (if provided). */
static int shm_do_open(struct libos_handle* hdl, struct libos_dentry* dent, mode_t type,
                          int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));

    int ret;

    char* uri;
    ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    PAL_HANDLE palhdl;
    enum pal_access access = LINUX_OPEN_FLAGS_TO_PAL_ACCESS(flags);
    enum pal_create_mode create = LINUX_OPEN_FLAGS_TO_PAL_CREATE(flags);
    pal_stream_options_t options = LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(flags) | PAL_OPTION_PASSTHROUGH;
    mode_t host_perm = HOST_PERM(perm);
    ret = PalStreamOpen(uri, access, host_perm, create, options, &palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    if (hdl) {
        hdl->uri = uri;
        uri = NULL;

        hdl->type = TYPE_SHM;
        hdl->pos = 0;
        hdl->pal_handle = palhdl;
    } else {
        PalObjectClose(palhdl);
    }
    ret = 0;

out:
    free(uri);
    return ret;
}


static int shm_setup_dentry(struct libos_dentry* dent, mode_t type, mode_t perm,
                               file_off_t size) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct libos_inode* inode = get_new_inode(dent->mount, type, perm);
    if (!inode)
        return -ENOMEM;
    inode->size = size;
    dent->inode = inode;
    return 0;
}

static int shm_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));

    int ret;

    /*
     * We don't know the file type yet, so we can't construct a PAL URI with the right prefix. In
     * most cases, a "file:" prefix is good enough: `PalStreamAttributesQuery` will access the file
     * and report the right file type.
     *
     * The only exception is when this is the root dentry of a "dev:" mount, i.e. a directly mounted
     * device. This is because PAL recognizes a special "dev:tty" device, which needs to be referred
     * to by this exact URI (and "file:tty" will not work).
     */
    char* uri = NULL;
    mode_t tmp_type = S_IFREG;
    if (!dent->parent && strstartswith(dent->mount->uri, URI_PREFIX_DEV))
        tmp_type = S_IFCHR;

    ret = chroot_dentry_uri(dent, tmp_type, &uri);
    if (ret < 0)
        goto out;

    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQuery(uri, &pal_attr);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    mode_t type;
    switch (pal_attr.handle_type) {
        case PAL_TYPE_FILE:
            type = S_IFREG;
            break;
        case PAL_TYPE_DIR:
            type = S_IFDIR;
            break;
        case PAL_TYPE_DEV:
            type = S_IFCHR;
            break;
        case PAL_TYPE_PIPE:
            log_warning("trying to access '%s' which is a host-level FIFO (named pipe); "
                        "Gramine supports only named pipes created by Gramine processes",
                        uri);
            ret = -EACCES;
            goto out;
        default:
            log_error("unexpected handle type returned by PAL: %d", pal_attr.handle_type);
            BUG();
    }

    mode_t perm = pal_attr.share_flags;

    file_off_t size = (type == S_IFREG ? pal_attr.pending_size : 0);

    ret = shm_setup_dentry(dent, type, perm, size);
out:
    free(uri);
    return ret;
}

static int shm_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    return shm_do_open(hdl, dent, dent->inode->type, flags, /*perm=*/0);
}
static int shm_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret;

    mode_t type = S_IFREG;

    ret = shm_do_open(hdl, dent, type, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        return ret;

    return shm_setup_dentry(dent, type, perm, /*size=*/0);
}

struct libos_fs_ops shm_fs_ops = {
    .mount      = &shm_mount,
    .mmap       = &shm_mmap,
    .hstat      = &generic_inode_hstat,
    .truncate   = &shm_truncate,
    .poll       = &generic_inode_poll,
};

struct libos_d_ops shm_d_ops = {
    .open    = &shm_open,
    .lookup  = &shm_lookup,
    .creat   = &shm_creat,
    .stat    = &generic_inode_stat,
    .readdir = &chroot_readdir,
    .unlink  = &chroot_unlink,
};

struct libos_fs shm_builtin_fs = {
    .name   = "shm",
    .fs_ops = &shm_fs_ops,
    .d_ops  = &shm_d_ops,
};