/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#pragma once

#include <endian.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

typedef struct {
        uint32_t length;

        unsigned char type;
        unsigned char data[];
} GdmPamExtensionMessage;

static inline void
gdm_pam_extension_zero_buffer (void   *s,
                               size_t  n)
{
#if (defined(__GLIBC__) && defined(__GLIBC_MINOR__) && \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)) && \
    (defined(_GNU_SOURCE) || defined(_DEFAULT_SOURCE))) || \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
        explicit_bzero (s, n);
#else
        memset (s, 0, n);
        __asm__ __volatile__ ("" : : "r"(s) : "memory");
#endif
}

static inline GdmPamExtensionMessage *
gdm_pam_extension_message_from_pam_message (const struct pam_message *query)
{
        return (GdmPamExtensionMessage *) (void *) query->msg;
}

static inline char *
gdm_pam_extension_message_to_pam_reply (void *msg)
{
        return (char *) msg;
}

static inline void
gdm_pam_extension_message_to_binary_prompt_message (GdmPamExtensionMessage *extended_message,
                                                    struct pam_message     *binary_message)
{
        binary_message->msg_style = PAM_BINARY_PROMPT;
        binary_message->msg = (void *) extended_message;
}

static inline bool
gdm_pam_extension_message_truncated (const GdmPamExtensionMessage *msg)
{
        return be32toh (msg->length) < sizeof (GdmPamExtensionMessage);
}

static inline bool
gdm_pam_extension_message_invalid_type (const GdmPamExtensionMessage *msg)
{
        bool _invalid = true;
        int _n = -1;
        const char *_supported_extensions;

        _supported_extensions = getenv ("GDM_SUPPORTED_PAM_EXTENSIONS");
        if (_supported_extensions != NULL) {
                const char *_p = _supported_extensions;
                while (*_p != '\0' && _n < UCHAR_MAX) {
                        size_t _length;
                        _length = strcspn (_p, " ");
                        if (_length > 0)
                                _n++;
                        _p += _length;
                        _length = strspn (_p, " ");
                        _p += _length;
                }
                if (_n >= msg->type)
                        _invalid = false;
        }

        return _invalid;
}

static inline bool
gdm_pam_extension_message_match (const GdmPamExtensionMessage *msg,
                                 char * const                 *supported_extensions,
                                 const char                   *name)
{
        return strcmp (supported_extensions[msg->type], name) == 0;
}

static inline bool
gdm_pam_extension_look_up_type (const char    *name,
                                unsigned char *extension_type)
{
        bool _supported = false;
        unsigned char _t = 0;
        const char *_supported_extensions;

        _supported_extensions = getenv ("GDM_SUPPORTED_PAM_EXTENSIONS");
        if (_supported_extensions != NULL) {
                const char *_p = _supported_extensions;
                while (*_p != '\0') {
                        size_t _length;
                        _length = strcspn (_p, " ");
                        if (strncmp (_p, name, _length) == 0) {
                                _supported = true;
                                break;
                        }
                        _p += _length;
                        _length = strspn (_p, " ");
                        _p += _length;
                        if (_t >= UCHAR_MAX) {
                                break;
                        }
                        _t++;
                }
                if (_supported && extension_type != NULL)
                        *extension_type = _t;
        }

        return _supported;
}

static inline bool
gdm_pam_extension_supported (const char *name)
{
        return gdm_pam_extension_look_up_type (name, NULL);
}

/* environment_block should be a statically allocated chunk of memory. This is
 * important because putenv() will leak otherwise (and setenv isn't thread safe)
 */
static inline void
gdm_pam_extension_advertise_supported_extensions (char               *environment_block,
                                                  size_t              block_size,
                                                  const char * const *supported_extensions)
{
        size_t _size = 0;
        unsigned char _t, _num_chunks;
        char *_p;

        _p = environment_block;
        _p = stpncpy (_p, "GDM_SUPPORTED_PAM_EXTENSIONS", block_size);
        *_p = '\0';
        _size += strlen (environment_block);

        for (_t = 0; supported_extensions[_t] != NULL && _t < UCHAR_MAX; _t++) {
                size_t _next_chunk = strlen (supported_extensions[_t]) + strlen (" ");
                if (_size + _next_chunk >= block_size)
                        break;
                _size += _next_chunk;
        }
        _num_chunks = _t;

        if (_t != 0) {
                _p = stpcpy (_p, "=");
                for (_t = 0; _t < _num_chunks; _t++) {
                        if (_t != 0)
                                _p = stpcpy (_p, " ");
                        _p = stpcpy (_p, supported_extensions[_t]);
                }
                *_p = '\0';
                putenv (environment_block);
        }
}
