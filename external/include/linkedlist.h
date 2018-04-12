/*
 * Copyright (c) 2018 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __LINKEDLIST_H__
#define __LINKEDLIST_H__

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <common_export.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
#define rwlock_t        SRWLOCK
#else
#define rwlock_t        pthread_rwlock_t
#endif

struct linked_list;

typedef struct linked_list_entry {
    void *data;
    char placeholder[sizeof(void *) * 2];
} ListEntry;

typedef struct linked_list List;

/* Return 0 if equals, -1 if entry1 < entry2, 1 if entry1 > entry2. */
typedef int ListEntryCompare(ListEntry *entry1, ListEntry *entry2);

COMMON_API
List *list_create(int synced, ListEntryCompare *compare);

COMMON_API
int list_insert(List *lst, int index, ListEntry *entry);

static inline
void list_add(List *lst, ListEntry *entry)
{
    list_insert(lst, -1, entry);
}

static inline
void list_push_head(List *lst, ListEntry *entry)
{
    list_insert(lst, 0, entry);
}

static inline
void list_push_tail(List *lst, ListEntry *entry)
{
    list_insert(lst, -1, entry);
}

COMMON_API
void *list_remove_entry(List *lst, ListEntry *entry);

COMMON_API
void *list_remove(List *lst, int index);

static inline
void *list_pop_head(List *lst)
{
    return list_remove(lst, 0);
}

static inline
void *list_pop_tail(List *lst)
{
    return list_remove(lst, -1);
}

COMMON_API
void *list_get(List *lst, int index);

COMMON_API
size_t list_size(List *lst);

static inline
int list_is_empty(List *lst)
{
    return list_size(lst) == 0;
}

COMMON_API
void list_clear(List *lst);

COMMON_API
int list_find(List *lst, ListEntry *entry);

static inline
int list_contains(List *lst, ListEntry *entry)
{
    return list_find(lst, entry) >= 0;
}

static inline
int list_index_of(List *lst, ListEntry *entry)
{
    return list_find(lst, entry);
}

typedef struct ListIterator {
    char placeholder[sizeof(void *) * 4];
} ListIterator;

COMMON_API
ListIterator *list_iterate(List *lst, ListIterator *iterator);

// return 1 on success, 0 end of iterator, -1 on modified conflict or error.
COMMON_API
int list_iterator_next(ListIterator *iterator, void **data);

COMMON_API
int list_iterator_has_next(ListIterator *iterator);

// return 1 on success, 0 nothing removed, -1 on modified conflict or error.
COMMON_API
int list_iterator_remove(ListIterator *iterator);

#ifdef __cplusplus
}
#endif

#endif
