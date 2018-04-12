#ifndef __SHADOWS_H__
#define __SHADOWS_H__

#include <stdint.h>
#include <linkedhashtable.h>
#include <ela_carrier.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    HashEntry he;

    char *service;
    char *bind_address;
    char *port;

    int state;
    int port_forwarding;
} Shadow;

static inline
uint32_t shadows_hash_code(const void *key, size_t len)
{
    return (uint32_t)key;
}

static inline
int shadows_key_compare(const void *key1, size_t len1,
                       const void *key2, size_t len2)
{
    return (uint32_t)key1 != (uint32_t)key2;
}

static inline
Hashtable *shadows_create(int capacity)
{
    return hashtable_create(capacity, 1, shadows_hash_code,
                            shadows_key_compare);
}

static inline
void shadows_put(Hashtable *htab, Shadow *shadow)
{
    shadow->he.data = shadow;
    shadow->he.key = (void *)shadow->service;
    shadow->he.keylen = strlen(shadow->service);

    hashtable_put(htab, &shadow->he);
}

static inline
Shadow *shadows_get(Hashtable *htab, const char *service)
{
    return (Shadow *)hashtable_get(htab, (void *)service, strlen(service));
}

static inline
int shadows_exist(Hashtable *htab, const char *service)
{
    return hashtable_exist(htab, (void *)service, strlen(service));
}

static inline
int shadows_is_empty(Hashtable *htab)
{
    return hashtable_is_empty(htab);
}

static inline
Shadow *shadows_remove(Hashtable *htab, const char *service)
{
    return hashtable_remove(htab, (void *)service, strlen(service));
}

static inline
void shadows_clear(Hashtable *htab)
{
    return hashtable_clear(htab);
}

static inline
HashtableIterator *shadows_iterate(Hashtable *htab,
                                  HashtableIterator *iterator)
{
    return hashtable_iterate(htab, iterator);
}

// return 1 on success, 0 end of iterator, -1 on modified conflict or error.
static inline
int shadows_iterator_next(HashtableIterator *iterator, Shadow **shadow)
{
    return hashtable_iterator_next(iterator, NULL, NULL, (void **)shadow);
}

static inline
int shadows_iterator_has_next(HashtableIterator *iterator)
{
    return hashtable_iterator_has_next(iterator);
}

// return 1 on success, 0 nothing removed, -1 on modified conflict or error.
static inline
int shadows_iterator_remove(HashtableIterator *iterator)
{
    return hashtable_iterator_remove(iterator);
}

#ifdef __cplusplus
}
#endif

#endif /* __AGENTS_H__ */
