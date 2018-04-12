#ifndef __AGENTS_H__
#define __AGENTS_H__

#include <stdint.h>
#include <linkedhashtable.h>
#include <ela_carrier.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    HashEntry he;

    char *userid;
    char *user_address;
    Hashtable *shadows;

    ElaSession *session;
    int stream_id;
    int state;

    void *priv;
} Agent;

static inline
uint32_t agents_hash_code(const void *key, size_t len)
{
    return (uint32_t)key;
}

static inline
int agents_key_compare(const void *key1, size_t len1,
                       const void *key2, size_t len2)
{
    return (uint32_t)key1 != (uint32_t)key2;
}

static inline
Hashtable *agents_create(int capacity)
{
    return hashtable_create(capacity, 1, agents_hash_code,
                            agents_key_compare);
}

static inline
void agents_put(Hashtable *htab, Agent *agent)
{
    agent->he.data = agent;
    agent->he.key = (void *)agent->userid;
    agent->he.keylen = strlen(agent->userid);

    hashtable_put(htab, &agent->he);
}

static inline
Agent *agents_get(Hashtable *htab, const char *userid)
{
    return (Agent *)hashtable_get(htab, (void *)userid, strlen(userid));
}

static inline
int agents_exist(Hashtable *htab, const char *userid)
{
    return hashtable_exist(htab, (void *)userid, strlen(userid));
}

static inline
int agents_is_empty(Hashtable *htab)
{
    return hashtable_is_empty(htab);
}

static inline
Agent *agents_remove(Hashtable *htab, const char *userid)
{
    return hashtable_remove(htab, (void *)userid, strlen(userid));
}

static inline
void agents_clear(Hashtable *htab)
{
    return hashtable_clear(htab);
}

static inline
HashtableIterator *agents_iterate(Hashtable *htab,
                                  HashtableIterator *iterator)
{
    return hashtable_iterate(htab, iterator);
}

// return 1 on success, 0 end of iterator, -1 on modified conflict or error.
static inline
int agents_iterator_next(HashtableIterator *iterator, Agent **agent)
{
    return hashtable_iterator_next(iterator, NULL, NULL, (void **)agent);
}

static inline
int agents_iterator_has_next(HashtableIterator *iterator)
{
    return hashtable_iterator_has_next(iterator);
}

// return 1 on success, 0 nothing removed, -1 on modified conflict or error.
static inline
int agents_iterator_remove(HashtableIterator *iterator)
{
    return hashtable_iterator_remove(iterator);
}

static inline
Agent *agents_get_by_stream(Hashtable *htab, int stream)
{
    HashtableIterator it;

recheck:
    agents_iterate(htab, &it);
    while (agents_iterator_has_next(&it)) {
        Agent *agent;
        int rc;

        rc = agents_iterator_next(&it, &agent);
        if (rc == 0)
            break;
        if (rc == -1)
            goto recheck;

        if (agent->stream_id == stream)
            return agent;
        else
            deref(agent);
    }
    return NULL;
}

static inline
Agent *agents_get_by_session(Hashtable *htab, void *session)
{
    HashtableIterator it;

recheck:
    agents_iterate(htab, &it);
    while (agents_iterator_has_next(&it)) {
        Agent *agent;
        int rc;

        rc = agents_iterator_next(&it, &agent);
        if (rc == 0)
            break;
        if (rc == -1)
            goto recheck;

        if (agent->session == session)
        return agent;
        else
            deref(agent);
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* __AGENTS_H__ */
