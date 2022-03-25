#ifndef NFQDOM
#define NFQDOM
//---------------------------------------------------------------------------

/*
 * Calculate the effective registered domain of a fully qualified domain name.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Florian Sager, 03.01.2009, sager@agitos.de, http://www.agitos.de
 * Ward van Wanrooij, 04.04.2010, ward@ward.nu
 * Ed Walker, 03.10.2012
 *
 */
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "nfqinfo.h"
#include "tld-canon.h"
//---------------------------------------------------------------------------

#define ALL    '*'
#define THS    '!'
#define CHILDREN_BITS (sizeof(unsigned int)*CHAR_BIT - CHAR_BIT)
#define CHILDREN_MAX  ((1ul << CHILDREN_BITS) - 1)

struct tldnode
{
    unsigned int num_children : CHILDREN_BITS;
    char attr;
    char label[];
};
typedef struct tldnode tldnode;

// The subnodes of a tldnode with children are stored in memory locations
// immediately before the node header.  This allows us to allocate the
// node header, label, and child vector in one go.
#define subnodes(tn) ((const tldnode *const *)(tn) - (tn)->num_children)
#define subnodes_w(tn) ((tldnode **)(tn) - (tn)->num_children)

// Prime numbers for hashing.
#define FIRSTH_PRIME 37
#define PRIME_A 54059
#define PRIME_B 76963
//---------------------------------------------------------------------------

class NFQDom
{
private:

    // Recursively construct a search tree from the string pointed-to by 'dptr'.
    static tldnode * parseTldNode(const char **dptr)
    {
        tldnode *rv;
        const char *p = *dptr;
        const char *name, *nend;
        unsigned long nchildren;

        // When we are called, the first thing at '*dptr' will be either
        // a name token (terminated by one of ',' '(' ')') or one of the
        // special characters '*' or '!'.
        if (p[0] == ALL || p[0] == THS)
        {
            // Special characters must be immediately followed by ',' or ')'.
            // They are not allowed to have subnodes.
            if (p[1] != ',' && p[1] != ')')
                abort();
            rv = (tldnode *) malloc(sizeof(tldnode));
            rv->num_children = 0;
            rv->attr = p[0];

            *dptr = p + 1; // leave cursor pointing at ',' / ')'
        }
        else
        {
            name = p;
            nend = p = p + strcspn(p, "(),");
            if (name == nend || *nend == '\0')
                abort();
            if (*p == '(')
            {
                char *endptr;
                errno = 0;
                nchildren = strtoul(p+1, &endptr, 10);
                if (endptr == p+1 || *endptr != ':' || errno
                    || nchildren > CHILDREN_MAX)
                    abort();
                p = endptr + 1;
            }
            else
                nchildren = 0;

            rv = (tldnode *)((char *)malloc(sizeof(tldnode) +
                                            nchildren*sizeof(tldnode *) +
                                            (nend - name + 1)) + nchildren * sizeof(tldnode *));

            rv->num_children = nchildren;
            rv->attr = '\0';
            memcpy(rv->label, name, nend - name);
            rv->label[nend-name] = '\0';

            *dptr = p;
            for (unsigned long i = 0; i < nchildren; i++)
            {
                subnodes_w(rv)[i] = parseTldNode(dptr);
                if (**dptr != ((i == nchildren-1) ? ')' : ','))
                    abort();

                (*dptr)++;
            }
        }
        return rv;
    }

public:

    // Read TLD string into fast-lookup data structure
    static void * loadTldTree()
    {
        const char *data = tldString;
        void *rv = parseTldNode(&data);

        // Should have consumed the entire string.
        if (*data)
            abort();

        return rv;
    }

    // Free tld node structure
    static void freeTldTree(tldnode *node)
    {
        for (unsigned int i = 0; i < node->num_children; i++)
             freeTldTree(subnodes_w(node)[i]);

        free(subnodes_w(node));
    }

    // Print tld node structure.
    static void printTldTree(const tldnode *node, const char *spacer)
    {
        if (!spacer)
            spacer = "";

        if (node->attr)
            printf("%s%s: %c\n", spacer, node->label, node->attr);
        else
            printf("%s%s:\n", spacer, node->label);

        if (node->num_children > 0)
        {
            size_t n = strlen(spacer);
            char nspacer[n+2+1];
            memcpy(nspacer, spacer, n);
            nspacer[n]   = ' ';
            nspacer[n+1] = ' ';
            nspacer[n+2] = '\0';

            for (unsigned int i = 0; i < node->num_children; i++)
                 printTldTree(subnodes(node)[i], nspacer);
        }
    }

    // Linear search for domain (and * if available)
    static const tldnode * findTldNode(const tldnode *parent,
                                       const char *seg_start, const char *seg_end)
    {
        const tldnode *allNode = 0;

        for (unsigned int i = 0; i < parent->num_children; i++)
        {
            if (!allNode && subnodes(parent)[i]->attr == ALL)
                allNode = subnodes(parent)[i];
            else
            {
                size_t m = seg_end - seg_start;
                size_t n = strlen(subnodes(parent)[i]->label);
                if (m == n && !memcmp(subnodes(parent)[i]->label, seg_start, n))
                    return subnodes(parent)[i];
            }
        }
        return allNode;
    }

    // Get registered domain from FQDN.
    static char * getRegisteredDomain(const char *hostname, void *nodeTree, char **tld_pointer)
    {
        int points_counter  = 0;
        const tldnode *tree = (const tldnode *) nodeTree;

        // Eliminate some special (always-fail) cases first.
        if (hostname[0] == '\0' || hostname[0] == '.' || !tld_pointer)
            return 0;

        *tld_pointer = NULL;

        // The registered domain will always be a suffix of the input hostname.
        // Start at the end of the name and work backward.
        const char *head = hostname;
        const char *seg_end = hostname + strlen(hostname);
        const char *seg_start;

        if (seg_end[-1] == '.')
            seg_end--;

        seg_start = seg_end;

        for (;;)
        {
            while (seg_start > head && *seg_start != '.')
                   seg_start--;

            if (*seg_start == '.')
                seg_start++;

            const tldnode *subtree = findTldNode(tree, seg_start, seg_end);
            if (!subtree || (subtree->num_children == 1 &&
                subnodes(subtree)[0]->attr == THS))  // Match found.
                break;
            else
            {
                if (points_counter < 2)
                {
                    if (seg_start > head)
                        *tld_pointer = (char*) seg_start - 1;
                }
            }

            if (seg_start == head)
            {
                if (*seg_end == '.') {
                    *tld_pointer = (char *) seg_end;
                    return (char *)seg_start;
                }

                *tld_pointer = NULL;

                // No match, i.e. the input name is too short to be a
                // registered domain.
                return 0;
            }

            // Advance to the next label.
            tree = subtree;

            if (seg_start[-1] != '.')
                return 0;

            seg_end = seg_start - 1;
            seg_start = seg_end - 1;

            ++points_counter;
        }

        // Ensure the stripped domain contains at least two labels.
        if (!strchr(seg_start, '.'))
        {
            if (seg_start == head)
                return 0;

            if (seg_start > head)
                *tld_pointer = (char*) seg_start - 1;

            seg_start -= 2;
            while (seg_start > head && *seg_start != '.')
                   seg_start--;

            if (*seg_start == '.')
                seg_start++;
        }

        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wcast-qual"
            return (char *)seg_start;
        #pragma GCC diagnostic pop
    }

    static bool findHashInFile(const unsigned long long int hash_value, CategoryFile *cf)
    {
        off_t last = 0;
        off_t first = 0;
        off_t middle = 0;
        bool found_value_flag = false;
        unsigned long long int file_value = 0;
        int size_factor = sizeof(unsigned long long int);

        last = cf->fileSize - size_factor;
        while (first <= last)
        {
            middle = first + size_factor * ((last - first) / (2 * size_factor));

            if (lseek(cf->dscp, middle, SEEK_SET) == -1 ||
                read(cf->dscp,&file_value,size_factor) == -1) // Error while reading from file.
                return false;

            if (hash_value < file_value)
                last = middle - size_factor;
            else if (hash_value > file_value)
                first = middle + size_factor;
            else {
                found_value_flag = true;
                break;
            }
        }

        return found_value_flag;
    }

    static unsigned long long int strToHash(const char *string)
    {
        unsigned long long int h = FIRSTH_PRIME;
        while (*string)
        {
            h = (h * PRIME_A) ^ (*(string++) * PRIME_B);
        }
        return h;
    }
};
//---------------------------------------------------------------------------
#endif
