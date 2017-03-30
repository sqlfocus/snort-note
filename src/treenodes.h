/****************************************************************************
 * Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

/* We moved the OptTreeNode and RuleTreeNode here to make them easier to
   include in dynamic preprocessors. */

#ifndef TREENODES_H
#define TREENODES_H

#include "rules.h"
#include "plugin_enum.h"
#include "rule_option_types.h"

struct _OptTreeNode;      /* forward declaration of OTN data struct */
struct _RuleTreeNode;     /* forward declaration of RTN data struct */

/* same as the rule header FP list */
typedef struct _OptFpList
{
    /* context data for this test */
    void *context;                    /* 记录正则串相关数据，如PatternMatchData */

    int (*OptTestFunc)(void *option_data, Packet *p);
                                      /* 匹配函数 */
    struct _OptFpList *next;

    unsigned char isRelative;
    option_type_t type;               /* 匹配类型 */

} OptFpList;

/* 规则选项解析结果 */
typedef struct _OptTreeNode
{
    /* plugin/detection functions go here */
    OptFpList *opt_func;         /* 规则的匹配函数 */
    RspFpList *rsp_func;         /* response functions */
    OutputFuncNode *outputFuncs; /* per sid enabled output functions */

    /* the ds_list is absolutely essential for the plugin system to work,
       it allows the plugin authors to associate "dynamic" data structures
       with the rule system, letting them link anything they can come up 
       with to the rules list */
    void *ds_list[PLUGIN_MAX];   /* 插件数据指针，如content模式匹配数据PatternMatchData，list of plugin data struct pointers */

    int chain_node_number;       /* 分配顺序计数？ */

    int evalIndex;       /* where this rule sits in the evaluation sets */

    int proto;                   /* IP协议, added for integrity checks during rule parsing */

    int session_flag;    /* record session data */

    char *logto;         /* log file in which to write packets which 
                            match this rule*/
    /* metadata about signature */
    SigInfo sigInfo;

    uint8_t stateless;  /* this rule can fire regardless of session state */
    uint8_t established; /* this rule can only fire if it is established */
    uint8_t unestablished;

    Event event_data;

    void* detection_filter; /* if present, evaluated last, after header checks */
    TagData *tag;

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    int activates;
    int activated_by;

    struct _OptTreeNode *OTN_activation_ptr;
    struct _RuleTreeNode *RTN_activation_ptr;

    struct _OptTreeNode *next;

    struct _OptTreeNode *nextSoid;

    /* ptr to list of RTNs (head part) */
    struct _RuleTreeNode **proto_nodes;   /* 对应的规则头列表 */

    /**number of proto_nodes. */
    unsigned short proto_node_num;

    uint8_t failedCheckBits;
    char generated;

    uint16_t longestPatternLen;

    int rule_state;                       /* Enabled or Disabled */

#ifdef PERF_PROFILING
    uint64_t ticks;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
    uint64_t checks;
    uint64_t matches;
    uint64_t alerts;
    uint8_t noalerts;
#endif

    int pcre_flag; /* PPM */
    uint64_t ppm_suspend_time; /* PPM */
    uint64_t ppm_disable_cnt; /*PPM */

    uint32_t num_detection_opts;          /* 选项关键字计数 */

    /**unique index generated in ruleIndexMap.
     */
    int ruleIndex;                        /* 规则索引，由解析顺序决定 */

    /* List of preprocessor registered fast pattern contents */
    void *preproc_fp_list;

} OptTreeNode;

/* function pointer list for rule head nodes */
typedef struct _RuleFpList
{
    /* context data for this test */
    void *context;

    /* rule check function pointer */
    int (*RuleHeadFunc)(Packet *, struct _RuleTreeNode *, struct _RuleFpList *, int);

    /* pointer to the next rule function node */
    struct _RuleFpList *next;
} RuleFpList;

/* 规则头解析结果；分开规则头和规则选项，为了最大限度的节省内存 */
typedef struct _RuleTreeNode
{
    RuleFpList *rule_func; /* 匹配函数，IP、端口匹配，match functions.. (Bidirectional etc.. ) */

    int head_node_number;  /* 分配顺序，在链表中的位置？ */

    RuleType type;         /* 规则类型，RULE_TYPE__ALERT，对应规则动作 */

    IpAddrSet *sip;        /* 对应的源IP解析结果 */
    IpAddrSet *dip;        /* 对应的目的IP解析结果 */

    int proto;             /* 协议类型，IPPROTO_TCP */

    PortObject * src_portobject;
    PortObject * dst_portobject;

    uint32_t flags;        /* 控制标识，ANY_SRC_IP、BIDIRECTIONAL等 */

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    ActivateListNode *activate_list;

#if 0
    struct _RuleTreeNode *right;  /* ptr to the next RTN in the list */

    /** list of rule options to associate with this rule node */
    OptTreeNode *down;   
#endif

    /**points to global parent RTN list (Drop/Alert) which contains this 
     * RTN.
     */
    struct _ListHead *listhead;    /* 指向SnortConfig->Alert等 */

    /**reference count from otn. Multiple OTNs can reference this RTN with the same
     * policy.
     */
    unsigned int otnRefCount;      /* 被规则选项引用的次数 */

} RuleTreeNode;

#endif /* TREENODES_H */
