// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <uapi/linux/sched/types.h>

#include "osi_hotthread.h"
#include "osi_topology.h"
#include "osi_tasktrack.h"

#define TOP_THREAD_CNT     (5)
#define MAX_CLUSTER        (3)
static struct task_track_cpu task_track[MAX_CLUSTER];
static struct task_track  hot_track[JANK_WIN_CNT][TOP_THREAD_CNT];
struct hot_track_node {
	struct plist_node node;
	struct task_track hot_track;
};
PLIST_HEAD(hot_thread_head);

void plist_add(struct plist_node *node, struct plist_head *head)
{
	struct plist_node *first, *iter, *prev = NULL;
	struct list_head *node_next = &head->node_list;

	WARN_ON(!plist_node_empty(node));
	WARN_ON(!list_empty(&node->prio_list));
	if (plist_head_empty(head))
		goto ins_node;
	first = iter = plist_first(head);
	do {
		if (node->prio < iter->prio) {
			node_next = &iter->node_list;
			break;
		}
		prev = iter;
		iter = list_entry(iter->prio_list.next, struct plist_node, prio_list);
	} while (iter != first);
	if (!prev || prev->prio != node->prio)
		list_add_tail(&node->prio_list, &iter->prio_list);
ins_node:
	list_add_tail(&node->node_list, node_next);
}

static DEFINE_RAW_SPINLOCK(hot_thread_lock);

int insert_hot_thread(struct oplus_task_struct *ots, struct task_struct *p, struct task_struct *leader, u32 now_idx)
{
	struct hot_track_node *hot_node;
	unsigned long flags;
	const struct cred *tcred;
	uid_t uid;
	u8 total_cnt = ots->total_cnt;

	if (!total_cnt)
		return 0;
	rcu_read_lock();
	tcred = __task_cred(p);
	uid = __kuid_val(tcred->uid);
	rcu_read_unlock();
	hot_node = kzalloc(sizeof(struct hot_track_node), GFP_ATOMIC);
	if (!hot_node) {
		return -ENOMEM;
	}
	raw_spin_lock_irqsave(&hot_thread_lock, flags);

	memcpy(hot_node->hot_track.comm, p->comm, TASK_COMM_LEN);
	memcpy(hot_node->hot_track.leader_comm, leader->comm, TASK_COMM_LEN);
	hot_node->hot_track.record.count = total_cnt;
	hot_node->hot_track.record.top_app_cnt = ots->top_app_cnt;
	hot_node->hot_track.record.non_topapp_cnt = ots->non_topapp_cnt;
	hot_node->hot_track.pid = p->pid;
	hot_node->hot_track.tgid = p->tgid;
	hot_node->hot_track.uid = uid;

	plist_node_init(&hot_node->node, INT_MAX - total_cnt);
	plist_add(&hot_node->node, &hot_thread_head);
	raw_spin_unlock_irqrestore(&hot_thread_lock, flags);
	return 0;
}

void  get_hot_thread(u32 now_idx)
{
	struct hot_track_node *hot_node, *tmp;
	unsigned long flags;
	int i = 0;
	raw_spin_lock_irqsave(&hot_thread_lock, flags);

	plist_for_each_entry_safe(hot_node, tmp, &hot_thread_head, node) {
		if (!hot_node) {
			goto out;
		}
		if (i < TOP_THREAD_CNT) {
			memcpy(&hot_track[now_idx][i], &hot_node->hot_track, sizeof(struct task_track));
			i++;
		}
		plist_del(&hot_node->node, &hot_thread_head);
		kfree(hot_node);
	}
out:
	raw_spin_unlock_irqrestore(&hot_thread_lock, flags);
}

static struct task_record *get_task_record(struct task_struct *t,
			u32 cpu)
{
	struct task_record *rc = NULL;

	rc = (struct task_record *) (&(get_oplus_task_struct(t)->record));
	return (struct task_record *) (&rc[cpu]);
}


void reset_perthread_cnt(struct oplus_task_struct *ots)
{
	ots->total_cnt = 0;
	ots->non_topapp_cnt = 0;
	ots->top_app_cnt = 0;
}
/* updated in each tick */
void jank_hotthread_update_tick(struct task_struct *p, u64 now)
{
	struct task_record *record_p, *record_b;

	u64 timestamp;
	u32 now_idx;
	u32 cpu, cluster_id;

	if (!p)
		return;
	cpu = p->cpu;
	cluster_id = get_cluster_id(cpu);
	record_p = get_task_record(p, cluster_id);

	if (record_p->winidx == get_record_winidx(now)) {
		record_p->count++;
	} else {
		record_p->count = 1;
	}

	record_p->winidx = get_record_winidx(now);

	now_idx = time2winidx(now);
	record_b = &task_track[cluster_id].track[now_idx].record;
	timestamp = task_track[cluster_id].track[now_idx].timestamp;

	if (!is_same_idx(timestamp, now) || (record_p->count > record_b->count)) {
		task_track[cluster_id].track[now_idx].pid = p->pid;
		task_track[cluster_id].track[now_idx].tgid = p->tgid;

		memcpy(task_track[cluster_id].track[now_idx].comm,
			p->comm, TASK_COMM_LEN);
		memcpy(record_b, record_p, sizeof(struct task_record));

		task_track[cluster_id].track[now_idx].timestamp = now;
	}
}

void hotthread_show(struct seq_file *m, u32 win_idx, u64 now)
{
	u32 i, now_index, idx;
	bool nospace = false;
	struct task_track  *tmp_track;
	u64 timestamp;
	pid_t  pid, tgid;
	uid_t uid;

	now_index =  time2winidx(now);
	for (i = 0; i < TOP_THREAD_CNT; i++) {
		nospace = (i == TOP_THREAD_CNT-1) ? true : false;
		idx = winidx_sub(now_index, win_idx);
		tmp_track = &hot_track[idx][i];
		pid = tmp_track->pid;
		tgid = tmp_track->tgid;
		uid = tmp_track->uid;
		timestamp = tmp_track->timestamp;
		if (tmp_track->record.count) {
			seq_printf(m, "%d$%d$%s$%d$%s$%d$%d%s", uid, tgid, tmp_track->leader_comm,
			pid, tmp_track->comm, tmp_track->record.top_app_cnt, tmp_track->record.non_topapp_cnt,
			nospace ? "" : "  ");
		}
	}
}

void jank_hotthread_show(struct seq_file *m, u32 win_idx, u64 now)
{
	u32 i, idx, now_index;
	u64 timestamp;
	struct task_track *track_p;
	struct task_struct *leader;
	char *comm;
	bool nospace = false;

	now_index =  time2winidx(now);

	for (i = 0; i < MAX_CLUSTER; i++) {
		nospace = (i == MAX_CLUSTER-1) ? true : false;


		idx = winidx_sub(now_index, win_idx);
		track_p = &task_track[i].track[idx];
		timestamp = track_p->timestamp;

		leader = jank_find_get_task_by_vpid(track_p->tgid);
		comm = leader ? leader->comm : track_p->comm;

		/*
		 * The following situations indicate that this thread is not hot
		 *  a) task is null, which means no suitable task, or task is dead
		 *  b) the time stamp is overdue
		 *  c) count did not reach the threshold
		 */
		if (!timestamp_is_valid(timestamp, now))
			seq_printf(m, "-%s", nospace ? "" : " ");
		else
			seq_printf(m, "%s$%d%s", comm,
						track_p->record.count,
						nospace ? "" : " ");

		if (leader)
			put_task_struct(leader);
	}
}

static int  top_hotthread_dump_win(struct seq_file *m, void *v, u32 win_cnt)
{
	u32 i;
	u64 now = jiffies_to_nsecs(jiffies);

	for (i = 0; i < win_cnt; i++) {
		hotthread_show(m, i, now);
		seq_puts(m, "\n");
	}
	return 0;
}

static int proc_top_hotthread_show(struct seq_file *m, void *v)
{
	return top_hotthread_dump_win(m, v, JANK_WIN_CNT/2);
}
static int proc_top_hotthread_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, proc_top_hotthread_show, inode);
}

static const struct proc_ops proc_top_hotthread_info_operations = {
	.proc_open	=	proc_top_hotthread_open,
	.proc_read	=	seq_read,
	.proc_lseek	=	seq_lseek,
	.proc_release =	single_release,
};


void osi_hotthread_proc_init(struct proc_dir_entry *pde)
{
	struct proc_dir_entry *entry = NULL;
	entry = proc_create("top_hotthread", S_IRUGO,
				pde, &proc_top_hotthread_info_operations);
	if (!entry) {
		osi_err("create top_hotthread fail\n");
		return;
	}
}

void osi_hotthread_proc_deinit(struct proc_dir_entry *pde)
{
	remove_proc_entry("top_hotthread", pde);
}
