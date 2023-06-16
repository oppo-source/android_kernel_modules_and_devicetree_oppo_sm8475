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

#include "osi_topology.h"

struct cluster_info cluster[CPU_NUMS];
u32 cluster_num;
struct cpumask all_cpu;
struct cpumask silver_cpu;
struct cpumask gold_cpu;

void cluster_init(void)
{
	u32 i, j = -1;
	struct cpufreq_policy *policy;

	cluster_num = 0;
	memset(&cluster, 0, sizeof(struct cluster_info) * CPU_NUMS);

	for (i = 0; i < CPU_NUMS; i++) {
		policy = cpufreq_cpu_get_raw(i);
		if (!policy)
			continue;

		if (policy->cpu == i) {
			cluster[++j].start_cpu = i;
			cluster_num++;
		}
		cpumask_set_cpu(i, &all_cpu);
		cluster[j].cpu_nr++;

		if (policy->cpu == 0)
			cpumask_set_cpu(i, &silver_cpu);
		else
			cpumask_set_cpu(i, &gold_cpu);
	}
}

u32 get_start_cpu(u32 cpu)
{
	struct cpufreq_policy *policy;
	u32 start_cpu;

	policy = cpufreq_cpu_get(cpu);
	start_cpu = cpumask_first(policy->related_cpus);
	cpufreq_cpu_put(policy);
	return start_cpu;
}

u32 get_cluster_id(u32 cpu)
{
	u32 cluster_id;

	cluster_id = topology_physical_package_id(cpu);
	return cluster_id;
}

bool is_cluster_cpu(u32 cpu)
{
	u32 start_cpu;
	struct cpufreq_policy *policy;

	policy = cpufreq_cpu_get(cpu);
	start_cpu = cpumask_first(policy->related_cpus);
	cpufreq_cpu_put(policy);
	if (start_cpu == cpu)
		return true;
	return false;
}

