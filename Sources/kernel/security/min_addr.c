#include <linux/init.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/sysctl.h>

/* Amount of virtual memory to protect from userspace access by both DAC and LSM */
unsigned long mmap_min_addr;

/* Amount of virtual memory to protect from userspace using CAP_SYS_RAWIO (DAC) */
unsigned long dac_mmap_min_addr = CONFIG_DEFAULT_MMAP_MIN_ADDR;

/* Amount of virtual memory to protect from userspace using LSM */
/* = CONFIG_LSM_MMAP_MIN_ADDR */
/* Only available if LSM is enabled */
#ifdef CONFIG_LSM_MMAP_MIN_ADDR
unsigned long lsm_mmap_min_addr = CONFIG_LSM_MMAP_MIN_ADDR;
#endif

/*
 * Update mmap_min_addr = max(dac_mmap_min_addr, lsm_mmap_min_addr)
 */
static void update_mmap_min_addr(void)
{
#ifdef CONFIG_LSM_MMAP_MIN_ADDR
	if (dac_mmap_min_addr > lsm_mmap_min_addr)
		mmap_min_addr = dac_mmap_min_addr;
	else
		mmap_min_addr = lsm_mmap_min_addr;
#else
	mmap_min_addr = dac_mmap_min_addr;
#endif
}

/*
 * sysctl handler which just sets dac_mmap_min_addr = the new value and then
 * calls update_mmap_min_addr() so non MAP_FIXED hints get rounded properly
 */
int mmap_min_addr_handler(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	/* Only allow writes if the process has CAP_SYS_RAWIO capability */
	if (write && !capable(CAP_SYS_RAWIO))
		return -EPERM;

	/* Call proc_doulongvec_minmax to handle the write */
	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);

	/* Update mmap_min_addr */
	update_mmap_min_addr();

	return ret;
}

/*
 * Initialization function called when the module is loaded
 */
static int __init init_mmap_min_addr(void)
{
	/* Set mmap_min_addr to the maximum value of dac_mmap_min_addr and lsm_mmap_min_addr */
	update_mmap_min_addr();

	return 0;
}

/* Register the init function to be called when the module is loaded */
pure_initcall(init_mmap_min_addr);
