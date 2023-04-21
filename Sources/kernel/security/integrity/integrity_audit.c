/*
 * Copyright (C) 2023 CWD SYSTEMS
 * Author: CWD
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: integrity_audit.c
 *	Audit calls for the integrity subsystem
 */

#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/audit.h>
#include "integrity.h"

static int integrity_audit_info;

/* enable or disable informational auditing messages */
static int __init integrity_audit_setup(char *str)
{
	unsigned long audit;
	if (!kstrtoul(str, 0, &audit))
		integrity_audit_info = audit ? 1 : 0;
	return 1;
}
__setup("integrity_audit=", integrity_audit_setup);

/* write an audit message */
void integrity_audit_msg(int audit_msgno, const char *op, const char *cause,
			 int result, const struct inode *inode,
			 const unsigned char *fname, int audit_info)
{
	struct audit_buffer *ab;
	char name[TASK_COMM_LEN];
	kuid_t uid = current_cred()->uid;
	kuid_t loginuid = audit_get_loginuid(current);
	u32 sessionid = audit_get_sessionid(current);
	
	if (!integrity_audit_info && audit_info == 1)
		return; /* Skip info messages */

	ab = audit_log_start(current->audit_context, GFP_KERNEL, audit_msgno);
	audit_log_format(ab, "pid=%d uid=%u auid=%u ses=%u",
			  task_pid_nr(current),
			  from_kuid(&init_user_ns, uid),
			  from_kuid(&init_user_ns, loginuid), sessionid);
	audit_log_task_context(ab);

	audit_log_format(ab, " op=%s cause=%s comm=", op, cause);
	audit_log_untrustedstring(ab, get_task_comm(name, current));
	
	if (fname) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, fname);
	}
	if (inode) {
		audit_log_format(ab, " dev=");
		audit_log_untrustedstring(ab, inode->i_sb->s_id);
		audit_log_format(ab, " ino=%lu", inode->i_ino);
	}
	audit_log_format(ab, " res=%d", !result);
	audit_log_end(ab);
}
