#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

struct sched_profiler_data {
    u64 timestamp;
    pid_t prev_pid;
    pid_t next_pid;
};

static struct sched_profiler_data last_switch;

//internal flag to know the internal state of enabled/disabled profiling.
static unsigned long my_scheduler_profiler = 0; //Disabled by default
//TODO: change var name better to "profiling_enabled"


static struct proc_dir_entry *my_scheduler_profiler_proc;

asmlinkage long sys_myprofiler(unsigned long *my_scheduler_profiler_flag)
{
	/**
	ubuntu@cs692:~$ grep -iRl "copy_to_user"
	linux-4.4.1lab2/tools/virtio/linux/uaccess.h
	*/
	unsigned long my_scheduler_profiler;

        //Check that the incoming buffer is a valid user memory
        if ((!access_ok(VERIFY_WRITE, (void __user *)my_scheduler_profiler_flag, sizeof(unsigned long))))
	  return -EINVAL;

        if(copy_from_user(&my_scheduler_profiler, my_scheduler_profiler_flag, sizeof(unsigned long)))
        {
           printk("ERROR: user passed in malicious string, return -EFAULT");
           return -EFAULT;
        }
        else
        {
           printk("SUCCESS: configured scheduler profiler En/Dis function to %d !", my_scheduler_profiler);
        }

	 return 0;
}

void profile_sched_switch(struct task_struct *prev, struct task_struct *next) {
    if (!profiling_enabled)
        return;

    last_switch.timestamp = ktime_get_ns(); // Get the current timestamp in nanoseconds.
    last_switch.prev_pid = prev->pid;       // Get the PID of the task being switched out.
    last_switch.next_pid = next->pid;       // Get the PID of the task being switched in.

    // TODO: Add code to write this data to a file or another logging mechanism.
}
EXPORT_SYMBOL_GPL(profile_sched_switch);


static int my_sched_prof_show(struct seq_file *m, void *v)
{

        printk("my_sched_prof_show() was called \n");
	//seq_printf(m, "%lu", &my_scheduler_profiler);
        
        seq_printf(m, "Timestamp: %llu, Previous PID: %d, Next PID: %d\n",
               last_switch.timestamp, last_switch.prev_pid, last_switch.next_pid);

        return 0;
}


static int my_sched_prof_open(struct inode *inode, struct file *file)
{
        printk("my_sched_prof_open() was called \n");
	return single_open(file, my_sched_prof_show, NULL);
}

static ssize_t my_sched_prof_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	char *buf;
	int value;

        //User passed in malicious buffer
        if(count > sizeof(unsigned long))
        {
          kfree(buf);
          return -EINVAL;
        }

        //Check that the incoming buffer is a valid user memory
        if ((!access_ok(VERIFY_READ, (void __user *)buffer, sizeof(unsigned long))))
        {
          kfree(buf);
          return -EINVAL;
        }

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (buf == NULL)
	  return -ENOMEM;

	if (copy_from_user(buf, buffer, count)) {
	  return -EFAULT;
	}

	buf[count] = '\0';
	//mconsole_notify(notify_socket, MCONSOLE_USER_NOTIFY, buf, count);
	/**
	https://www.educative.io/answers/how-to-read-data-using-sscanf-in-c
	*/
	
	/*
	https://www.scaler.com/topics/sscanf-in-c/#
	*/
	if(sscanf(buf, "%d", &value) < 0)
	{
		return -EFAULT;
	}
	my_scheduler_profiler = value;
	return count;
}

static const struct file_operations my_sched_prof_operations = {
	.owner		= THIS_MODULE,
	.open		= my_sched_prof_open,
	.read		= seq_read,
        .write          = my_sched_prof_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init my_sched_prof_init(void)
{
	struct proc_dir_entry *dir;
 	dir = proc_mkdir("lk692", NULL);
	if(dir == NULL)
	{
		return -ENOMEM;
	}
		
	my_scheduler_profiler_proc = proc_create("my_scheduler_profiler", 0, dir, &my_sched_prof_operations);
	
	if (!my_scheduler_profiler_proc) {
		printk("error in create proc entry, return -ENOMEM !!");
		return -ENOMEM;
	}

	return 0;
}


static void __exit my_sched_prof_exit(void)
{

		printk("my_sched_prof_exit() was called \n");
		remove_proc_entry("my_scheduler_profiler", NULL);
}

module_init(my_sched_prof_init);
module_exit(my_sched_prof_exit);
