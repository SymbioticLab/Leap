#include <linux/module.h>  
#include <linux/kernel.h>   
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/socket.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hasan Al Maruf");
MODULE_DESCRIPTION("Kernel module to enable/disable Leap components");

char *cmd;
unsigned long tried = 0;
char *process_name;
MODULE_PARM_DESC(cmd, "A string, for prefetch load/unload command");
module_param(cmd, charp, 0000);
MODULE_PARM_DESC(process_name, "A string, for process name");
module_param(process_name, charp, 0000);

static int get_pid_for_process(void) {
	int pid = -1;
	struct task_struct *task;
	for_each_process(task) {
		if (strcmp(process_name, task->comm) == 0) {
			pid = task->pid;
			printk(KERN_INFO "Process id of %s process is %i\n",process_name, task->pid);
		}
	}
	return pid;
}

static int process_find_init(void) {	
	int pid = -1;
	printk(KERN_INFO "Initiating process find for %s!\n", process_name);
	if (!process_name) {
		printk(KERN_INFO "Invalid process_name\n");
		return -1;
	}
	while(pid == -1) {
		pid = get_pid_for_process();
		tried++;
		if (tried > 30)
			break;
		if (pid == -1)
			msleep(1000); //milisecond sleep
	}
	if(pid != -1) {
		set_process_id(pid);
		printk("PROCESS ID set for remote I/O -> %ld\n", get_process_id());
	}
	else {
		printk(KERN_INFO "Failed to track process within %ld seconds\n", tried);
	}
	return 0;
}

static void usage(void) {
        printk(KERN_INFO "To enable remote I/O data path: insmod leap_functionality.ko process_name=\"tunkrank\" cmd=\"init\"\n");
        printk(KERN_INFO "To enable prefetching: insmod leap_functionality.ko cmd=\"prefetch\"\n");
        printk(KERN_INFO "To disable prefetching: insmod leap_functionality.ko cmd=\"readahead\"\n");
        printk(KERN_INFO "To have swap info log: insmod leap_functionality.ko cmd=\"log\"\n");
}

static int __init leap_functionality_init(void) {	
	if(strcmp(cmd, "init") == 0){
		process_find_init();
		return 0;
	}
	if(strcmp(cmd, "prefetch") == 0){
		init_swap_trend(32);
		set_custom_prefetch(1);
		return 0;
	}
	else if(strcmp(cmd, "log") == 0) {
		swap_info_log();
		return 0;
	}
	else if(strcmp(cmd, "readahead") == 0){
		set_custom_prefetch(0);
		return 0;
	}
	else
                usage();
	return 0;
}

static void __exit leap_functionality_exit(void){
    printk(KERN_INFO "Cleaning up leap functionality sample module.\n");
}

module_init(leap_functionality_init);
module_exit(leap_functionality_exit);

