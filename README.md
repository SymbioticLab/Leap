# Leap: Faster Data Path for Remote Memory
Leap is a prefetching solution for remote memory accesses due to memory disaggregation. At its core, Leap employs an online, majority-based prefetching algorithm, which increases the page cache hit rate. We complement it with a lightweight and efficient data path in the kernel that isolates each application’s data path to the disaggregated memory and mitigates latency bottlenecks arising from legacy throughput-optimizing operations. Integration of Leap in the Linux kernel improves the median and tail remote page access latencies of memory-bound applications by up to 104.04× and 22.62×, respectively, over the default data path. This leads to up to 10.16× performance improvements for applications using disaggregated memory in comparison to the state-of-the-art solutions.

Detailed design and performance benchmarks are available in our USENIX ATC'20 paper. [[Paper]](https://www.usenix.org/system/files/atc20-maruf.pdf) [[Slide]](https://www.usenix.org/system/files/atc20-paper437-slides-maruf.pdf) [[Talk]](https://2459d6dc103cb5933875-c0245c5c937c5dedcca3f1764ecc9b2f.ssl.cf2.rackcdn.com/atc20/atc20-paper437-video-long-maruf.mp4)

Dependency
-----------
The current version of Leap is tested on
* Operating system: Linux Kernel v4.4.0/4.11.0:  
* RDMA NIC driver: [MLNX_OFED 3.4/4.1](http://www.mellanox.com/page/products_dyn?product_family=26) (*recommend 4.1*), and select the right version for your operating system. 
* Hardware: Mellanox ConnectX-3/4 (InfiniBand)

Code Organization
-----------
To implement Leap's core functionalities, we made the following addition/modification over Linux's source code.

* `leap/leap.c`: All functionalities related to remote I/O.
* `mm/swap_state.c`: Prefetching algorithm and prefetch cache management.
* `mm/page_io.c`: Bypass Block-Layer operations and redirect the paging events to the remote I/O interface.
* `mm/memory.c`: Eager cache eviction.

Compile
-----------
* To compile the Leap Kernel:
    ```bash
    # Install dependency packages 
    sudo apt-get install -y git build-essential kernel-package fakeroot libncurses5-dev libssl-dev ccache libelf-dev libqt4-dev pkg-config ncurses-dev
    
    # Get the config file, uncomment unnecessary device driveres to have a faster compilation.
    cp /boot/config-'uname -r' .config 

    # Clean previous make
    make mrproper 

    # Compile, install headers and modules, generate grub and reboot
    yes ''| make oldconfig
    make -j32
    make headers_install
    make modules_install
    make install
    reboot 
    ```
    Detailed information on how to compile Linux Kernel from source code can be found [here](https://github.com/SymbioticLab/Leap/blob/dev/README)
* To compile the user-space daemon that exposes a machine's local memory as remote memory:
    ```bash
    cd daemon/
    make
    ```
    
Usage
-----------
Let's conside a simple one-to-one experiment, where we have two machines (M1 and M2).
Applications run in M1. M1 needs remote memory from M2.
We need to install Leap Kernel on M1, and run the user-space daemon on M2.

1. Setup InfiniBand NIC on both machines:
    ```bash
    # assume all IB NICs are connected in the same LAN (192.168.0.x)
    # M1:192.168.0.11, M2:192.168.0.12
    sudo modprobe ib_ipoib
    sudo ifconfig ib0 192.168.0.11/24
    ```
2. Compile the daemon on M2 and run it:
    ```bash  	
    cd daemon   
    # ./daemon <ip> <port> 
    # pick up an unused port number
    ./daemon 192.168.0.12 9400
    ```
3. Compile and install Leap Kernel on M1. For remote paging, configure the swap space so that it can support the maximum amount of remote memory footprint. [Here](https://www.howtogeek.com/106873/how-to-use-fdisk-to-manage-partitions-on-linux/) you can find how to adjust the swap space using `fdisk`. 
4. Leap exposes multiple syscall and kernel level functions to control its functionalities realtime.
    * Connect remote machine M2 using the `is_session_create` system call
    ```C
    syscall(is_session_create, "rdma://1,192.168.0.12:9400");
    # if you want to connect multiple machine's from M1, just change the parameter.
    # for exapmle, to connect 3 machines with <ip:port>=<192.168.0.12:9400>, <192.168.0.13:9402>, <192.168.0.14:9400>; the parameter string should be:
    "rdma://3,192.168.0.12:9400,192.168.0.13:9402,192.168.0.14:9400"
    ```
    * To enable the remote I/O; use the kernel-level function `set_process_id(unsigned long pid)`. Setting it to `0` will disable the remote I/O data path.
    * To enable the prefetching, initially set the history buffer size using `init_swap_trend(int history_buffer_size)`, then initiate Leap's prefetching using `set_custom_prefetch(1)`. You can go back to Linux's default read-ahead prefetcher by performing `set_custom_prefetch(0)`.
    
    [Here](https://github.com/SymbioticLab/Leap/blob/dev/example/leap_functionality.c) you will find a sample kernel module that uses the above mentioned functions to run Leap's features.
    
Contact
-----------
This work is done by [Hasan Al Maruf](http://web.eecs.umich.edu/~hasanal/) and [Mosharaf Chowdhury](http://www.mosharaf.com/)
You can email us at `hasanal at umich dot edu`, file issues, or submit pull requests.
