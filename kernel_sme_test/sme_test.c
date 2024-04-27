/*
 * sme_test.c
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include "asm/cacheflush.h"
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/dma-buf.h>
#include <linux/timekeeping.h>
#include <linux/timex.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/numa.h>
#include <linux/cpuset.h>

#define SUCCESS 0
#define DRIVERNAME "sme_test"
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SME DECRYPT/ENCRYPT TEST");
#define GROUP_SIZE 64
#define LINE_SIZE	64
#define BUF_LEN 64

struct page** allocate_pages_group(void)
{
    int i;
    struct page** pages = kmalloc(sizeof(struct page*) * GROUP_SIZE, GFP_KERNEL);

    if (!pages) {
        pr_err("Failed to allocate memory for page group structure\n");
        return NULL;
    }

    for (i = 0; i < GROUP_SIZE; i++) {
        pages[i] = alloc_page(GFP_KERNEL);
        if (!pages[i]) {
            pr_err("Failed to allocate page %d\n", i);
            while (i-- > 0) {
                __free_page(pages[i]);
            }
            kfree(pages);
            return NULL;
        }
    }

    return pages;
}

static unsigned long vaddr2paddr(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd))
    {
        printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d))
    {
        printk("not mapped in p4d\n");
        return -1;
    }
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud))
    {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd))
    {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte))
    {
        printk("not mapped in pte\n");
        return -1;
    }

    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;

    return paddr;
}


void free_pages_group(struct page** pages)
{
    int i;
    for (i = 0; i < GROUP_SIZE; i++) {
        __free_page(pages[i]);
    }
    kfree(pages);
}


static __inline__ int64_t rdtsc_s(void)
{
  unsigned a, d; 
    mb(); //加了一个内存屏障
    rmb(); //加了一个内存屏障
    wmb();
  asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
  asm volatile("rdtsc" : "=a" (a), "=d" (d)); 
  return ((unsigned long)a) | (((unsigned long)d) << 32); 
}

static __inline__ int64_t rdtsc_e(void)
{
  unsigned a, d; 
   mb(); //加了一个内存屏障
   rmb(); //加了一个内存屏障
    wmb();
  asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");

  asm volatile("rdtscp" : "=a" (a), "=d" (d)); 
  return ((unsigned long)a) | (((unsigned long)d) << 32); 
}


void write_to_pages(struct page** pages,struct page** pages1)
{
    int i,j,k;
    int re_time = 100000;
    void *unenc;
    void *enc;
    unsigned int z = 0;
    unsigned int index,index1,index2;
    volatile char tmp;
    unsigned int sizes = GROUP_SIZE * PAGE_SIZE;
    for(index = 0;index <= 999999;index++)
    {
        z += 1;
    }
    pr_info("%lu",z);
    unsigned int time0,time1,time2,time3,random_number,start,start1,end,end1;
    unsigned int notime0,notime1,notime2,notime3;
    unsigned int total_time0,total_time1,total_time2,total_time3,total_time4;
    unsigned int nototal_time0,nototal_time1,nototal_time2,nototal_time3,nototal_time4;
        unenc = vmap(pages, GROUP_SIZE, 0, PAGE_KERNEL_NOCACHE);               // C-bit, plaintext 
        enc = vmap(pages1, GROUP_SIZE, 0, __pgprot(__PAGE_KERNEL_NOCACHE)); // no C-bit, ciphertext
        memset(unenc, 0, sizes);//初始化这个页，确保tlb能命中
        char *unenc_char = (char *)unenc;
        char *enc_char = (char *)enc;
        // print_hex_dump(KERN_DEBUG, "[Unenc Vaule] ", DUMP_PREFIX_OFFSET, 16, 1, unenc, 128, 1);
        // print_hex_dump(KERN_DEBUG, "[Enc Vaule] ", DUMP_PREFIX_OFFSET, 16, 1, enc, 128, 1);
        printk("enc physical address %llx\nunenc physical adress %llx\n",vaddr2paddr(enc_char),vaddr2paddr(unenc_char));
        for(j=0;j<sizes;j++)
        {
            unenc_char[j] = j % 256;
        }
        total_time3 = 0;
        total_time0 = 0;
        total_time1 = 0;
        total_time2 = 0;
        total_time4 = 0;
        nototal_time3 = 0;
        nototal_time0 = 0;
        nototal_time1 = 0;
        nototal_time2 = 0;
        nototal_time4 = 0;
    for(k = 0; k<= re_time; k++){
        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        time0 = end - start;
        total_time0 += time0;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[1128]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        time1 = end - start;
        total_time1 += time1;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index1 = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[1128]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[67]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        time2 = end - start;
        total_time2 += time2;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index1 = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index2 = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[1128]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[67]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&unenc_char[3090]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        time3 = end - start;
        total_time3 += time3;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        notime0 = end - start;
        nototal_time0 += notime0;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[1128]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        notime1 = end - start;
        nototal_time1 += notime1;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index1 = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[1128]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[67]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        notime2 = end - start;
        nototal_time2 += notime2;

        start = 0;
        start1 = 0;
        end = 0;
        end1 =0;
        random_number = 0;
        index = 0;
        get_random_bytes(&random_number, sizeof(random_number));
        index = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index1 = random_number % (sizes - 16);
        get_random_bytes(&random_number, sizeof(random_number));
        index2 = random_number % (sizes - 16);
        mb(); //加了一个内存屏障
        rmb(); //加了一个内存屏障
        wmb();
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtsc" : "=a" (start), "=d" (start1)); 
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[0]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[1128]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[67]) // hit
                        : );
            asm volatile ("mov (%1), %0"
                        : "=r" (tmp)  
                        : "r" (&enc_char[3090]) // hit
                        : );
        mb(); 
        asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile("rdtscp" : "=a" (end), "=d" (end1)); 
        end = ((unsigned long)end) | (((unsigned long)end1) << 32) ;
        start = ((unsigned long)start) | (((unsigned long)start1) << 32) ;
        notime3 = end - start;
        nototal_time3 += notime3;


        // printk(" <@c-bit@%llu@%llu@%llu@%llu@> <@no-bit@%llu@%llu@%llu@%llu@>",time0,time1,time2,time3,notime0,notime1,notime2,notime3);

    }
        printk("c-bit is %llu %llu %llu %llu\nnoc-bit is %llu %llu %llu %llu\n",total_time0 / re_time,total_time1 / re_time,total_time2 / re_time,total_time3 / re_time
        ,nototal_time0 / re_time,nototal_time1 / re_time,nototal_time2 / re_time,nototal_time3 / re_time);
}



int sme_test_init_module(void)
{
    // struct cpumask cpus; // 用于绑定 CPU 的 CPU mask
    // nodemask_t nodes; // 用于指定 NUMA 节点的 NODE mask

    // cpumask_clear(&cpus);
    // nodes_clear(nodes);

    // if (num_possible_nodes() > 0) {
    //     node_set(0, nodes);
    //     if (cpumask_of_node(0)) {
    //         cpumask_copy(&cpus, cpumask_of_node(0));
    //     }
    // }
    // if (!cpumask_empty(&cpus)) {
    //     set_cpus_allowed_ptr(current, &cpus);
    // }
    // printk(KERN_INFO "NUMA module initialized.\n");

    // int k = 0;
    // for(k=0;k<1;k++){
        // preempt_disable();
        struct page **pages = allocate_pages_group();
        if (!pages) {
            return -ENOMEM;
        }
        struct page **pages1 = allocate_pages_group();
        if (!pages) {
            return -ENOMEM;
        }
        write_to_pages(pages,pages1);
        free_pages_group(pages);
        free_pages_group(pages1);
        // preempt_enable();
    return SUCCESS;
}

void sme_test_exit_module(void)
{
}

module_init(sme_test_init_module);
module_exit(sme_test_exit_module);

