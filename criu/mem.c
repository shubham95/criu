#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "mem.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "log.h"
#include "kerndat.h"
#include "stats.h"
#include "vma.h"
#include "shmem.h"
#include "uffd.h"
#include "pstree.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "bitmap.h"
#include "sk-packet.h"
#include "files-reg.h"
#include "pagemap-cache.h"
#include "fault-injection.h"
#include "prctl.h"
#include "compel/infect-util.h"

#include "protobuf.h"
#include "images/pagemap.pb-c.h"

struct pme_list{
	uint64_t start;
	uint64_t end;
	struct pme_list *next;
};
struct pme_list *pme_list_head = NULL;
struct pme_list *pme_list_tail = NULL;

//Declare global variable for prepare_mapping parrallel
struct history_pme{
	
	/* list of VMAs */
	uint64_t mapp_addr;
	uint64_t start;
	uint64_t end;
	unsigned long nr_pages;
	int is_valid;
	int is_matched;
	struct history_pme *next; 
};
struct history_pme *history_pme_head =NULL;
struct history_pme *history_pme_tail =NULL;



static int task_reset_dirty_track(int pid)
{
	int ret;

	if (!opts.track_mem)
		return 0;

	BUG_ON(!kdat.has_dirty_track);

	ret = do_task_reset_dirty_track(pid);
	BUG_ON(ret == 1);
	return ret;
}

int do_task_reset_dirty_track(int pid)
{
	int fd, ret;
	char cmd[] = "4";

	pr_info("Reset %d's dirty tracking\n", pid);

	fd = __open_proc(pid, EACCES, O_RDWR, "clear_refs");
	if (fd < 0)
		return errno == EACCES ? 1 : -1;

	ret = write(fd, cmd, sizeof(cmd));
	if (ret < 0) {
		if (errno == EINVAL) /* No clear-soft-dirty in kernel */
			ret = 1;
		else {
			pr_perror("Can't reset %d's dirty memory tracker (%d)", pid, errno);
			ret = -1;
		}
	} else {
		pr_info(" ... done\n");
		ret = 0;
	}

	close(fd);
	return ret;
}

unsigned long dump_pages_args_size(struct vm_area_list *vmas)
{
	/* In the worst case I need one iovec for each page */
	return sizeof(struct parasite_dump_pages_args) +
		vmas->nr * sizeof(struct parasite_vma_entry) +
		(vmas->nr_priv_pages + 1) * sizeof(struct iovec);
}

static inline bool __page_is_zero(u64 pme)
{
	return (pme & PME_PFRAME_MASK) == kdat.zero_page_pfn;
}

static inline bool __page_in_parent(bool dirty)
{
	/*
	 * If we do memory tracking, but w/o parent images,
	 * then we have to dump all memory
	 */

	return opts.track_mem && opts.img_parent && !dirty;
}

bool should_dump_page(VmaEntry *vmae, u64 pme)
{
	/*
	 * vDSO area must be always dumped because on restore
	 * we might need to generate a proxy.
	 */
	if (vma_entry_is(vmae, VMA_AREA_VDSO))
		return true;
	/*
	 * In turn VVAR area is special and referenced from
	 * vDSO area by IP addressing (at least on x86) thus
	 * never ever dump its content but always use one provided
	 * by the kernel on restore, ie runtime VVAR area must
	 * be remapped into proper place..
	 */
	if (vma_entry_is(vmae, VMA_AREA_VVAR))
		return false;

	/*
	 * Optimisation for private mapping pages, that haven't
	 * yet being COW-ed
	 */
	if (vma_entry_is(vmae, VMA_FILE_PRIVATE) && (pme & PME_FILE))
		return false;
	if (vma_entry_is(vmae, VMA_AREA_AIORING))
		return true;
	if ((pme & (PME_PRESENT | PME_SWAP)) && !__page_is_zero(pme))
		return true;

	return false;
}

bool page_is_zero(u64 pme)
{
	return __page_is_zero(pme);
}

bool page_in_parent(bool dirty)
{
	return __page_in_parent(dirty);
}

static bool is_stack(struct pstree_item *item, unsigned long vaddr)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		uint64_t sp = dmpi(item)->thread_sp[i];

		if (!((sp ^ vaddr) & ~PAGE_MASK))
			return true;
	}

	return false;
}

/*
 * This routine finds out what memory regions to grab from the
 * dumpee. The iovs generated are then fed into vmsplice to
 * put the memory into the page-pipe's pipe.
 *
 * "Holes" in page-pipe are regions, that should be dumped, but
 * the memory contents is present in the pagent image set.
 */

static int generate_iovs(struct pstree_item *item, struct vma_area *vma, struct page_pipe *pp, u64 *map, u64 *off, bool has_parent)
{
	u64 *at = &map[PAGE_PFN(*off)];
	unsigned long pfn, nr_to_scan;
	unsigned long pages[3] = {};
	int ret = 0;

	nr_to_scan = (vma_area_len(vma) - *off) / PAGE_SIZE;

	for (pfn = 0; pfn < nr_to_scan; pfn++) {
		unsigned long vaddr;
		unsigned int ppb_flags = 0;
		int st;

		if (!should_dump_page(vma->e, at[pfn]))
			continue;

		vaddr = vma->e->start + *off + pfn * PAGE_SIZE;

		if (vma_entry_can_be_lazy(vma->e) && !is_stack(item, vaddr))
			ppb_flags |= PPB_LAZY;

		/*
		 * If we're doing incremental dump (parent images
		 * specified) and page is not soft-dirty -- we dump
		 * hole and expect the parent images to contain this
		 * page. The latter would be checked in page-xfer.
		 */

		if (has_parent && page_in_parent(at[pfn] & PME_SOFT_DIRTY)) {
			ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page(pp, vaddr, ppb_flags);
			if (ppb_flags & PPB_LAZY && opts.lazy_pages)
				st = 1;
			else
				st = 2;
		}

		if (ret) {
			/* Do not do pfn++, just bail out */
			pr_debug("Pagemap full\n");
			break;
		}

		pages[st]++;
	}

	*off += pfn * PAGE_SIZE;

	cnt_add(CNT_PAGES_SCANNED, nr_to_scan);
	cnt_add(CNT_PAGES_SKIPPED_PARENT, pages[0]);
	cnt_add(CNT_PAGES_LAZY, pages[1]);
	cnt_add(CNT_PAGES_WRITTEN, pages[2]);

	pr_info("Pagemap generated: %lu pages (%lu lazy) %lu holes\n",
		pages[2] + pages[1], pages[1], pages[0]);
	return ret;
}

static struct parasite_dump_pages_args *prep_dump_pages_args(struct parasite_ctl *ctl,
		struct vm_area_list *vma_area_list, bool skip_non_trackable)
{
	struct parasite_dump_pages_args *args;
	struct parasite_vma_entry *p_vma;
	struct vma_area *vma;

	args = compel_parasite_args_s(ctl, dump_pages_args_size(vma_area_list));

	p_vma = pargs_vmas(args);
	args->nr_vmas = 0;

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_area_is_private(vma, kdat.task_size))
			continue;
		/*
		 * Kernel write to aio ring is not soft-dirty tracked,
		 * so we ignore them at pre-dump.
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING) && skip_non_trackable)
			continue;
		if (vma->e->prot & PROT_READ)
			continue;

		p_vma->start = vma->e->start;
		p_vma->len = vma_area_len(vma);
		p_vma->prot = vma->e->prot;

		args->nr_vmas++;
		p_vma++;
	}

	return args;
}

static int drain_pages(struct page_pipe *pp, struct parasite_ctl *ctl,
		      struct parasite_dump_pages_args *args)
{
	struct page_pipe_buf *ppb;
	int ret = 0;

	debug_show_page_pipe(pp);

	/* Step 2 -- grab pages into page-pipe */
	list_for_each_entry(ppb, &pp->bufs, l) {
		args->nr_segs = ppb->nr_segs;
		args->nr_pages = ppb->pages_in;
		pr_debug("PPB: %d pages %d segs %u pipe %d off\n",
				args->nr_pages, args->nr_segs, ppb->pipe_size, args->off);

		ret = compel_rpc_call(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0)
			return -1;
		ret = compel_util_send_fd(ctl, ppb->p[1]);
		if (ret)
			return -1;

		ret = compel_rpc_sync(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0)
			return -1;

		args->off += args->nr_segs;
	}

	return 0;
}

static int xfer_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	int ret;

	/*
	 * Step 3 -- write pages into image (or delay writing for
	 *           pre-dump action (see pre_dump_one_task)
	 */
	timing_start(TIME_MEMWRITE);
	ret = page_xfer_dump_pages(xfer, pp);
	timing_stop(TIME_MEMWRITE);

	return ret;
}

static int detect_pid_reuse(struct pstree_item *item,
			    struct proc_pid_stat* pps,
			    InventoryEntry *parent_ie)
{
	unsigned long long dump_ticks;
	struct proc_pid_stat pps_buf;
	unsigned long long tps; /* ticks per second */
	int ret;

	if (!parent_ie) {
		pr_err("Pid-reuse detection failed: no parent inventory, " \
		       "check warnings in get_parent_inventory\n");
		return -1;
	}

	tps = sysconf(_SC_CLK_TCK);
	if (tps == -1) {
		pr_perror("Failed to get clock ticks via sysconf");
		return -1;
	}

	if (!pps) {
		pps = &pps_buf;
		ret = parse_pid_stat(item->pid->real, pps);
		if (ret < 0)
			return -1;
	}

	dump_ticks = parent_ie->dump_uptime/(USEC_PER_SEC/tps);

	if (pps->start_time >= dump_ticks) {
		/* Print "*" if unsure */
		pr_warn("Pid reuse%s detected for pid %d\n",
			pps->start_time == dump_ticks ? "*" : "",
			item->pid->real);
		return 1;
	}
	return 0;
}

static int generate_vma_iovs(struct pstree_item *item, struct vma_area *vma,
			     struct page_pipe *pp, struct page_xfer *xfer,
			     struct parasite_dump_pages_args *args,
			     struct parasite_ctl *ctl, pmc_t *pmc,
			     bool has_parent, bool pre_dump,
			     int parent_predump_mode)
{
	u64 off = 0;
	u64 *map;
	int ret;

	if (!vma_area_is_private(vma, kdat.task_size) &&
				!vma_area_is(vma, VMA_ANON_SHARED))
		return 0;

	/*
	 * To facilitate any combination of pre-dump modes to run after
	 * one another, we need to take extra care as discussed below.
	 *
	 * The SPLICE mode pre-dump, processes all type of memory regions,
	 * whereas READ mode pre-dump skips processing those memory regions
	 * which lacks PROT_READ flag.
	 *
	 * Now on mixing pre-dump modes:
	 * 	If SPLICE mode follows SPLICE mode	: no issue
	 *		-> everything dumped both the times
	 *
	 * 	If READ mode follows READ mode		: no issue
	 *		-> non-PROT_READ skipped both the time
	 *
	 * 	If READ mode follows SPLICE mode   	: no issue
	 *		-> everything dumped at first,
	 *		   the non-PROT_READ skipped later
	 *
	 * 	If SPLICE mode follows READ mode   	: Need special care
	 *
	 * If READ pre-dump happens first, then it has skipped processing
	 * non-PROT_READ regions. Following SPLICE pre-dump expects pagemap
	 * entries for all mappings in parent pagemap, but last READ mode
	 * pre-dump cycle has skipped processing & pagemap generation for
	 * non-PROT_READ regions. So SPLICE mode throws error of missing
	 * pagemap entry for encountered non-PROT_READ mapping.
	 *
	 * To resolve this, the pre-dump-mode is stored in current pre-dump's
	 * inventoy file. This pre-dump mode is read back from this file
	 * (present in parent pre-dump dir) as parent-pre-dump-mode during
	 * next pre-dump.
	 *
	 * If parent-pre-dump-mode and next-pre-dump-mode are in READ-mode ->
	 * SPLICE-mode order, then SPLICE mode doesn't expect mappings for
	 * non-PROT_READ regions in parent-image and marks "has_parent=false".
	 */

	if (!(vma->e->prot & PROT_READ)) {
		if (opts.pre_dump_mode == PRE_DUMP_READ && pre_dump)
			return 0;
		if ((parent_predump_mode == PRE_DUMP_READ &&
			opts.pre_dump_mode == PRE_DUMP_SPLICE) || !pre_dump)
			has_parent = false;
	}

	if (vma_entry_is(vma->e, VMA_AREA_AIORING)) {
		if (pre_dump)
			return 0;
		has_parent = false;
	}

	map = pmc_get_map(pmc, vma);
	if (!map)
		return -1;

	if (vma_area_is(vma, VMA_ANON_SHARED))
		return add_shmem_area(item->pid->real, vma->e, map);

again:
	ret = generate_iovs(item,vma, pp, map, &off, has_parent);
	if (ret == -EAGAIN) {
		BUG_ON(!(pp->flags & PP_CHUNK_MODE));

		ret = drain_pages(pp, ctl, args);
		if (!ret)
			ret = xfer_pages(pp, xfer);
		if (!ret) {
			page_pipe_reinit(pp);
			goto again;
		}
	}

	return ret;
}

static int __parasite_dump_pages_seized(struct pstree_item *item,
		struct parasite_dump_pages_args *args,
		struct vm_area_list *vma_area_list,
		struct mem_dump_ctl *mdc,
		struct parasite_ctl *ctl)
{
	pmc_t pmc = PMC_INIT;
	struct page_pipe *pp;
	struct vma_area *vma_area;
	struct page_xfer xfer = { .parent = NULL };
	int ret, exit_code = -1;
	unsigned cpp_flags = 0;
	unsigned long pmc_size;
	int possible_pid_reuse = 0;
	bool has_parent;
	int parent_predump_mode = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, item->pid->real);
	pr_info("----------------------------------------\n");

	timing_start(TIME_MEMDUMP);

	pr_debug("   Private vmas %lu/%lu pages\n",
		 vma_area_list->nr_priv_pages_longest, vma_area_list->nr_priv_pages);

	/*
	 * Step 0 -- prepare
	 */

	pmc_size = max(vma_area_list->nr_priv_pages_longest,
		       vma_area_list->nr_shared_pages_longest);
	if (pmc_init(&pmc, item->pid->real, &vma_area_list->h,
			 pmc_size * PAGE_SIZE))
		return -1;

	if (!(mdc->pre_dump || mdc->lazy))
		/*
		 * Chunk mode pushes pages portion by portion. This mode
		 * only works when we don't need to keep pp for later
		 * use, i.e. on non-lazy non-predump.
		 */
		cpp_flags |= PP_CHUNK_MODE;
	pp = create_page_pipe(vma_area_list->nr_priv_pages,
					    mdc->lazy ? NULL : pargs_iovs(args),
					    cpp_flags);
	if (!pp)
		goto out;

	if (!mdc->pre_dump) {
		/*
		 * Regular dump -- create xfer object and send pages to it
		 * right here. For pre-dumps the pp will be taken by the
		 * caller and handled later.
		 */
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto out_pp;

		xfer.transfer_lazy = !mdc->lazy;
	} else {
		ret = check_parent_page_xfer(CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto out_pp;

		if (ret)
			xfer.parent = NULL + 1;
	}

	if (xfer.parent) {
		possible_pid_reuse = detect_pid_reuse(item, mdc->stat,
						      mdc->parent_ie);
		if (possible_pid_reuse == -1)
			goto out_xfer;
	}


	/*
	 * Step 1 -- generate the pagemap
	 */
	args->off = 0;
	has_parent = !!xfer.parent && !possible_pid_reuse;
	if(mdc->parent_ie)
		parent_predump_mode = mdc->parent_ie->pre_dump_mode;

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		ret = generate_vma_iovs(item, vma_area, pp, &xfer, args, ctl,
					&pmc, has_parent, mdc->pre_dump,
					parent_predump_mode);
		if (ret < 0)
			goto out_xfer;
	}

	if (mdc->lazy)
		memcpy(pargs_iovs(args), pp->iovs,
		       sizeof(struct iovec) * pp->nr_iovs);

	/*
	 * Faking drain_pages for pre-dump here. Actual drain_pages for pre-dump
	 * will happen after task unfreezing in cr_pre_dump_finish(). This is
	 * actual optimization which reduces time for which process was frozen
	 * during pre-dump.
	 */
	if (mdc->pre_dump && opts.pre_dump_mode == PRE_DUMP_READ)
		ret = 0;
	else
		ret = drain_pages(pp, ctl, args);

	if (!ret && !mdc->pre_dump)
		ret = xfer_pages(pp, &xfer);
	if (ret)
		goto out_xfer;

	timing_stop(TIME_MEMDUMP);

	/*
	 * Step 4 -- clean up
	 */

	ret = task_reset_dirty_track(item->pid->real);
	if (ret)
		goto out_xfer;
	exit_code = 0;
out_xfer:
	if (!mdc->pre_dump)
		xfer.close(&xfer);
out_pp:
	if (ret || !(mdc->pre_dump || mdc->lazy))
		destroy_page_pipe(pp);
	else
		dmpi(item)->mem_pp = pp;
out:
	pmc_fini(&pmc);
	pr_info("----------------------------------------\n");
	return exit_code;
}

int parasite_dump_pages_seized(struct pstree_item *item,
		struct vm_area_list *vma_area_list,
		struct mem_dump_ctl *mdc,
		struct parasite_ctl *ctl)
{
	int ret;
	struct parasite_dump_pages_args *pargs;

	pargs = prep_dump_pages_args(ctl, vma_area_list, mdc->pre_dump);

	/*
	 * Add PROT_READ protection for all VMAs we're about to
	 * dump if they don't have one. Otherwise we'll not be
	 * able to read the memory contents.
	 *
	 * Afterwards -- reprotect memory back.
	 *
	 * This step is required for "splice" mode pre-dump and dump.
	 * Skip this step for "read" mode pre-dump.
	 * "read" mode pre-dump delegates processing of non-PROT_READ
	 * regions to dump stage. Adding PROT_READ works fine for
	 * static processing (target process frozen during pre-dump)
	 * and fails for dynamic as explained below.
	 *
	 * Consider following sequence of instances to reason, why
	 * not to add PROT_READ in "read" mode pre-dump ?
	 *
	 *	CRIU- "read" pre-dump		    Target Process
	 *
	 *					1. Creates mapping M
	 *					   without PROT_READ
	 * 2. CRIU freezes target
	 *    process
	 * 3. Collect the mappings
	 * 4. Add PROT_READ to M
	 *    (non-PROT_READ region)
	 * 5. CRIU unfreezes target
	 *    process
	 *					6. Add flag PROT_READ
	 *					   to mapping M
	 *					7. Revoke flag PROT_READ
	 *					   from mapping M
	 * 8. process_vm_readv tries
	 *    to copy mapping M
	 *    (believing M have
	 *     PROT_READ flag)
	 * 9. syscall fails to copy
	 *    data from M
	 */

	if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
		pargs->add_prot = PROT_READ;
		ret = compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl);
		if (ret) {
			pr_err("Can't dump unprotect vmas with parasite\n");
			return ret;
		}
	}

	if (fault_injected(FI_DUMP_PAGES)) {
		pr_err("fault: Dump VMA pages failure!\n");
		return -1;
	}

	ret = __parasite_dump_pages_seized(item, pargs, vma_area_list, mdc, ctl);
	if (ret) {
		pr_err("Can't dump page with parasite\n");
		/* Parasite will unprotect VMAs after fail in fini() */
		return ret;
	}

	if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
		pargs->add_prot = 0;
		if (compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl)) {
			pr_err("Can't rollback unprotected vmas with parasite\n");
			ret = -1;
		}
	}

	return ret;
}

int prepare_mm_pid(struct pstree_item *i)
{
	pid_t pid = vpid(i);
	int ret = -1, vn = 0;
	struct cr_img *img;
	struct rst_info *ri = rsti(i);

	img = open_image(CR_FD_MM, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ri->mm, PB_MM);
	close_image(img);
	if (ret <= 0)
		return ret;

	if (collect_special_file(ri->mm->exe_file_id) == NULL)
		return -1;

	pr_debug("Found %zd VMAs in image\n", ri->mm->n_vmas);
	img = NULL;
	if (ri->mm->n_vmas == 0) {
		/*
		 * Old image. Read VMAs from vma-.img
		 */
		img = open_image(CR_FD_VMAS, O_RSTR, pid);
		if (!img)
			return -1;
	}


	while (vn < ri->mm->n_vmas || img != NULL) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		ri->vmas.nr++;
		if (!img)
			vma->e = ri->mm->vmas[vn++];
		else {
			ret = pb_read_one_eof(img, &vma->e, PB_VMA);
			if (ret <= 0) {
				xfree(vma);
				close_image(img);
				img = NULL;
				break;
			}
		}
		list_add_tail(&vma->list, &ri->vmas.h);

		if (vma_area_is_private(vma, kdat.task_size)) {
			ri->vmas.rst_priv_size += vma_area_len(vma);
			if (vma_has_guard_gap_hidden(vma))
				ri->vmas.rst_priv_size += PAGE_SIZE;
		}

		pr_info("vma 0x%"PRIx64" 0x%"PRIx64"  nr_pages %ld \n", vma->e->start, vma->e->end,(vma->e->end - vma->e->start)/PAGE_SIZE);

		if (vma_area_is(vma, VMA_ANON_SHARED))
			ret = collect_shmem(pid, vma);
		else if (vma_area_is(vma, VMA_FILE_PRIVATE) ||
				vma_area_is(vma, VMA_FILE_SHARED))
			ret = collect_filemap(vma);
		else if (vma_area_is(vma, VMA_AREA_SOCKET))
			ret = collect_socket_map(vma);
		else
			ret = 0;
		if (ret)
			break;
	}

	if (img)
		close_image(img);
	return ret;
}

static inline bool check_cow_vmas(struct vma_area *vma, struct vma_area *pvma)
{
	/*
	 * VMAs that _may_[1] have COW-ed pages should ...
	 *
	 * [1] I say "may" because whether or not particular pages are
	 * COW-ed is determined later in restore_priv_vma_content() by
	 * memcmp'aring the contents.
	 */

	/* ... coincide by start/stop pair (start is checked by caller) */
	if (vma->e->end != pvma->e->end)
		return false;
	/* ... both be private (and thus have space in premmaped area) */
	if (!vma_area_is_private(vma, kdat.task_size))
		return false;
	if (!vma_area_is_private(pvma, kdat.task_size))
		return false;
	/* ... have growsdown and anon flags coincide */
	if ((vma->e->flags ^ pvma->e->flags) & (MAP_GROWSDOWN | MAP_ANONYMOUS))
		return false;
	/* ... belong to the same file if being filemap */
	if (!(vma->e->flags & MAP_ANONYMOUS) && vma->e->shmid != pvma->e->shmid)
		return false;

	pr_debug("Found two COW VMAs @0x%"PRIx64"-0x%"PRIx64"\n", vma->e->start, pvma->e->end);
	return true;
}

static inline bool vma_inherited(struct vma_area *vma)
{
	return (vma->pvma != NULL && vma->pvma != VMA_COW_ROOT);
}

static void prepare_cow_vmas_for(struct vm_area_list *vmas, struct vm_area_list *pvmas)
{
	struct vma_area *vma, *pvma;

	vma = list_first_entry(&vmas->h, struct vma_area, list);
	pvma = list_first_entry(&pvmas->h, struct vma_area, list);

	while (1) {
		if ((vma->e->start == pvma->e->start) && check_cow_vmas(vma, pvma)) {
			vma->pvma = pvma;
			if (pvma->pvma == NULL)
				pvma->pvma = VMA_COW_ROOT;
		}

		/* <= here to shift from matching VMAs and ... */
		while (vma->e->start <= pvma->e->start) {
			vma = vma_next(vma);
			if (&vma->list == &vmas->h)
				return;
		}

		/* ... no == here since we must stop on matching pair */
		while (pvma->e->start < vma->e->start) {
			pvma = vma_next(pvma);
			if (&pvma->list == &pvmas->h)
				return;
		}
	}
}

void prepare_cow_vmas(void)
{
	struct pstree_item *pi;

	for_each_pstree_item(pi) {
		struct pstree_item *ppi;
		struct vm_area_list *vmas, *pvmas;

		ppi = pi->parent;
		if (!ppi)
			continue;

		vmas = &rsti(pi)->vmas;
		if (vmas->nr == 0) /* Zombie */
			continue;

		pvmas = &rsti(ppi)->vmas;
		if (pvmas->nr == 0) /* zombies cannot have kids,
				     * but helpers can (and do) */
			continue;

		if (rsti(pi)->mm->exe_file_id != rsti(ppi)->mm->exe_file_id)
			/*
			 * Tasks running different executables have
			 * close to zero chance of having cow-ed areas
			 * and actually kernel never creates such.
			 */
			continue;

		prepare_cow_vmas_for(vmas, pvmas);
	}
}

/* Map a private vma, if it is not mapped by a parent yet */
static int premap_private_vma(struct pstree_item *t, struct vma_area *vma, void **tgt_addr)
{
	//agruments to function pstree, vmas list, addrress to mmap pointer , address of pr
	//tgt_addr = is address to mmap address

	int ret;
	void *addr;
	unsigned long nr_pages, size;

	nr_pages = vma_entry_len(vma->e) / PAGE_SIZE;
	vma->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
	if (vma->page_bitmap == NULL)
		return -1;

	/*
	 * A grow-down VMA has a guard page, which protect a VMA below it.
	 * So one more page is mapped here to restore content of the first page
	 */
	if (vma_has_guard_gap_hidden(vma))
		vma->e->start -= PAGE_SIZE;

	size = vma_entry_len(vma->e);
	if (!vma_inherited(vma)) {
		//comes into this if vma is inherited
		struct history_pme *tmp;
		int found =0;
		int flag = 0;
		/*
		 * The respective memory area was NOT found in the parent.
		 * Map a new one.
		 */

		/*
		 * Restore AIO ring buffer content to temporary anonymous area.
		 * This will be placed in io_setup'ed AIO in restore_aio_ring().
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING))
			flag |= MAP_ANONYMOUS;
		else if (vma_area_is(vma, VMA_FILE_PRIVATE)) {
			ret = vma->vm_open(vpid(t), vma);
			if (ret < 0) {
				pr_err("Can't fixup VMA's fd\n");
				return -1;
			}
		}

		/*
		 * All mappings here get PROT_WRITE regardless of whether we
		 * put any data into it or not, because this area will get
		 * mremap()-ed (branch below) so we MIGHT need to have WRITE
		 * bits there. Ideally we'd check for the whole COW-chain
		 * having any data in.
		 */


		/*
		 * If content of vma is already mapped in vma 
		 * mmremap it cuurent target address
		 * 
		 * 		addr = mremap(paddr, size, size,
		 *		MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
		 *		if (addr != *tgt_addr) {
		 *			pr_perror("Unable to remap a private vma");
		 *			return -1;
		 *		}
		 */
		

		tmp = history_pme_head;
		found = -1;
		// while(tmp){
		// 	if((tmp->is_valid == 1) && (unsigned long)vma->e->start == tmp->start && (unsigned long)vma->e->end == tmp->end && (unsigned long)size == (unsigned long)(tmp->nr_pages * PAGE_SIZE)){
		// 		found =1;
		// 		break;
		// 	}
		// 	else if((tmp->is_valid == 1) && (unsigned long)vma->e->start == tmp->start && (unsigned long)vma->e->end > tmp->end){
		// 		/*
		// 		 *
		// 		 * original vma |++++++++++++++++++++++|
		// 		 * Customm  vma |+++++++++++++++|
		// 		 * 
		// 		 * AFter  remap |+++++++++++++++-------|
		// 		 * 
		// 		 */
		// 		unsigned long old_size;
		// 		void *change_addr;
		// 		old_size = tmp->end - tmp->start;
		// 		//new_size = (unsigned long)vma->e->end - (unsigned long)vma->e->start;
		// 		// new_size =0;

		// 		change_addr = mmap(NULL,size,PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0,0);
		// 		memcpy(change_addr,(void *)tmp->mapp_addr,old_size);
		// 		tmp->mapp_addr = (unsigned long)change_addr;
		// 		// orgin_addr = mremap(tmp->mapp_addr,old_size,old_size,0);
		// 		// pr_debug("\n\n\n Orgin addr %p Mapped addr %p\n\n\n",orgin_addr,tmp->mapp_addr);
		// 		tmp->end = (tmp->start + (unsigned long)size);
		// 		tmp->nr_pages = size /PAGE_SIZE;

		// 		pr_debug("\n\n\n Case 1: been there  new start %p new end %p \n\n\n",(void *)tmp->start,(void *)tmp->end);
		// 		found =1;
		// 		break;

		// 	}
		// 	// else if((tmp->is_valid == 1) && (unsigned long)vma->e->start == (unsigned long)tmp->vaddr && (unsigned long)vma->e->end < (unsigned long)tmp->end){
		// 	// 	/*
		// 	// 	 * we are shrinking VMA
		// 	// 	 * original vma |++++++++++++++|
		// 	// 	 * Customm  vma |++++++++++++++++++++++|
		// 	// 	 * 
		// 	// 	 * AFter  remap |+++++++++++++++-------|
		// 	// 	 * 
		// 	// 	 */

		// 	// 	//unsigned long old_size;
		// 	// 	void *change_addr;
		// 	// 	//old_size = (unsigned long)tmp->end - (unsigned long)tmp->vaddr;
		// 	// 	//new_size = (unsigned long)vma->e->end - (unsigned long)vma->e->start;
		// 	// 	// new_size =0;

		// 	// 	change_addr = mmap(NULL,size,PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0,0);
		// 	// 	memcpy(change_addr,tmp->mapp_addr,size);
		// 	// 	tmp->mapp_addr = change_addr;
		// 	// 	// orgin_addr = mremap(tmp->mapp_addr,old_size,old_size,0);
		// 	// 	// pr_debug("\n\n\n Orgin addr %p Mapped addr %p\n\n\n",orgin_addr,tmp->mapp_addr);
		// 	// 	tmp->end = (void *)((unsigned long)tmp->vaddr + (unsigned long)size);
		// 	// 	tmp->nr_pages = size /PAGE_SIZE;

		// 	// 	pr_debug("\n\n\n Case 2: been there  new start %p new end %p \n\n\n",tmp->vaddr,tmp->end);
		// 	// 	found =1;
		// 	// 	break;
		// 	// }
		// 	tmp = tmp->next;
		// }

		if(found ==1){
			unsigned long old_size;
			pr_debug("Matching found at %p  nr_pages %ld \n",(void *)tmp->start,size/PAGE_SIZE);
			// change protection of mmaped vma 
			//int mprotect(void *addr, size_t len, int prot);

			old_size = tmp->end - tmp->start;
			addr = mremap((void *)tmp->mapp_addr, size, size,MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
			mprotect(addr,size,vma->e->prot | PROT_WRITE);

			pr_debug("\n\n\n else part second premap Orgin addr %p Mapped addr %p\n\n\n",addr,*tgt_addr);
			pr_debug("Arguments 1: %p, 2: %ld, 3: %ld, 5 %p",(void *)tmp->mapp_addr,old_size,old_size,*tgt_addr);

		 	if (addr != *tgt_addr) {
		 		pr_perror("Unable to remap a private vma");
		 		return -1;
		 	}
			tmp->is_matched   = 1;
			vma->e->is_filled = 1;
		}
		else{

			if(tmp != NULL){
					/*
					* DISASTROUS ERORR 
					* earlier i was accessing tmp->start without checking NULL condition and getting seg fault
					*/
					flag = flag | MAP_POPULATE;

			}			
			addr = mmap(*tgt_addr, size,
					vma->e->prot | PROT_WRITE|PROT_READ,
					vma->e->flags | MAP_FIXED | flag,
					vma->e->fd, vma->e->pgoff);

			pr_debug("MMap is working with MAP_FIXED\n\n");

			if (addr == MAP_FAILED) {
				pr_perror("Unable to map ANON_VMA");
				return -1;
			}
		}
		//skip this if you have done the mremap

	} else {
		void *paddr;

		/*
		 * The area in question can be COWed with the parent. Remap the
		 * parent area. Note, that it has already being passed through
		 * the restore_priv_vma_content() call and thus may have some
		 * pages in it.
		 */

		paddr = decode_pointer(vma->pvma->premmaped_addr);
		if (vma_has_guard_gap_hidden(vma))
			paddr -= PAGE_SIZE;

		addr = mremap(paddr, size, size,
				MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
		if (addr != *tgt_addr) {
			pr_perror("Unable to remap a private vma");
			return -1;
		}
	}

	/*
	 *status is changed to VMA_PREMMAPED
	 *Update the vma->premmaped_addr to new addr
	 */
	vma->e->status |= VMA_PREMMAPED;
	vma->premmaped_addr = (unsigned long) addr;
	pr_debug("\tpremap %#016"PRIx64"-%#016"PRIx64" -> %016lx\n",
		vma->e->start, vma->e->end, (unsigned long)addr);

	if (vma_has_guard_gap_hidden(vma)) { /* Skip guard page */
		vma->e->start += PAGE_SIZE;
		vma->premmaped_addr += PAGE_SIZE;
	}

	if (vma_area_is(vma, VMA_FILE_PRIVATE))
		vma->vm_open = NULL; /* prevent from 2nd open in prepare_vmas */

	*tgt_addr += size;
	return 0;
}

static inline bool vma_force_premap(struct vma_area *vma, struct list_head *head)
{
	/*
	 * On kernels with 4K guard pages, growsdown VMAs
	 * always have one guard page at the
	 * beginning and sometimes this page contains data.
	 * In case the VMA is premmaped, we premmap one page
	 * larger VMA. In case of in place restore we can only
	 * do this if the VMA in question is not "guarded" by
	 * some other VMA.
	 */
	if (vma->e->flags & MAP_GROWSDOWN) {
		if (vma->list.prev != head) {
			struct vma_area *prev;

			prev = list_entry(vma->list.prev, struct vma_area, list);
			if (prev->e->end == vma->e->start) {
				pr_debug("Force premmap for 0x%"PRIx64":0x%"PRIx64"\n",
						vma->e->start, vma->e->end);
				return true;
			}
		}
	}

	return false;
}

/*
 * Ensure for s390x that vma is below task size on restore system
 */
static int task_size_check(pid_t pid, VmaEntry *entry)
{
#ifdef __s390x__
	if (entry->end <= kdat.task_size)
		return 0;
	pr_err("Can't restore high memory region %lx-%lx because kernel does only support vmas up to %lx\n", entry->start, entry->end, kdat.task_size);
	return -1;
#else
	return 0;
#endif
}

static int premap_priv_vmas(struct pstree_item *t, struct vm_area_list *vmas,
		void **at, struct page_read *pr)
{
	//agruments to function pstree, vmas list, addrress to mmap pointer , address of pr
	//at == address to new mmap area
	struct vma_area *vma;
	unsigned long pstart = 0;
	int ret = 0;
	LIST_HEAD(empty);

	filemap_ctx_init(true);

	list_for_each_entry(vma, &vmas->h, list) {

		if (task_size_check(vpid(t), vma->e)) {
			ret = -1;
			break;
		}

		if (pstart > vma->e->start) {
			ret = -1;
			pr_err("VMA-s are not sorted in the image file\n");
			break;
		}
		//take address of first vma
		pstart = vma->e->start;

		//i guess if vma is not private dont do any thing
		if (!vma_area_is_private(vma, kdat.task_size))
			continue;


		//pvma stand for parent for inherited vma
		if (vma->pvma == NULL && pr->pieok && !vma_force_premap(vma, &vmas->h)) {
			/*
			 * VMA in question is not shared with anyone. We'll
			 * restore it with its contents in restorer.
			 * Now let's check whether we need to map it with
			 * PROT_WRITE or not.
			 */

			/*
			 * This loop ensures that if pagemap is span on more than one vma
			 * change the permissions
			 */
			do {
				if (pr->pe->vaddr + pr->pe->nr_pages * PAGE_SIZE <= vma->e->start)
					continue;
				if (pr->pe->vaddr > vma->e->end)
					vma->e->status |= VMA_NO_PROT_WRITE;
				break;
			} while (pr->advance(pr));

			continue;
		}
		//return 1;

		/*
		 * This function called when above if block fails that means vma is inherited 
		 * but in our case we have pieok=false(intensliy) that means it will  not restore 
		 * in restorer the pages is going to read here in (restore_priv_vma_content)
		 */
		//args passed pstree , vma, address to new mmap
		ret = premap_private_vma(t, vma, at);

		if (ret < 0)
			break;
	}

	filemap_ctx_fini();

	return ret;
}

static int restore_priv_vma_content(struct pstree_item *t, struct page_read *pr)
{
	struct vma_area *vma,*my_vma;
	int ret = 0;
	struct list_head *vmas = &rsti(t)->vmas.h;
	struct list_head *vma_io = &rsti(t)->vma_io;
	struct history_pme *tmp;
	void *source_addr,*tgt_addr;//,*remap_addr,*remap_tmp;

	int loop_var = 1;

	unsigned int nr_restored = 0;
	unsigned int nr_shared = 0; 
	unsigned int nr_dropped = 0;
	unsigned int nr_compared = 0;
	unsigned int nr_lazy = 0;
	unsigned int nr_skip_is_filled = 0;
	unsigned int nr_mremap = 0;
	unsigned int nr_memcpy = 0;
	unsigned long va;
	unsigned long offset_va;

	vma = list_first_entry(vmas, struct vma_area, list);
	my_vma = list_first_entry(vmas, struct vma_area, list);
	rsti(t)->pages_img_id = pr->pages_img_id;

	//pr_debug("vmas %p\n",vmas);

	//printing vma
	// while (vma) {
	// 	pr_debug("Shubham Vma start %p, vma end %p\n",(void *)vma->e->start,(void *)vma->e->end);
	// 	vma = vma_next(vma);
	// }

	// vma = list_first_entry(vmas, struct vma_area, list);



	/*
	 * Read Page Content from our list that we updated
	 * 
	 * Algo description  :
	 * There are two list List1 : it contains all pages (we have to make sure this list is sorted)
	 * 					  List2 : it vma list with premmaped vma address
	 * 					  Offset: it points to starting address of List 1
	 * 
	 * 	while(List1){
	 *  	if(offset >= List2.start && offset < List2.end){
	 * 			
	 * 			read_size = min(List1.end - offset, List2.end - offset)
	 * 			read(offset, size);
	 * 			offset += size;
	 * 			
	 * 			if(offset == List1.end){
	 * 				List1  = List1.next;
	 * 				offset = List1.start;
	 * 			}		
	 * 		}else{
	 * 			List2 = list2->next;
	 * 		}
	 *  }
	 *  
	 *  Whole CREDIT TO : Mr Mainuk
	 * 
	 */

	  tmp = history_pme_head;
	  if(tmp != NULL){
		  /*
		   * DISASTROUS ERORR 
		   * earlier i was accessing tmp->start without checking NULL condition and getting seg fault
		   */
		  loop_var = 0;
		  offset_va = tmp->start;

	  }

	  while(tmp && ((unsigned long)my_vma!= (unsigned long)vmas)){
		  /*
		   * Circular list condition break if you are at the end of list the next
		   * pointer will point to the head pointer which is diffrent from first
		   * node pointer 
		   * And accessing element was creating Seg fault which was not easy
		   * to debug 
		   * 
		   * break when next pointer == head
		   * 
		   * Credit : sattu
		   * 
		   */ 

		if(offset_va >= my_vma->e->start && offset_va < my_vma->e->end){
			unsigned long read_size,read_pages;
			//void *source_addr,*tgt_addr;
			int fd_memmove=-1;
			char buff_args[50];


			read_size  =  min_t(unsigned long,tmp->end - offset_va,my_vma->e->end - offset_va);
			read_pages = read_size/PAGE_SIZE;
			//vma_size  =  my_vma->e->end - my_vma->e->start;
			// //mremap it
			source_addr = (void*)(tmp->mapp_addr + (offset_va - tmp->start));
			tgt_addr    = (void*)((unsigned long)my_vma->premmaped_addr + (offset_va - my_vma->e->start));
			////remap_addr  =  mremap(source_addr,read_size,read_size,MREMAP_FIXED|MREMAP_MAYMOVE,tgt_addr);
			// if(read_size == vma_size && (offset_va==my_vma->e->start)){
			// 	remap_addr  =  mremap(source_addr,read_size,read_size,MREMAP_FIXED|MREMAP_MAYMOVE,tgt_addr);
			// 	if(remap_addr != tgt_addr){
			// 		return -1;
			// 	}
			// 	nr_mremap += read_size/PAGE_SIZE;
			// 	pr_debug(" CASE A Succesfull mremap pages from start addr %p nr_pages %ld into vma %p\n\n",(void *)offset_va,read_size/PAGE_SIZE,(void*)my_vma->e->start);

			// }
			// else if((0) && read_size < vma_size && (offset_va==my_vma->e->start)){
			// 	remap_tmp = mremap(source_addr,read_size,vma_size,MREMAP_MAYMOVE);
			// 	pr_debug("tmp remap %p \n",remap_tmp);
			// 	if(remap_tmp == NULL){
			// 		return -1;
			// 	}
			// 	remap_addr  =  mremap(remap_tmp,read_size,read_size,MREMAP_FIXED|MREMAP_MAYMOVE,tgt_addr);
			// 	if(remap_addr != tgt_addr){
			// 		return -1;
			// 	}
			// 	pr_debug("CASE B Succesfull mremap pages from start addr %p nr_pages %ld into vma %p vma_size %ld\n\n",(void *)offset_va,read_size/PAGE_SIZE,(void*)my_vma->e->start,vma_size/PAGE_SIZE);

			// }else{
			// 	pr_debug("offset %p list start %p end %p mmaped %p\n",(void *)offset_va,(void *)tmp->start,(void *)tmp->end,(void *)tmp->mapp_addr);
			// 	pr_debug("source %p tgt %p, read_size %ld pages %ld\n",source_addr,tgt_addr,read_size,read_size/PAGE_SIZE);
			// 	memcpy(tgt_addr,source_addr,read_size);
			// 	pr_debug("CASE C: Succesfull mremap pages from start addr %p nr_pages %ld into vma %p vma_size %ld\n\n",(void *)offset_va,read_size/PAGE_SIZE,(void*)my_vma->e->start,vma_size/PAGE_SIZE);		
			// 	nr_memcpy += read_size/PAGE_SIZE;
			// }


			/*
			 * Implemented Kernel module pinning pages instead of copying
			 * module name : memmove
			 * read call : pass 3 arguments source addr , Destination addr, nr_pages all in unsigned long
			 * 
			 * Credit Deba
			 */

			 fd_memmove = open("/dev/memmove",O_RDWR);
			 if(fd_memmove < 0){
				pr_debug("memove device not opened\n");
			 }
			 
			 //Filling arguments into buffer
   			 *((unsigned long *)buff_args) = (unsigned long)source_addr;
   			 *((unsigned long *)buff_args+8) = (unsigned long)tgt_addr;
   			 *((unsigned long *)buff_args+16) = (unsigned long)read_pages;			 
  			 
			pr_debug("Source addr %ld, Target addr %ld, nr_pages %ld\n",(unsigned long)source_addr,(unsigned long)tgt_addr,read_pages);
			if(read(fd_memmove, buff_args,24) < 0){
				pr_perror("Read error\n");
			}

			close(fd_memmove);

			offset_va += read_size;
			if(offset_va == tmp->end){
				tmp = tmp->next;

		  	/*
		   	 * DISASTROUS ERORR 
		   	 * earlier i was accessing tmp->start without checking NULL condition and getting seg fault
		   	 */
				if(tmp == NULL){
					pr_err("break\n");
					break;
				}
				offset_va = tmp->start;
			}
		}else{
			my_vma = vma_next(my_vma);
		   /*
		    * DISASTROUS ERORR 
		    * earlier i was accessing tmp->start without checking NULL condition and getting seg fault
		    */
			if(((unsigned long)my_vma == (unsigned long)vmas)){
				pr_err("break\n");
				break;
			}
		}
	  }
	/*
	 * Read page contents.
	 */
	(loop_var == 1)?pr_debug("Normal Restore\n"):pr_debug("Restore Parallel\n");
	while (loop_var) {
		unsigned long off, i, nr_pages;

		ret = pr->advance(pr);
		if (ret <= 0)
			break;

		va = (unsigned long)decode_pointer(pr->pe->vaddr);
		nr_pages = pr->pe->nr_pages;

		pr_err("here\n");


		/*
		 * New approach to skip vmas filling there is a flag in vmas is_filled
		 * if is_filled ==1 that mean we have alreaty filled that pages to skip that vma
		 * 
		 */

		
		/* 
		 * Here some of vmas are already filled with pages we have to skip that
		 * the vma start address should be matched with pagemap addr because our 
		 * vma are made from pagemap 
		 * There is flag is_matched in our history list 
		 */
		// tmp = history_pme_head;
		// found = -1;
		// while(tmp){

		// 	if(tmp->is_matched ==1){
		// 		pr_debug("\n\n\n  va %p  tmp->vaddr %p pages %ld  %ld\n\n\n",(void *)va,tmp->vaddr,nr_pages,tmp->nr_pages );
		// 	}
		// 	if((tmp->is_matched == 1)&&(tmp->is_valid == 1) && (unsigned long)va == (unsigned long)tmp->vaddr && nr_pages == tmp->nr_pages ){
		// 		found =1;
		// 		break;
		// 	}
		// 	tmp = tmp->next;
		// }

		// if(found == 1){
		// 	pr_debug("Skip of page read : Addr %p nr_pages %ld\n",(void*)va,nr_pages);
		// 	pr->skip_pages(pr,nr_pages*PAGE_SIZE);
		// 	continue;
		// }

		/*
		 * This means that userfaultfd is used to load the pages
		 * on demand.
		 */
		if (opts.lazy_pages && pagemap_lazy(pr->pe)) {
			pr_debug("Lazy restore skips %ld pages at %lx\n", nr_pages, va);
			pr->skip_pages(pr, nr_pages * PAGE_SIZE);
			nr_lazy += nr_pages;
			continue;
		}
		pr_err("here\n");

		for (i = 0; i < nr_pages; i++) {
			unsigned char buf[PAGE_SIZE];
			void *p;

			/*
			 * The lookup is over *all* possible VMAs
			 * read from image file.
			 */
			while (va >= vma->e->end) {
				if (vma->list.next == vmas)
					goto err_addr;
				vma = vma_next(vma);
			}

			/*
			 * Make sure the page address is inside existing VMA
			 * and the VMA it refers to still private one, since
			 * there is no guarantee that the data from pagemap is
			 * valid.
			 */
			if (va < vma->e->start)
				goto err_addr;
			else if (unlikely(!vma_area_is_private(vma, kdat.task_size))) {
				pr_err("Trying to restore page for non-private VMA\n");
				goto err_addr;
			}


			/*
			 *
			 * Skipping whole vma
			 */
			pr_err("here\n");

			// if(vma->e->is_filled == 1){
			// 	unsigned long vma_nr_pages;
			// 	vma_nr_pages = 0;
			// 	vma_nr_pages = (vma->e->end - vma->e->start)/PAGE_SIZE;


			// 	pr_debug("Whether vma is filled or not start %p and end %p is_filled %d   va_nr %ld  vma_nr %ld\n\n",(void *)vma->e->start,(void *)vma->e->end,vma->e->is_filled,nr_pages,vma_nr_pages);		

			// 	/*
			// 	 * This should work because our vma in this case is completely full 
			// 	 */
			// 	// if(nr_pages < vma_nr_pages){
			// 	// 	pr->skip_pages(pr,nr_pages*PAGE_SIZE);
			// 	// }
			// 	// else{
			// 	// 	pr->skip_pages(pr,vma_nr_pages * PAGE_SIZE);
			// 	// }
			// 	pr->skip_pages(pr,nr_pages*PAGE_SIZE);
			// 	nr_skip_is_filled += nr_pages;
			// 	i+=nr_pages;
			// 	continue;

			// }
			//Solve mystery when/why it goes to VMA_PREMMAPPED
			if (!vma_area_is(vma, VMA_PREMMAPED)) {
				
				// find minimum between two
				// if total pages left and vma size left
				// if from va there are consecutive page mapped 1000 and vma is smallso we
				// will copy only pages till vmas
				unsigned long len = min_t(unsigned long,
						(nr_pages - i) * PAGE_SIZE,
						vma->e->end - va);

				if (vma->e->status & VMA_NO_PROT_WRITE) {
					pr_debug("VMA 0x%"PRIx64":0x%"PRIx64" RO %#lx:%lu IO\n",
							vma->e->start, vma->e->end, va, nr_pages);
					BUG();
				}

				pr_debug("Shubham log: Start addr %p, nr_pages %ld, len %ld\n",(void *)va,len/4096,len);
				if (pagemap_enqueue_iovec(pr, (void *)va, len, vma_io))
					return -1;

				/*
					skip pages
					pr->pi_off +=len;
					pr->cvaddr +=len;
				*/
				pr->skip_pages(pr, len);

				// increment va
				va += len;
				// divide len by 4096 to get nr of pages
				len >>= PAGE_SHIFT;
				nr_restored += len;
				pr_debug("Shubham nr_restored %d :\n",nr_restored);

				// incremet nr of pages restored to i
				i += len - 1;
				pr_debug("Enqueue page-read\n");
				continue;
			}

			/*
			 * Otherwise to the COW restore
			 */
			pr_debug("Shubham only");

			off = (va - vma->e->start) / PAGE_SIZE;

			//vma->premmaped_addr is the new mmap address
			p = decode_pointer((off) * PAGE_SIZE +
					vma->premmaped_addr);

			set_bit(off, vma->page_bitmap);
			if (vma_inherited(vma)) {
				clear_bit(off, vma->pvma->page_bitmap);

				ret = pr->read_pages(pr, va, 1, buf, 0);
				if (ret < 0)
					goto err_read;

				va += PAGE_SIZE;
				nr_compared++;

				if (memcmp(p, buf, PAGE_SIZE) == 0) {
					nr_shared++; /* the page is cowed */
					continue;
				}

				nr_restored++;
				memcpy(p, buf, PAGE_SIZE);
			} else {
				int nr;

				/*
				 * Try to read as many pages as possible at once.
				 *
				 * Within the t pagemap we still have
				 * nr_pages - i pages (not all, as we might have
				 * switched VMA above), within			 * PROT_WRITE or not.
 the t VMA
				 * we have at most (vma->end - t_addr) bytes.
				 */

				nr = min_t(int, nr_pages - i, (vma->e->end - va) / PAGE_SIZE);

				//putting pages into new mmap location which is present in  p
				ret = pr->read_pages(pr, va, nr, p, PR_ASYNC);
				if (ret < 0)
					goto err_read;

				va += nr * PAGE_SIZE;
				nr_restored += nr;
				i += nr - 1;

				pr_debug("Shubham log: In restore_priv vma nr of pages : %d\n",nr);

				bitmap_set(vma->page_bitmap, off + 1, nr - 1);
			}

		}
	}
 
err_read:
	pr_debug("Shubham log: In err_read after finishing while loop\n");
	//print vma_io list


	if (pr->sync(pr))
		return -1;

	pr->close(pr);
	if (ret < 0)
		return ret;

	/* Remove pages, which were not shared with a child */
	list_for_each_entry(vma, vmas, list) {
		unsigned long size, i = 0;
		void *addr = decode_pointer(vma->premmaped_addr);

		if (!vma_inherited(vma))
			continue;

		size = vma_entry_len(vma->e) / PAGE_SIZE;
		while (1) {
			/* Find all pages, which are not shared with this child */
			i = find_next_bit(vma->pvma->page_bitmap, size, i);

			if ( i >= size)
				break;

			ret = madvise(addr + PAGE_SIZE * i,
						PAGE_SIZE, MADV_DONTNEED);
			if (ret < 0) {
				pr_perror("madvise failed");
				return -1;
			}
			i++;
			nr_dropped++;
		}
	}

	cnt_add(CNT_PAGES_COMPARED, nr_compared);
	cnt_add(CNT_PAGES_SKIPPED_COW, nr_shared);
	cnt_add(CNT_PAGES_RESTORED, nr_restored);
	cnt_add(CNT_PAGES_PRE_FILLED, nr_skip_is_filled);
	cnt_add(CNT_PAGES_REMAP,nr_mremap);
	cnt_add(CNT_PAGES_COPY,nr_memcpy);

	pr_info("nr_restored_pages: %d\n", nr_restored);
	pr_info("nr_shared_pages:   %d\n", nr_shared);
	pr_info("nr_dropped_pages:   %d\n", nr_dropped);
	pr_info("nr_lazy:           %d\n", nr_lazy);
	pr_info("nr_pages_skip_isfilled %d\n",nr_skip_is_filled);

	return 0;

err_addr:
	pr_err("Page entry address %lx outside of VMA %lx-%lx\n",
	       va, (long)vma->e->start, (long)vma->e->end);
	return -1;
}

static int maybe_disable_thp(struct pstree_item *t, struct page_read *pr)
{
	struct _MmEntry *mm = rsti(t)->mm;

	/*
	 * There is no need to disable it if the page read doesn't
	 * have parent. In this case VMA will be empty until
	 * userfaultfd_register, so there would be no pages to
	 * collapse. And, once we register the VMA with uffd,
	 * khugepaged will skip it.
	 */
	if (!(opts.lazy_pages && page_read_has_parent(pr)))
		return 0;

	if (!kdat.has_thp_disable)
		pr_warn("Disabling transparent huge pages. "
			"It may affect performance!\n");

	/*
	 * temporarily disable THP to avoid collapse of pages
	 * in the areas that will be monitored by uffd
	 */
	if (prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) {
		pr_perror("Cannot disable THP");
		return -1;
	}
	if (!(mm->has_thp_disabled && mm->thp_disabled))
		rsti(t)->has_thp_enabled = true;

	return 0;
}

int merge_pme_list(struct pme_list *head){
	struct pme_list *A ,*B;
	A = head;
	if(A==NULL)return 0;
	B = A->next;
	if(B==NULL)return 0;

	while(A!=NULL && B!=NULL){
		if(A->end == B->start){
			A->end = B->end;
			A->next = B->next;
			free(B);
			return 1;
		}else{
			A =B;
			B =B->next;
		}
	}
	return 0;
}

void print_pme_list(struct pme_list *head){
	struct pme_list *tmp = head;

	while(tmp){
		pr_debug("Printing Merged list : start %p  end %p nr_pages %ld\n",(void *)tmp->start, (void *)tmp->end, (tmp->end -tmp->start)/4096);
		tmp = tmp->next;
	}
}

void free_pme_list(struct pme_list *head){
	struct pme_list *tmp = head;

	while(head){
		tmp =head;
		head = head->next;
		free(tmp);
	}
}

int prepare_mappings_parallel(int dir_fd, unsigned long process_id, int dump_no){
	
	int ret =-1;
	int page_fd =-1;
	unsigned long off_st=0;
	//int concide_case = -1;
	
	struct page_read pr;
	struct history_pme *node;
	struct history_pme *history_pme_tmp;
	struct pme_list *pme_tmp_list;
	void *addr = NULL;
	void *addr_tmp =  NULL;


	//First argument is process pid to be restored with which is just the sake of combatiblitiy.

	ret = open_page_read_parallel(dir_fd, process_id, &pr, PR_TASK);
	if(ret<=0)return -1;

	page_fd = img_raw_fd(pr.pi);


	//Why advance
	/*
		pr->curr_pme++;
		if (pr->curr_pme >= pr->nr_pmes)
			return 0;

		pr->pe = pr->pmes[pr->curr_pme];
		pr->cvaddr = pr->pe->vaddr;
	*/

	/*
	 * Copy the content of pmes array to global array So that we can 
	 * merge the consequetive mmappings into one
	 */



	if(dump_no == 1){
		
		for(int i=0;i< pr.nr_pmes; i++){				
			struct pme_list *node = (struct pme_list*)malloc(sizeof(struct pme_list));
			node->start = pr.pmes[i]->vaddr;
			node->end   = pr.pmes[i]->vaddr + (pr.pmes[i]->nr_pages * PAGE_SIZE);
			node->next 	= NULL;
			if(pme_list_head == NULL){
				pme_list_head = node;
				pme_list_tail = node;
			}else{
				pme_list_tail->next = node;
				pme_list_tail = node;
			}
			pr_debug("shubham Pmes : %p   , nr_of pages %d, has_in_flags %d, has_in_parent\n",(void *)pr.pmes[i]->vaddr, pr.pmes[i]->nr_pages, pr.pmes[i]->flags);


		}

		while(merge_pme_list(pme_list_head)){
			// print_pme_list(pme_list_head);
			// pr_debug("\n\n\n");
		}

		print_pme_list(pme_list_head);


		// redaing pages now to criu address space


		pme_tmp_list = pme_list_head;
		while(pme_tmp_list){
			
			size_t ret,size;
			ret  = 0;
			size = pme_tmp_list->end - pme_tmp_list->start;
			addr = mmap(NULL,size,PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0, 0);
			if(addr == MAP_FAILED){
				pr_debug("Mmap Failed\n");
				return -1;
			}
			addr_tmp = addr;
			while(size>0){
				ret = pread(page_fd, addr_tmp, size, off_st);
				pr_debug("Robust Read properly Actual size : %ld, Actual read :%ld\n",size,ret);

				off_st+=ret;
				size-=ret;
				addr_tmp = (void *)((unsigned long) addr_tmp + ret);

			}

			pr_debug("start addresss %p | size read %ld\n",addr,ret);


			//fill this entry to global history list
			node = (struct history_pme*)malloc(sizeof(struct history_pme));
			node->mapp_addr  = (uint64_t)addr;
			node->start      = pme_tmp_list->start;
			node->nr_pages   = (pme_tmp_list->end - pme_tmp_list->start)/PAGE_SIZE;
			node->end        = (node->start + (node->nr_pages * PAGE_SIZE));
			node->is_valid   = 1;
			node->is_matched = -1;
			node->next       = NULL;

			if(history_pme_head ==NULL){
				history_pme_head = node;
				history_pme_tail = node;
			}else{
				history_pme_tail->next = node;
				history_pme_tail = node;
			}


			pme_tmp_list = pme_tmp_list->next;
		}

	}
	else{
		//for consequetive dump


			/*
			 * free old pme list
			 *  free_pme_list(pme_list_head);
			 */
			free_pme_list(pme_list_head);
			pme_list_head = NULL;
			for(int i=0;i< pr.nr_pmes; i++){

				if(pr.pmes[i]->flags >=4){
					//if pages are present here						
					struct pme_list *node = (struct pme_list*)malloc(sizeof(struct pme_list));
					node->start = pr.pmes[i]->vaddr;
					node->end   = pr.pmes[i]->vaddr + (pr.pmes[i]->nr_pages * PAGE_SIZE);
					node->next	= NULL;

					if(pme_list_head == NULL){
						pme_list_head = node;
						pme_list_tail = node;
					}else{
						pme_list_tail->next = node;
						pme_list_tail = node;
					}
					pr_debug("shubham Pmes : %p   , nr_of pages %d, has_in_flags %d, has_in_parent\n",(void *)pr.pmes[i]->vaddr, pr.pmes[i]->nr_pages, pr.pmes[i]->flags);

				}
			

			}

			while(merge_pme_list(pme_list_head)){
				//  print_pme_list(pme_list_head);
				//  pr_debug("\n\n\n");
			}
			
			print_pme_list(pme_list_head);
			pr_debug("\n\n\n");


			pme_tmp_list 	= pme_list_head;


			while(pme_tmp_list){

				int case_occur =-1;
                //what an error you have to reintillize it for every node of pme_tmp_list
			    history_pme_tmp = history_pme_head;
				while(history_pme_tmp){
					//Handling case of overlap
					//case 1:
					if((history_pme_tmp->is_valid == 1) && pme_tmp_list->start >= history_pme_tmp->start && pme_tmp_list->end <= history_pme_tmp->end){
						/*
						 * Total over lap
						 * List 1: A|+++++++++++++++++++|B    history_pme_tmp
						 * List 2: 		C|+++++++++|D	      pme_tmp_list
						 * Condition if( C>= A && D<=B)
						 * 
						 * offset handling
						 * read_start_addr = C-A;
						 * read_size = D-C;
						 * 
						 */ 
						 unsigned long size,ret,addr_off_st,read_start;
						 pr_debug("CASE: A \n");
						 addr_off_st = 0;
						 read_start  = 0;
						 size = pme_tmp_list->end - pme_tmp_list->start;
						 //have to take care of mmaped address
						 addr_off_st = pme_tmp_list->start - history_pme_tmp->start;
						 read_start = history_pme_tmp->mapp_addr + addr_off_st ;

						 pr_debug("Trying to read the content at %p: %d:	%ld\n\n\n",(void *)read_start,page_fd,size);

						//  pr_debug("History Vma start %p  end %p  mapped_addr %p nr_pages %ld\n",(void *)history_pme_tmp->start,(void *)history_pme_tmp->end,(void *)history_pme_tmp->mapp_addr,history_pme_tmp->nr_pages);
						//  pr_debug("Orginal Vma start %p  end %p  nr_pages %ld\n",(void *)pme_tmp_list->start,(void *)pme_tmp_list->end,(pme_tmp_list->end - pme_tmp_list->start)/PAGE_SIZE);
						 
						//  pr_debug("pread args page_fd %d, addr %p, size %ld, off %ld addr_off %ld\n",page_fd,(void *)read_start,size,off_st,addr_off_st);
						 ret = pread(page_fd,(void *)read_start,size,off_st);
						 
						 if(ret != size){
							 history_pme_tmp->is_valid = 0;
							 pr_debug("\n\n\nCase A is not able to read succesfully Actual read %ld : Desired %ld \n\n\n",ret,size);
							 break;
						 }
						 pr_debug("Succefully override the pages in vma %p  nr_pages %ld\n",(void *)pme_tmp_list->start,ret/4096);
												 
						 //new_entry = 1;
						 case_occur = 1;
						 pr_debug("Case_occur  %d\n\n",case_occur);
						 break;
					}else if((history_pme_tmp->is_valid==1) && pme_tmp_list->start >= history_pme_tmp->start && pme_tmp_list->start < history_pme_tmp->end && pme_tmp_list->end > history_pme_tmp->end){
						/*
						 * Approach 5
						 * partial over lap
						 * List 1: A|+++++++++++++++++++|B    			history_pme_tmp
						 * List 2: 			C|+++++++++++++++++|D	    pme_tmp_list
						 * UPDATE
						 * List 1: E|++++++++++++++++++++++++++|F
						 * 
						 *  s1	Do mmap(C-D)
						 *  s2	Read fill (C-D)
						 * 	s3	Do mmap(E-F)
						 * 	s4	mremap(A into E)
						 *  s5	addr_offset  = C-A
						 * 	s6	mremap(C into (E+ addroffset))
						 * 	s7  update mmap_addr of history_list
						 *  s8 	free both A and C
						 */ 

						void *first_addr, *remap_addr;//, *offset_addr;
						uint64_t first_size, sec_size, third_size, addr_offst,ret;

						first_size = history_pme_tmp->end - history_pme_tmp->start;  //List 1
						sec_size   = pme_tmp_list->end - pme_tmp_list->start;		 //List 2
						third_size = pme_tmp_list->end - history_pme_tmp->start;	 //List mod

						remap_addr = mremap((void *)history_pme_tmp->mapp_addr,first_size,third_size,MREMAP_MAYMOVE);
						if((unsigned long)remap_addr !=-1){
							pr_debug("CASE BRemap Succesfull\n");
						}
						addr_offst = pme_tmp_list->start - history_pme_tmp->start;
						first_addr = (void *)((unsigned long)remap_addr + addr_offst);
						ret = pread(page_fd,first_addr,sec_size,off_st);
						if(ret != sec_size){
							pr_debug("Case B Unable to do pread successful ret %ld  size %ld\n",ret,sec_size);
							return -1;
						}						
						pr_debug("CASE B Succefully override the new map %p\n",remap_addr);


						// first_addr = mmap(NULL,sec_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						// if(first_addr== MAP_FAILED){
						// 	pr_debug("MMap failde for CASE D\n");
						// 	return -1;
						// }	
						

						// pr_debug("\n\n\nTrying to read the content at %p: %d:	%ld\n\n\n",first_addr,page_fd,sec_size);
						// ret = pread(page_fd,first_addr,sec_size,off_st);
						// if(ret != sec_size){
						// 	pr_debug("Case B Unable to do pread successful ret %ld  size %ld\n",ret,sec_size);
						// 	return -1;
						// }
						
						// sec_addr   = mmap(NULL,third_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						// if(sec_addr== MAP_FAILED){
						// 	pr_debug("MMap failde for CASE D\n");
						// 	return -1;
						// }						

						// remap_addr = mremap((void *)history_pme_tmp->mapp_addr,first_size,first_size,MREMAP_FIXED|MREMAP_MAYMOVE,sec_addr);
						// if(remap_addr != sec_addr){
						// 	pr_debug("Case B Unable to do 1st mremap successful\n");
						// }
						
						// addr_offst = pme_tmp_list->start - history_pme_tmp->start;
						// offset_addr = (void *)(addr_offst+(unsigned long)sec_addr);

						// remap_addr = mremap((void *)first_addr,sec_size,sec_size,MREMAP_FIXED|MREMAP_MAYMOVE,offset_addr);
						// if(remap_addr != offset_addr){
						// 	pr_debug("Case B Unable to do 2nd mremap successful\n");

						// }
						
						//munmap((void *)history_pme_tmp->mapp_addr,first_size);
						//munmap(first_addr,sec_size);
						history_pme_tmp->mapp_addr = (unsigned long)remap_addr;
						history_pme_tmp->end = history_pme_tmp->start + third_size;
						history_pme_tmp->nr_pages = (history_pme_tmp->end - history_pme_tmp->start)/4096;
						case_occur = 1;
						 pr_debug("Case_occur  %d\n\n",case_occur);

		
					}else if((history_pme_tmp->is_valid==1) && pme_tmp_list->start < history_pme_tmp->start && pme_tmp_list->end > history_pme_tmp->start && pme_tmp_list->end <= history_pme_tmp->end){
						/*
						 * Approach 5
						 * partial over lap
						 * List 1: 			A|+++++++++++++++++++|B    			history_pme_tmp
						 * List 2: 	C|++++++++++++++++|D	    				pme_tmp_list
						 * UPDATE
						 * List 1:  E|+++++++++++++++++++++++++++|F
						 * 
						 *  s1	Do mmap(C-D)
						 *  s2	Read fill (C-D)
						 * 	s3	Do mmap(E-F)
						 * 	s4	mremap(C into E)
						 *  s5	addr_offset  = A-C
						 * 	s6	mremap(A into (E+addr_offset))
						 * 	s7  update mmap_addr of history_list
						 *  s8 	free both A and C
						 */

						void *first_addr, *offset_addr;
						uint64_t first_size, sec_size, third_size, addr_offst,ret;

						first_size = history_pme_tmp->end - history_pme_tmp->start;  //List 1
						sec_size   = pme_tmp_list->end - pme_tmp_list->start;		 //List 2
						third_size = history_pme_tmp->end - pme_tmp_list->start;	 //List mod


						first_addr = mmap(NULL,third_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						if(first_addr== MAP_FAILED){
							pr_debug("MMap failde for CASE C\n");
							return -1;
						}

						ret = pread(page_fd,first_addr,sec_size,off_st);
						if(ret != sec_size){
							pr_debug("Case C Unable to do pread successful\n");
							return -1;
						}

						addr_offst = history_pme_tmp->start - pme_tmp_list->start;
						offset_addr = (void *)(addr_offst+(unsigned long)first_addr);

						memcpy(offset_addr,(void *)history_pme_tmp->mapp_addr,first_size);

						pr_debug("CASE C Succefully override the new map %p\n",first_addr);

						// first_addr = mmap(NULL,sec_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						// if(first_addr== MAP_FAILED){
						// 	pr_debug("MMap failde for CASE D\n");
						// 	return -1;
						// }
						
						// pr_debug("\n\n\nTrying to read the content at %p: %d:	%ld\n\n\n",first_addr,page_fd,sec_size);
						// ret = pread(page_fd,first_addr,sec_size,off_st);
						// if(ret != sec_size){
						// 	pr_debug("Case C Unable to do pread successful\n");
						// 	return -1;
						// }
						
						// sec_addr   = mmap(NULL,third_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						// if(sec_addr== MAP_FAILED){
						// 	pr_debug("MMap failde for CASE D\n");
						// 	return -1;
						// }

						// remap_addr = mremap(first_addr,sec_size,sec_size,MREMAP_FIXED|MREMAP_MAYMOVE,sec_addr);
						// if(remap_addr != sec_addr){
						// 	pr_debug("Case C Unable to do 1st mremap successful\n");
						// }
						
						// addr_offst = history_pme_tmp->start - pme_tmp_list->start;
						// offset_addr = (void *)(addr_offst+(unsigned long)sec_addr);

						// remap_addr = mremap((void *)history_pme_tmp->mapp_addr,sec_size,sec_size,MREMAP_FIXED|MREMAP_MAYMOVE,offset_addr);
						// if(remap_addr != offset_addr){
						// 	pr_debug("Case C Unable to do 2nd mremap successful\n");

						// }
						
						munmap((void *)history_pme_tmp->mapp_addr,first_size);
						// munmap(first_addr,sec_size);
						history_pme_tmp->mapp_addr = (unsigned long)first_addr;
						history_pme_tmp->start = pme_tmp_list->start;
						history_pme_tmp->end = history_pme_tmp->start + third_size;
						history_pme_tmp->nr_pages = (history_pme_tmp->end - history_pme_tmp->start)/4096;
						case_occur = 1;
						 pr_debug("Case_occur  %d\n\n",case_occur);

					}

					history_pme_tmp = history_pme_tmp->next;
				}

					if(case_occur == -1){
						/*
						 * Case D
						 * Here there is no case of overlapping will occured so
						 * that means ita new vma we should directly add into history list
						 * 
						 * List2 : C|+++++++++++++++++++++++|D
						 * 
						 * s1: mmap(C-D)
						 * s2: add it to history list
						 *
						 */

						unsigned long sec_size;
						void *first_addr;

						sec_size   = pme_tmp_list->end - pme_tmp_list->start;

						pr_debug("Case Occur : %d\n\n",case_occur);
						first_addr = mmap(NULL,sec_size,PROT_WRITE|PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
						if(first_addr== MAP_FAILED){
							pr_debug("MMap failde for CASE D\n");
							return -1;
						}

						node = (struct history_pme*)malloc(sizeof(struct history_pme));
						node->mapp_addr  = (uint64_t)first_addr;
						node->start      = pme_tmp_list->start;
						node->nr_pages   = (pme_tmp_list->end - pme_tmp_list->start)/PAGE_SIZE;
						node->end        = (node->start + (node->nr_pages * PAGE_SIZE));
						node->is_valid   = 1;
						node->is_matched = -1;
						node->next       = NULL;

						if(history_pme_head ==NULL){
							history_pme_head = node;
							history_pme_tail = node;
						}else{
							history_pme_tail->next = node;
							history_pme_tail = node;
						}
						
					}

				off_st += (pme_tmp_list->end - pme_tmp_list->start);

				pme_tmp_list = pme_tmp_list->next;
			}

	}



	// for(int i=0;i<pr.nr_pmes;i++){

	// 	unsigned long size = ((unsigned long)pr.pmes[i]->nr_pages) * PAGE_SIZE;
	// 	/*
	// 		PE_PARENT  1<<0
	// 		PE_LAZY    1<<1
	// 		PE_PRESENT 1<<2
	// 	*/

	// 	if(pr.pmes[i]->flags>=4){
	// 		//present


	// 		/*
	// 		 * For consecutive pre dump we have to make x vmas data valid like if uptdate happend
	// 		 * in consecutive predump we have to keep overwrite the vma content.
	// 		 * and if there is new entry in pagemap we have to add new vma to the list of x vmas
	// 		 * there can be four case of overlap that we have to handle to make vma data valid
	// 		 * 
	// 		 *  case 1:
	// 		 *  |+++++++++old+++++++++|
	// 		 * 		|------new----|
	// 		 * 
	// 		 *  case 2:
	// 		 *  		|+++++++++old+++++++|
	// 		 *  |-------new------|
	// 		 * 
	// 		 *  case 3:
	// 		 * 	|+++++++++old++++++++|
	// 		 *               |---------new-------|
	// 		 *  
	// 		 *  case 4:
	// 		 *  |--------new-------| 
	// 		 * 	
	// 		 * 
	// 		 */


	// 		if(dump_no == 1){
	// 			size_t ret=0;
	// 			addr = mmap(NULL,size,PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE,0, 0);
	// 			ret = pread(page_fd, addr, size, off_st);
	// 			if(size!=ret){
	// 				pr_debug("Not able to read properly Actual size : %ld, Actual read :%ld\n",size,ret);
	// 				continue;
	// 				//skipping this read
	// 			}
	// 			//Increasing offset for next pageread
	// 			off_st+=size;
	// 			pr_debug("start addresss %p | size read %ld\n",addr,ret);


	// 			//fill this entry to global history list
	// 			node = (struct history_pme*)malloc(sizeof(struct history_pme));
	// 			node->mapp_addr  = (void *)addr;
	// 			node->vaddr      = (void *)pr.pmes[i]->vaddr;
	// 			node->nr_pages   = pr.pmes[i]->nr_pages;
	// 			node->end        = (void *)((unsigned long)node->vaddr + (node->nr_pages * PAGE_SIZE));
	// 			node->is_valid   = 1;
	// 			node->is_matched = -1;
	// 			node->next       = NULL;

	// 			if(history_pme_head ==NULL){
	// 				history_pme_head = node;
	// 				history_pme_tail = node;
	// 			}else{
	// 				history_pme_tail->next = node;
	// 				history_pme_tail = node;
	// 			}

	// 		}
	// 		else{
	// 			//for consecutive pre-dumps

	// 			struct history_pme *tmp = history_pme_head;
	// 			unsigned long end;
	// 			int new_entry;
	// 			new_entry = -1;
	// 			end = (pr.pmes[i]->nr_pages*PAGE_SIZE + pr.pmes[i]->vaddr);

	// 			pr_debug("Else 2nd pre-dump \n\n\n");

	// 			while(tmp){

	// 				//case a : see cases info in above comment
 	// 				if((tmp->is_valid == 1) && pr.pmes[i]->vaddr >= (unsigned long)tmp->vaddr && end <= (unsigned long)tmp->end){
						
	// 					 unsigned long size,ret,addr_off_st,read_start;
	// 					 pr_debug("CASE: A \n");
	// 					 addr_off_st = 0;
	// 					 read_start  = 0;
	// 					 size = pr.pmes[i]->nr_pages*PAGE_SIZE;
	// 					 //have to take care of mmaped address
	// 					 addr_off_st = pr.pmes[i]->vaddr - (unsigned long)tmp->vaddr;
	// 					 read_start = (unsigned long)tmp->mapp_addr + addr_off_st ;

	// 					 ret = pread(page_fd,(void *)read_start,size,off_st);
						 
	// 					 if(ret != size){
	// 						 tmp->is_valid = 0;
	// 						 pr_debug("\n\n\nCase A is valid 0\n\n\n");
	// 						 break;
	// 					 }
	// 					 pr_debug("Succefully override the pages in vma %p  nr_pages %ld\n",(void *)pr.pmes[i]->vaddr,ret/4096);
												 
	// 					 new_entry = 1;
	// 					 break;
	// 				 }
	// 				//case b 
 	// 				if((tmp->is_valid==1) && pr.pmes[i]->vaddr < (unsigned long)tmp->vaddr && end > (unsigned long)tmp->vaddr && end <= (unsigned long)tmp->end){
						 
	// 					 unsigned long size,ret,addr_off_st;
	// 					 pr_debug("CASE: B \n");
	// 					 addr_off_st = (unsigned long)tmp->vaddr - pr.pmes[i]->vaddr;
	// 					 size = pr.pmes[i]->nr_pages*PAGE_SIZE - addr_off_st;
	// 					 off_st += addr_off_st;
	// 					 //have to take care of mmaped address
	// 					 //addr_off_st =(unsigned long)tmp->vaddr - pr.pmes[i]->vaddr;
	// 					 ret = pread(page_fd,(void *)tmp->mapp_addr,size,off_st);
	// 					 if(ret != size){
	// 						 tmp->is_valid = 0;
	// 						 pr_debug("\n\n\nCase B is valid 0\n\n\n");

	// 						 off_st-=addr_off_st;
	// 						 continue;
	// 					 }
	// 					 //Reset the offset bc in end we are incrementing it anyway
	// 					 off_st-=addr_off_st;

	// 					 pr_debug("Succefully override the pages in vma %p  nr_pages %ld\n",(void *)pr.pmes[i]->vaddr,ret/4096);
	// 					 new_entry     = 1;
	// 				 }
	// 				//case c 
 	// 				if((tmp->is_valid==1) && pr.pmes[i]->vaddr >= (unsigned long)tmp->vaddr &&pr.pmes[i]->vaddr < (unsigned long)tmp->end && end > (unsigned long)tmp->end){
 						 
	// 					 unsigned long size,ret,addr_off_st,read_start;
	// 					 pr_debug("CASE: C \n");
	// 					 addr_off_st = 0;
	// 					 //have to take care of mmaped address
	// 					 addr_off_st = pr.pmes[i]->vaddr - (unsigned long)tmp->vaddr;
	// 					 size = pr.pmes[i]->vaddr - (unsigned long)tmp->end;
	// 					 pr_debug("\n\n\n Size Reverse %ld lpme-> start %p cpme->start %p lpme->end %p cpme->end %p \n\n\n",size,tmp->vaddr,(void *)pr.pmes[i]->vaddr,tmp->end,(void *)end);
	// 					 size = (unsigned long)tmp->end - pr.pmes[i]->vaddr;
	// 					 read_start = (unsigned long)tmp->mapp_addr + addr_off_st;

	// 					 ret = pread(page_fd,(void *)read_start,size,off_st);
						 
	// 					 if(ret != size){
	// 						 tmp->is_valid = 0;
	// 						 pr_debug("\n\n\nCase C is valid 0\n\n\n");

	// 						 //reset the offset if not read properly
	// 						 //off_st-=ret;
	// 						// break;
	// 					 }
	// 					 pr_debug("Succefully override the pages in vma %p  nr_pages %ld\n",(void *)pr.pmes[i]->vaddr,ret/4096);
	// 					 new_entry     = 1;
	// 				 }


	// 				tmp=tmp->next;
	// 			}

	// 			if(new_entry == -1){
	// 				//new entry found add to list
	// 			}

	// 			off_st += (pr.pmes[i]->nr_pages *PAGE_SIZE);

	// 		}

	// 	}	
	// }


	//print linked list{



	history_pme_tmp = history_pme_head;
	while(history_pme_tmp){
		pr_debug("shubham printing list start : %p, end :%p   , nr_of pages %ld, valid %d\n",(void *)history_pme_tmp->start,(void*)history_pme_tmp->end,history_pme_tmp->nr_pages, history_pme_tmp->is_valid);
		history_pme_tmp=history_pme_tmp->next;
	}
	


	return ret;

}

int prepare_mappings(struct pstree_item *t)
{
	int ret = 0;
	void *addr;
	struct vm_area_list *vmas;
	struct page_read pr;
	//unsigned long buff;
	//unsigned long tot_write_byte,wbyte;
	//int file_to_fd;
	// struct vma_area *vma;
	// struct list_head *vmas_head;


	void *old_premmapped_addr = NULL;
	unsigned long old_premmapped_len;

	vmas = &rsti(t)->vmas;
	// vmas_head = &rsti(t)->vmas.h;
	if (vmas->nr == 0) /* Zombie */
		goto out;

	/* Reserve a place for mapping private vma-s one by one */
	// it gives random address
	timing_start(TIME_PREMAP);
	addr = mmap(NULL, vmas->rst_priv_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	//buff = (unsigned long)addr;
	//tot_write_byte = vmas->rst_priv_size;
	pr_debug("\n\n\n\n Large Contigous VMA addr %p\n\n\n\n",addr);
	if (addr == MAP_FAILED) {
		ret = -1;
		pr_perror("Unable to reserve memory (%lu bytes)", vmas->rst_priv_size);
		goto out;
	}

	old_premmapped_addr = rsti(t)->premmapped_addr;
	old_premmapped_len = rsti(t)->premmapped_len;
	rsti(t)->premmapped_addr = addr;
	rsti(t)->premmapped_len = vmas->rst_priv_size;

	ret = open_page_read(vpid(t), &pr, PR_TASK);
	if (ret <= 0)
		return -1;

	//thp = transparent huge pages
	if (maybe_disable_thp(t, &pr))
		return -1;

	pr.advance(&pr); /* shift to the 1st iovec */

	//agruments to function pstree, vmas list, addrress to mmap pointer , address of pr
	
	//this functions mmap the vmas with offset

	ret = premap_priv_vmas(t, vmas, &addr, &pr);
	timing_stop(TIME_PREMAP);
	if (ret < 0)
		goto out;

	pr.reset(&pr);

	//In case pieok == false it will fill the pages in this function
	timing_start(TIME_COPY_CONTENT);
	ret = restore_priv_vma_content(t, &pr);
	timing_stop(TIME_COPY_CONTENT);

	/*
	 * write all vma to file to later chk on diff
	 * 
	 */
    // wbyte =4096;
	// file_to_fd = open("/home/connoisseur/project/vma_file",O_CREAT|O_RDWR);
	// while(tot_write_byte>0){
	// 	wbyte = write(file_to_fd,(void *)buff,wbyte);
    //     if(wbyte<0){
    //         break;
    //     }
	// 	buff+=wbyte;
	// 	tot_write_byte-=wbyte;
	// }
    // close(file_to_fd);



	if (ret < 0)
		goto out;

	if (old_premmapped_addr) {
		ret = munmap(old_premmapped_addr, old_premmapped_len);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)",
					old_premmapped_addr, old_premmapped_len);
	}

	/*
	 * Not all VMAs were premmaped. Find out the unused tail of the
	 * premapped area and unmap it.
	 */
	old_premmapped_len = addr - rsti(t)->premmapped_addr;
	if (old_premmapped_len < rsti(t)->premmapped_len) {
		unsigned long tail;

		tail = rsti(t)->premmapped_len - old_premmapped_len;
		ret = munmap(addr, tail);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)", addr, tail);
		rsti(t)->premmapped_len = old_premmapped_len;
		pr_info("Shrunk premap area to %p(%lx)\n",
				rsti(t)->premmapped_addr, rsti(t)->premmapped_len);
	}

out:
	return ret;
}

bool vma_has_guard_gap_hidden(struct vma_area *vma)
{
	return kdat.stack_guard_gap_hidden && (vma->e->flags & MAP_GROWSDOWN);
}

/*
 * A guard page must be unmapped after restoring content and
 * forking children to restore COW memory.
 */
int unmap_guard_pages(struct pstree_item *t)
{
	struct vma_area *vma;
	struct list_head *vmas = &rsti(t)->vmas.h;

	if (!kdat.stack_guard_gap_hidden)
		return 0;

	list_for_each_entry(vma, vmas, list) {
		if (!vma_area_is(vma, VMA_PREMMAPED))
			continue;

		if (vma->e->flags & MAP_GROWSDOWN) {
			void *addr = decode_pointer(vma->premmaped_addr);

			if (munmap(addr - PAGE_SIZE, PAGE_SIZE)) {
				pr_perror("Can't unmap guard page");
				return -1;
			}
		}
	}

	return 0;
}

int open_vmas(struct pstree_item *t)
{
	int pid = vpid(t);
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	filemap_ctx_init(false);

	list_for_each_entry(vma, &vmas->h, list) {
		if (!vma_area_is(vma, VMA_AREA_REGULAR) || !vma->vm_open)
			continue;

		pr_info("Opening %#016"PRIx64"-%#016"PRIx64" %#016"PRIx64" (%x) vma\n",
				vma->e->start, vma->e->end,
				vma->e->pgoff, vma->e->status);

		if (vma->vm_open(pid, vma)) {
			pr_err("`- Can't open vma\n");
			return -1;
		}

		/*
		 * File mappings have vm_open set to open_filemap which, in
		 * turn, puts the VMA_CLOSE bit itself. For all the rest we
		 * need to put it by hands, so that the restorer closes the fd
		 */
		if (!(vma_area_is(vma, VMA_FILE_PRIVATE) ||
					vma_area_is(vma, VMA_FILE_SHARED)))
			vma->e->status |= VMA_CLOSE;
	}

	filemap_ctx_fini();

	return 0;
}

static int prepare_vma_ios(struct pstree_item *t, struct task_restore_args *ta)
{
	struct cr_img *pages;

	/*
	 * We optimize the case when rsti(t)->vma_io is empty.
	 *
	 * This is useful for for remote images, where all VMAs are premapped
	 * (pr->pieok is false). This avoids re-opening the CR_FD_PAGES file,
	 * which could be no longer be available.
	 */
	if (list_empty(&rsti(t)->vma_io)) {
		ta->vma_ios = NULL;
		ta->vma_ios_n = 0;
		ta->vma_ios_fd = -1;
		return 0;
	}

	/*
	 * If auto-dedup is on we need RDWR mode to be able to punch holes in
	 * the input files (in restorer.c)
	 */
	pages = open_image(CR_FD_PAGES, opts.auto_dedup ? O_RDWR : O_RSTR,
				rsti(t)->pages_img_id);
	if (!pages)
		return -1;

	ta->vma_ios_fd = img_raw_fd(pages);
	return pagemap_render_iovec(&rsti(t)->vma_io, ta);
}

int prepare_vmas(struct pstree_item *t, struct task_restore_args *ta)
{
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	ta->vmas = (VmaEntry *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vmas_n = vmas->nr;

	list_for_each_entry(vma, &vmas->h, list) {
		VmaEntry *vme;

		vme = rst_mem_alloc(sizeof(*vme), RM_PRIVATE);
		if (!vme)
			return -1;

		/*
		 * Copy VMAs to private rst memory so that it's able to
		 * walk them and m(un|re)map.
		 */
		*vme = *vma->e;

		if (vma_area_is(vma, VMA_PREMMAPED))
			vma_premmaped_start(vme) = vma->premmaped_addr;
	}

	return prepare_vma_ios(t, ta);
}