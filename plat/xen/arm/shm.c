/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdio.h>
#include <string.h>
#include <libfdt.h>
#include <common/pt.h>
#include <xen-arm/os.h>
#include <xen-arm/mm.h>
#include <xen-arm/shm.h>
#include <uk/essentials.h>
#include <uk/paging.h>
#include <uk/print.h>
#include <uk/spinlock.h>

#define DT_SHM_COMPAT "xen,shared-memory-v1"
#define DT_GET_NEXT_SHM(dtb, node) \
	fdt_node_offset_by_compatible(dtb, node, DT_SHM_COMPAT)

/* Attributes of an shm page, write access is added by uk_shm_map() */
#define SHM_PT_ATTR_RO							\
	(XENPLAT_PT_ATTR_MEM & ~(UK_PAGING_PAGE_ATTR_PROT_WRITE |	\
				 UK_PAGING_PAGE_ATTR_PROT_EXEC))

/* Always use L3 page tables to allow page-granularity permission control */
static lpae_t shm_l2_pgtable[Ln_ENTRIES] __align(PAGE_SIZE);
static lpae_t shm_l3_pgtable[SHM_NR_L3_TABLES][Ln_ENTRIES] __align(PAGE_SIZE);

static __vaddr_t shm_next_va = FIX_SHM_START;

static struct uk_shm_entry shm_entries[CONFIG_XEN_SHM_MAX_ENTRIES];
static int shm_count;

static struct uk_spinlock shm_lock = UK_SPINLOCK_INITIALIZER();

/* Puts the shm page tables into the hierarchy */
static int shm_pt_init(void)
{
	__vaddr_t vaddr = FIX_SHM_START;
	unsigned int i;
	int rc;

	/* The L2 table goes into the L1 entry of the shm window */
	rc = xenplat_pt_link(vaddr, UK_PAGING_PT_LEVELS - 1, shm_l2_pgtable);
	if (unlikely(rc))
		return rc;

	/* One L3 table per 2MB block of the shm window */
	for (i = 0; i < SHM_NR_L3_TABLES; i++) {
		rc = xenplat_pt_link(vaddr, UK_PAGING_PAGE_LARGE_LEVEL,
				     shm_l3_pgtable[i]);
		if (unlikely(rc))
			return rc;

		vaddr += SZ_2M;
	}

	return 0;
}

static __vaddr_t shm_map_region(__paddr_t paddr, __sz size)
{
	__vaddr_t vaddr;
	int rc;

	if (size > FIX_SHM_TOP - shm_next_va) {
		uk_pr_err("%s: mapping exceeds available VA space\n",
			  __func__);
		return 0;
	}

	vaddr = shm_next_va;
	rc = xenplat_pt_map(vaddr, paddr, size >> PAGE_SHIFT,
			    UK_PAGING_PAGE_LEVEL, SHM_PT_ATTR_RO);
	if (unlikely(rc)) {
		uk_pr_err("%s: could not map pa=0x%lx: %d\n",
			  __func__, (unsigned long)paddr, rc);
		return 0;
	}

	shm_next_va += size;

	return vaddr;
}

void shm_init(void)
{
	const void *dtb = HYPERVISOR_dtb;
	int node, lenp, parent, naddr, nsz;
	const fdt64_t *reg;
	__u64 paddr, size;
	__vaddr_t vaddr;
	const char *id;
	int rc;

	rc = shm_pt_init();
	if (unlikely(rc)) {
		uk_pr_err("%s: could not link page tables: %d\n",
			  __func__, rc);
		return;
	}

	node = -1;
	while ((node = DT_GET_NEXT_SHM(dtb, node)) >= 0) {
		parent = fdt_parent_offset(dtb, node);
		if (parent < 0) {
			uk_pr_err("%s: cannot find parent node\n", __func__);
			continue;
		}
		naddr = fdt_address_cells(dtb, parent);
		nsz = fdt_size_cells(dtb, parent);
		if (naddr != 2 || nsz != 2) {
			uk_pr_err("%s: unsupported cells: addr=%d size=%d\n",
				  __func__, naddr, nsz);
			return;
		}

		reg = fdt_getprop(dtb, node, "reg", &lenp);
		if (!reg || lenp < (int)(sizeof(fdt64_t) * 2)) {
			uk_pr_err("%s: bad reg property\n", __func__);
			continue;
		}

		paddr = fdt64_ld(&reg[0]);
		size = fdt64_ld(&reg[1]);

		if ((paddr & ~PAGE_MASK) || (size & ~PAGE_MASK) || !size) {
			uk_pr_err("%s: region not page-aligned pa=0x%lx sz=0x%lx, skipping\n",
				  __func__, (unsigned long)paddr,
				  (unsigned long)size);
			continue;
		}

		id = fdt_getprop(dtb, node, "xen,id", NULL);
		if (!id) {
			uk_pr_err("%s: missing xen,id, skipping\n", __func__);
			continue;
		}
		if (strlen(id) >= UK_SHM_ID_MAXLEN) {
			uk_pr_err("%s: id '%s' exceeds max len (+null) (%d), skipping\n",
				  __func__, id, UK_SHM_ID_MAXLEN);
			continue;
		}

		if (shm_count >= CONFIG_XEN_SHM_MAX_ENTRIES) {
			uk_pr_err("%s: too many shm entries\n", __func__);
			return;
		}

		vaddr = shm_map_region(paddr, size);
		if (!vaddr)
			return;

		shm_entries[shm_count].vaddr = vaddr;
		shm_entries[shm_count].size = size;
		snprintf(shm_entries[shm_count].id, UK_SHM_ID_MAXLEN,
			 "%s", id);
		shm_count++;

		uk_pr_debug("%s: shm id=%s pa=0x%lx sz=0x%lx va=0x%lx\n",
			    __func__, id, (unsigned long)paddr,
			    (unsigned long)size, vaddr);
	}
}

void *uk_shm_map(const char *id, __sz len, __u16 perm, __off offset)
{
	struct uk_shm_entry *entry = __NULL;
	unsigned long flags;
	unsigned long attr;
	void *result;
	int rc;
	int i;

	if (!id) {
		uk_pr_err("%s: id is NULL\n", __func__);
		return __NULL;
	}

	if (len == 0) {
		uk_pr_err("%s: len is 0 for id='%s'\n", __func__, id);
		return __NULL;
	}

	if (((unsigned long)offset & ~PAGE_MASK) ||
	    (len & ~PAGE_MASK)) {
		uk_pr_err("%s: offset/len not page-aligned id='%s' off=0x%lx len=0x%lx\n",
			  __func__, id, (unsigned long)offset,
			  (unsigned long)len);
		return __NULL;
	}

	uk_spin_lock_irqsave(&shm_lock, flags);

	for (i = 0; i < shm_count; i++) {
		if (strncmp(shm_entries[i].id, id, UK_SHM_ID_MAXLEN) == 0) {
			entry = &shm_entries[i];
			break;
		}
	}
	if (!entry) {
		uk_pr_err("%s: id '%s' not found\n", __func__, id);
		uk_spin_unlock_irqrestore(&shm_lock, flags);
		return __NULL;
	}

	if ((__sz)offset + len > entry->size) {
		uk_pr_err("%s: bounds check failed id='%s' off=0x%lx len=0x%lx size=0x%lx\n",
			  __func__, id, (unsigned long)offset,
			  (unsigned long)len, (unsigned long)entry->size);
		uk_spin_unlock_irqrestore(&shm_lock, flags);
		return __NULL;
	}

	/*
	 * Per-call permission: each call unconditionally sets
	 * the requested access. (e.g. RW → RO → RW supported)
	 */
	attr = SHM_PT_ATTR_RO;
	if (!(perm & UK_SHM_RO))
		attr |= UK_PAGING_PAGE_ATTR_PROT_WRITE;

	result = (void *)(entry->vaddr + (__sz)offset);

	rc = xenplat_pt_set_attr((__vaddr_t)result, len >> PAGE_SHIFT,
				 UK_PAGING_PAGE_LEVEL, attr);
	if (unlikely(rc)) {
		uk_pr_err("%s: could not set permissions id='%s': %d\n",
			  __func__, id, rc);
		result = __NULL;
	}

	uk_spin_unlock_irqrestore(&shm_lock, flags);

	return result;
}
