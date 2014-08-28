#pragma once

#pragma pack(push,1)

#define QCOW_VERSION_1 1
#define QCOW_VERSION_2 2
#define QCOW_VERSION_3 3

#define QCOW_MAGIC 0x514649fb /*  'Q', 'F', 'I' followed by 0xfb. */

struct qcow_header {
	__be32 magic;
	__be32 version;

	__be64 backing_file_offset;
	__be32 backing_file_size;

	__be32 cluster_bits;
	__be64 size;
	__be32 crypt_method;

	__be32 l1_size;
	__be64 l1_table_offset;

	__be64 refcount_table_offset;
	__be32 refcount_table_clusters;

	__be32 nb_snapshots;
	__be64 snapshots_offset;
};

inline __u32 qcow_header_cluster_bits(struct qcow_header *header)
{
	return be32_to_cpu(header->cluster_bits); 
}

inline __u64 qcow_header_size(struct qcow_header *header)
{
	return be64_to_cpu(header->size); 
}

inline __u32 qcow_header_version(struct qcow_header *header)
{
	return be32_to_cpu(header->version); 
}

inline __u32 qcow_header_magic(struct qcow_header *header)
{
	return be32_to_cpu(header->magic); 
}

inline __u32 qcow_header_l1_size(struct qcow_header *header)
{
	return be32_to_cpu(header->l1_size); 
}

inline __u64 qcow_header_l1_table_offset(struct qcow_header *header)
{
	return be64_to_cpu(header->l1_table_offset); 
}


inline __u64 qcow_header_refcount_table_offset(struct qcow_header *header)
{
	return be64_to_cpu(header->refcount_table_offset); 
}

inline __u32 qcow_header_refcount_table_clusters(struct qcow_header *header)
{
	return be32_to_cpu(header->refcount_table_clusters); 
}

struct qcow_snapshot_header {
      /* header is 8 byte aligned */
      __be64 l1_table_offset;

      __be32 l1_size;
      __be16 id_str_size;
      __be16 name_size;

      __be32 date_sec;
      __be32 date_nsec;

      __be64 vm_clock_nsec;

      __be32 vm_state_size;
      __be32 extra_data_size; /* for extension */
      /* extra data follows */
      /* id_str follows */
      /* name follows  */
} qcow_snapshot_header;

struct qcow_index {
	__be64	value;
};

#define QCOW_INDEX_COPIED_BIT		63
#define QCOW_INDEX_COMPRESSED_BIT	62

inline unsigned long qcow_index_offset(struct qcow_index *index)
{
	unsigned long offset = be64_to_cpu(index->value);
	offset &= ~(1UL << QCOW_INDEX_COPIED_BIT);
	offset &= ~(1UL << QCOW_INDEX_COMPRESSED_BIT);
	
	return offset;
}

inline void qcow_index_set(struct qcow_index *index, unsigned long offset, bool copied, bool compressed)
{
	unsigned long value = offset;
	if (copied)
		value |= (1UL << QCOW_INDEX_COPIED_BIT);
	if (compressed)
		value |= (1UL << QCOW_INDEX_COMPRESSED_BIT);
	index->value = cpu_to_be64(value);
	return;
}

#define QCOW_INDEX_BITS 3 

struct qcow_cluster_ref {
	__be16	count;
};

#pragma pack(pop)
