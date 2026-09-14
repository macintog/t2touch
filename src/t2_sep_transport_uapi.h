/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef T2_SEP_TRANSPORT_UAPI_H
#define T2_SEP_TRANSPORT_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define T2_AKS_IOC_MAGIC 0xa7

struct t2_aks_ioc_exchange {
	__u8 operation;
	__s8 sep_status;
	__u8 reserved0[2];
	__u32 request_length;
	__u32 response_capacity;
	__u32 response_length;
	__u64 request;
	__u64 response;
};

struct t2_aks_ioc_info {
	__u8 connection_generation[16];
	__u32 flags;
	__u32 header_version;
	__u32 provisioning_phase;
	__u32 stable_absence_count;
};

struct t2_aks_ioc_replacement {
	__u8 old_account_uuid[16];
	__u8 new_account_uuid[16];
	__u8 activation_material[16];
	__u64 session;
	__u32 phase;
	__u32 reserved0;
};

#define T2_AKS_INFO_F_OOL_REGISTERED          (1U << 0)
#define T2_AKS_INFO_F_ACM_REGISTERED          (1U << 1)
/* Bit 2 is reserved after retiring the direct-PCI xART experiment. */
#define T2_AKS_INFO_F_XART_UUID_PUBLISHED     (1U << 2)
/* Retired D127: bridgeOS, not the raw PCI transport, launches versioned apps. */
#define T2_AKS_INFO_F_VERSIONED_APP_SELECTED  (1U << 3)
#define T2_AKS_INFO_F_PROVISIONING_ENABLED    (1U << 4)
#define T2_AKS_INFO_F_PROVISIONING_POISONED   (1U << 5)
#define T2_AKS_INFO_F_INVENTORY_ONLY          (1U << 6)
#define T2_AKS_INFO_F_PASSWORD_BOUND          (1U << 7)
#define T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE   (1U << 8)
#define T2_AKS_INFO_F_RUNTIME_POISONED        (1U << 9)
#define T2_AKS_INFO_F_IDENTITY_SECRET_SET     (1U << 10)
#define T2_AKS_INFO_F_REPLACEMENT_ENABLED     (1U << 11)
#define T2_AKS_INFO_F_REPLACEMENT_ARMED       (1U << 12)

#define T2_AKS_PROVISIONING_PHASE_IDLE        0U
#define T2_AKS_PROVISIONING_PHASE_CREATED     1U
#define T2_AKS_PROVISIONING_PHASE_COMPLETE    2U

#define T2_AKS_REPLACEMENT_PHASE_NONE         0U
#define T2_AKS_REPLACEMENT_PHASE_DELETE       1U
#define T2_AKS_REPLACEMENT_PHASE_CREATE       2U
#define T2_AKS_REPLACEMENT_PHASE_RECOVER      3U

#define T2_AKS_IOC_EXCHANGE \
	_IOWR(T2_AKS_IOC_MAGIC, 0, struct t2_aks_ioc_exchange)
#define T2_AKS_IOC_GET_INFO \
	_IOR(T2_AKS_IOC_MAGIC, 1, struct t2_aks_ioc_info)
#define T2_AKS_IOC_ARM_REPLACEMENT \
	_IOW(T2_AKS_IOC_MAGIC, 2, struct t2_aks_ioc_replacement)
#define T2_ACM_IOC_MAGIC 0xac

struct t2_acm_ioc_exchange {
	__u8 request_code;
	__u8 reserved0[3];
	__u32 request_length;
	__u32 response_capacity;
	__u32 response_length;
	__u32 request_info;
	__u32 response_info;
	__u64 generation;
	__u64 request;
	__u64 response;
};

struct t2_acm_ioc_info {
	__u64 generation;
	__u32 capacity;
	__u32 flags;
};

#define T2_ACM_INFO_F_POISONED (1U << 0)

#define T2_ACM_IOC_EXCHANGE \
	_IOWR(T2_ACM_IOC_MAGIC, 0, struct t2_acm_ioc_exchange)
#define T2_ACM_IOC_GET_INFO \
	_IOR(T2_ACM_IOC_MAGIC, 1, struct t2_acm_ioc_info)

#endif
