// SPDX-License-Identifier: GPL-2.0-only
/*
 * Staged Intel T2 SEP mailbox/OOL transport bring-up.
 *
 * The default mode maps BAR4 and reports status only.  Setting register_ool=1
 * explicitly enables bus mastering, allocates the two 16 KiB AppleKeyStore
 * endpoint-7 buffers, and registers them through SEP endpoint 0.  It does not
 * issue an AppleKeyStore operation.
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/capability.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <linux/ctype.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/hex.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>

#include "t2_acm_lifecycle.h"
#include "t2_aks_protocol.h"
#include "t2_sep_transport_uapi.h"

static_assert(sizeof(struct t2_acm_ioc_exchange) == 48);
static_assert(sizeof(struct t2_acm_ioc_info) == 16);
static_assert(sizeof(struct t2_aks_ioc_exchange) == 32);
static_assert(sizeof(struct t2_aks_ioc_info) == 32);

#define T2_SEP_VENDOR_ID            0x106b
#define T2_SEP_DEVICE_ID            0x1802
#define T2_SEP_MAILBOX_BAR          4
#define T2_SEP_BAR_MIN_SIZE         0x10000

#define T2_SEP_INBOX_STATUS         0x0108
#define T2_SEP_OUTBOX_STATUS        0x010c
#define T2_SEP_INBOX_DATA           0x0810
#define T2_SEP_OUTBOX_DATA          0x0820
#define T2_SEP_INBOX_EMPTY          BIT(17)
#define T2_SEP_OUTBOX_FULL          BIT(16)

/*
 * AppleSEPIntelIOP::startCPUGated() on Intel T2 performs these three BAR4
 * writes, in order, after its two interrupt event sources are enabled.  The
 * names deliberately describe only the observed behavior: the public
 * register semantics are not known yet.
 */
#define T2_SEP_APPLE_START_ZERO     0x8040
#define T2_SEP_APPLE_START_ONE      0x8048
#define T2_SEP_APPLE_START_KICK     0x8028
#define T2_SEP_APPLE_START_VALUE    5

#define T2_SEP_ENDPOINT_MASK        GENMASK(4, 0)
#define T2_SEP_CONTROL_ENDPOINT     0
#define T2_SEP_DISCOVERY_ENDPOINT   0xfd
#define T2_SEP_AKS_ENDPOINT         7
#define T2_SEP_ACM_ENDPOINT         10
#define T2_SEP_CMSG_SET_OOL_IN      2
#define T2_SEP_CMSG_SET_OOL_OUT     3
#define T2_SEP_OOL_SIZE             0x4000
#define T2_SEP_DMA_BITS             44
#define T2_SEP_TIMEOUT_US           (5 * USEC_PER_SEC)
#define T2_SEP_AKS_GET_CAPABILITIES 0x4d
#define T2_SEP_AKS_GET_PRIMARY_IDENTITY 0x51
#define T2_SEP_AKS_HEADER_V1        1
#define T2_SEP_AKS_HEADER_V2        2
#define T2_SEP_AKS_HEADER_V1_SIZE   0x48
#define T2_SEP_AKS_HEADER_V2_SIZE   0x50
#define T2_SEP_AKS_V1_WIRE_SIZE     (sizeof(u32) + T2_SEP_AKS_HEADER_V1_SIZE)
#define T2_SEP_AKS_V2_WIRE_SIZE     (sizeof(u32) + T2_SEP_AKS_HEADER_V2_SIZE)
#define T2_SEP_AKS_CAP_REQ_SIZE     0x5c
#define T2_SEP_AKS_MAX_BODY_SIZE    (T2_SEP_OOL_SIZE - T2_SEP_AKS_V2_WIRE_SIZE)
#define T2_SEP_AKS_CDHASH_SIZE      20
#define T2_SEP_AKS_CDHASH_HEX_SIZE  (T2_SEP_AKS_CDHASH_SIZE * 2)

struct t2_sep_message {
	u32 word[4];
};

enum t2_aks_provisioning_phase {
	T2_AKS_PROVISIONING_IDLE = T2_AKS_PROVISIONING_PHASE_IDLE,
	T2_AKS_PROVISIONING_CREATED = T2_AKS_PROVISIONING_PHASE_CREATED,
	T2_AKS_PROVISIONING_COMPLETE = T2_AKS_PROVISIONING_PHASE_COMPLETE,
};

struct t2_sep_transport {
	struct pci_dev *pdev;
	void __iomem *bar;
	void *ool_in;
	dma_addr_t ool_in_dma;
	void *ool_out;
	dma_addr_t ool_out_dma;
	bool ool_in_registered;
	bool ool_out_registered;
	void *acm_ool_in;
	dma_addr_t acm_ool_in_dma;
	void *acm_ool_out;
	dma_addr_t acm_ool_out_dma;
	bool acm_ool_in_registered;
	bool acm_ool_out_registered;
	struct miscdevice aks_miscdev;
	struct miscdevice acm_miscdev;
	struct mutex exchange_lock;
	atomic_t aks_opened;
	atomic_t acm_opened;
	u8 next_transaction;
	u32 aks_header_version;
	u8 aks_connection_generation[16];
	enum t2_aks_provisioning_phase aks_provisioning_phase;
	bool aks_provisioning_poisoned;
	u32 aks_stable_absence_count;
	u64 aks_absence_session;
	bool aks_password_bound;
	u8 aks_authorized_context[T2_ACM_CONTEXT_SIZE];
	bool acm_identity_secret_set;
	bool acm_identity_secret_externalized;
	bool acm_identity_secret_live;
	bool acm_identity_secret_consumed;
	bool acm_identity_target_created;
	u8 acm_identity_secret_context[T2_ACM_CONTEXT_SIZE];
	u32 acm_identity_secret_user_id;
	u64 aks_provisioning_session;
	u32 aks_provisioning_handle;
	bool aks_provisioning_handle_released;
	bool aks_provisioning_unload_attempted;
	bool aks_runtime_handle_active;
	bool aks_runtime_poisoned;
	bool aks_runtime_unload_attempted;
	bool aks_runtime_alias_bound;
	bool aks_runtime_unlock_attempted;
	u64 aks_runtime_session;
	u32 aks_runtime_handle;
	u32 aks_runtime_alias;
	u32 aks_replacement_phase;
	u64 aks_replacement_session;
	u8 aks_replacement_old_uuid[16];
	u8 aks_replacement_new_uuid[16];
	u8 aks_replacement_activation_material[16];
	bool aks_replacement_delete_attempted;
	bool aks_replacement_create_attempted;
	u64 acm_generation;
	bool acm_poisoned;
	bool acm_context_active;
	u8 acm_context[T2_ACM_CONTEXT_SIZE];
	u32 acm_context_user_id;
	bool misc_registered;
	bool acm_misc_registered;
};

static bool register_ool;
module_param(register_ool, bool, 0400);
MODULE_PARM_DESC(register_ool,
	"Register endpoint-7 coherent buffers with SEP (default: false)");

static bool probe_capabilities;
module_param(probe_capabilities, bool, 0400);
MODULE_PARM_DESC(probe_capabilities,
	"Issue one read-only AppleKeyStore capability query (default: false)");

static bool register_acm;
module_param(register_acm, bool, 0400);
MODULE_PARM_DESC(register_acm,
	"Register separate endpoint-10 ACM OOL buffers (default: false)");

static bool retain_runtime_handle;
module_param(retain_runtime_handle, bool, 0400);
MODULE_PARM_DESC(retain_runtime_handle,
	"Retain one bound compatibility runtime handle across root helper opens (default: false)");

static bool inventory_only;
module_param(inventory_only, bool, 0400);
MODULE_PARM_DESC(inventory_only,
	"Expose only read-only primary-identity inventory operation 0x51 (default: false)");

static bool enable_identity_provisioning;
module_param(enable_identity_provisioning, bool, 0400);
MODULE_PARM_DESC(enable_identity_provisioning,
	"Permit one kernel-owned create/export identity transaction per boot (experimental; default: false)");

static bool enable_identity_replacement;
module_param(enable_identity_replacement, bool, 0400);
MODULE_PARM_DESC(enable_identity_replacement,
	"Permit one explicitly armed identity replacement transaction per boot (experimental; default: false)");

static bool mirror_apple_start;
module_param(mirror_apple_start, bool, 0400);
MODULE_PARM_DESC(mirror_apple_start,
	"Mirror the Intel AppleSEPIntelIOP BAR4 start sequence (experimental; default: false)");

static uint aks_platform_asid;
module_param(aks_platform_asid, uint, 0600);
MODULE_PARM_DESC(aks_platform_asid,
	"macOS audit-session ID stamped into verify-secret AKS headers (default: 0)");

static ulong aks_platform_proc_uniqueid;
module_param(aks_platform_proc_uniqueid, ulong, 0600);
MODULE_PARM_DESC(aks_platform_proc_uniqueid,
	"Synthetic process unique ID stamped into verify-secret AKS headers (default: 0)");

static char aks_platform_cdhash[T2_SEP_AKS_CDHASH_HEX_SIZE + 1];
module_param_string(aks_platform_cdhash, aks_platform_cdhash,
		    sizeof(aks_platform_cdhash), 0600);
MODULE_PARM_DESC(aks_platform_cdhash,
	"Optional 40-hex-character caller CDHash stamped into verify-secret AKS headers");

struct t2_aks_header_v1 {
	u8 digest[16];
	__le32 version;
	__le64 usec_time;
	__le32 flags;
	__le64 clock_id;
	u8 platform_data[0x20];
} __packed;

static_assert(sizeof(struct t2_aks_header_v1) == T2_SEP_AKS_HEADER_V1_SIZE);

struct t2_aks_header_v2 {
	struct t2_aks_header_v1 v1;
	__le64 calendar_seconds;
} __packed;

static_assert(sizeof(struct t2_aks_header_v2) == T2_SEP_AKS_HEADER_V2_SIZE);

static int t2_aks_stamp_verify_platform_data(struct t2_aks_header_v2 *header)
{
	u8 cdhash[T2_SEP_AKS_CDHASH_SIZE];
	size_t length;
	int ret;

	put_unaligned_le64(aks_platform_proc_uniqueid,
			     header->v1.platform_data);
	put_unaligned_le32(aks_platform_asid,
			     header->v1.platform_data + sizeof(__le64));

	length = strnlen(aks_platform_cdhash, sizeof(aks_platform_cdhash));
	if (!length)
		return 0;
	if (length != T2_SEP_AKS_CDHASH_HEX_SIZE)
		return -EINVAL;
	ret = hex2bin(cdhash, aks_platform_cdhash, sizeof(cdhash));
	if (ret)
		return ret;
	memcpy(header->v1.platform_data + sizeof(__le64) + sizeof(__le32),
	       cdhash, sizeof(cdhash));
	memzero_explicit(cdhash, sizeof(cdhash));
	return 0;
}

static int t2_sep_wait_outbox(struct t2_sep_transport *sep)
{
	unsigned int waited;
	u32 inbox, outbox;

	for (waited = 0; waited < T2_SEP_TIMEOUT_US; waited += 100) {
		if (!(readl(sep->bar + T2_SEP_OUTBOX_STATUS) &
		      T2_SEP_OUTBOX_FULL))
			return 0;
		usleep_range(100, 200);
	}
	inbox = readl(sep->bar + T2_SEP_INBOX_STATUS);
	outbox = readl(sep->bar + T2_SEP_OUTBOX_STATUS);
	dev_warn(&sep->pdev->dev,
		 "mailbox send timeout: inbox=%#x outbox=%#x\n",
		 inbox, outbox);
	return -ETIMEDOUT;
}

static int t2_sep_send(struct t2_sep_transport *sep,
		       const struct t2_sep_message *message)
{
	int ret;

	ret = t2_sep_wait_outbox(sep);
	if (ret)
		return ret;

	/* AppleSEPIntelIOP posts the final word last; it is always zero. */
	writel(message->word[0], sep->bar + T2_SEP_OUTBOX_DATA + 0x0);
	writel(message->word[1], sep->bar + T2_SEP_OUTBOX_DATA + 0x4);
	writel(message->word[2], sep->bar + T2_SEP_OUTBOX_DATA + 0x8);
	writel(0, sep->bar + T2_SEP_OUTBOX_DATA + 0xc);
	return 0;
}

static int t2_sep_receive(struct t2_sep_transport *sep,
			  struct t2_sep_message *message)
{
	unsigned int waited;
	u32 inbox, outbox;

	for (waited = 0; waited < T2_SEP_TIMEOUT_US; waited += 100) {
		if (!(readl(sep->bar + T2_SEP_INBOX_STATUS) &
		      T2_SEP_INBOX_EMPTY)) {
			message->word[0] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x0);
			message->word[1] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x4);
			message->word[2] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x8);
			/* Reading the final word advances the hardware FIFO. */
			message->word[3] = readl(sep->bar + T2_SEP_INBOX_DATA + 0xc);
			return 0;
		}
		usleep_range(100, 200);
	}
	inbox = readl(sep->bar + T2_SEP_INBOX_STATUS);
	outbox = readl(sep->bar + T2_SEP_OUTBOX_STATUS);
	dev_warn(&sep->pdev->dev,
		 "mailbox receive timeout: inbox=%#x outbox=%#x\n",
		 inbox, outbox);
	return -ETIMEDOUT;
}

static void t2_sep_log_unrelated(struct t2_sep_transport *sep,
				 const struct t2_sep_message *message)
{
	u8 endpoint = message->word[0];
	u8 opcode = message->word[0] >> 16;
	u8 advertised_endpoint = message->word[0] >> 24;
	char service[5];
	unsigned int index;

	if (endpoint != T2_SEP_DISCOVERY_ENDPOINT || opcode != 0) {
		dev_dbg(&sep->pdev->dev,
			"queued unrelated mailbox message from endpoint %u\n",
			endpoint);
		return;
	}

	for (index = 0; index < 4; index++) {
		u8 byte = message->word[1] >> (index * 8);

		service[index] = isprint(byte) ? byte : '.';
	}
	service[4] = '\0';
	dev_info(&sep->pdev->dev,
		 "SEP discovery advertised endpoint %u service '%s'\n",
		 advertised_endpoint, service);
}

static void t2_sep_mirror_apple_start(struct t2_sep_transport *sep)
{
	/* Exact write order recovered from matching AppleSEPIntelIOP. */
	writel(0, sep->bar + T2_SEP_APPLE_START_ZERO);
	writel(1, sep->bar + T2_SEP_APPLE_START_ONE);
	writel(T2_SEP_APPLE_START_VALUE,
	       sep->bar + T2_SEP_APPLE_START_KICK);
	/* Flush posted PCI writes without reading an unknown control register. */
	readl(sep->bar + T2_SEP_INBOX_STATUS);
	dev_info(&sep->pdev->dev,
		 "mirrored Intel AppleSEPIntelIOP start sequence\n");
}

static void t2_sep_log_mailbox_timeout(struct t2_sep_transport *sep,
				       const char *protocol, u8 endpoint,
				       u8 opcode, const char *phase,
				       unsigned int skipped)
{
	u32 inbox_status = readl(sep->bar + T2_SEP_INBOX_STATUS);
	u32 outbox_status = readl(sep->bar + T2_SEP_OUTBOX_STATUS);

	/* Status bits and counts are sufficient; never log mailbox or OOL data. */
	dev_warn_ratelimited(&sep->pdev->dev,
		"%s endpoint %u opcode %#x %s timed out after %u unrelated messages (inbox_empty=%u outbox_full=%u)\n",
		protocol, endpoint, opcode, phase, skipped,
		!!(inbox_status & T2_SEP_INBOX_EMPTY),
		!!(outbox_status & T2_SEP_OUTBOX_FULL));
}

static int t2_sep_control(struct t2_sep_transport *sep, u8 target_endpoint,
			  u8 opcode, u8 tag, dma_addr_t dma, size_t size)
{
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	unsigned int skipped = 0;
	u8 endpoint;
	int ret;

	if (!IS_ALIGNED(dma, SZ_4K) || dma >> T2_SEP_DMA_BITS || size > U32_MAX)
		return -ERANGE;

	/* EP0 wire layout: endpoint, tag, opcode, target endpoint. */
	request.word[0] = T2_SEP_CONTROL_ENDPOINT | (tag << 8) |
		(opcode << 16) | (target_endpoint << 24);
	request.word[1] = lower_32_bits(dma >> PAGE_SHIFT);
	request.word[2] = size;

	ret = t2_sep_send(sep, &request);
	if (ret) {
		if (ret == -ETIMEDOUT)
			t2_sep_log_mailbox_timeout(sep, "control",
				target_endpoint, opcode, "send", 0);
		return ret;
	}

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret) {
			if (ret == -ETIMEDOUT)
				t2_sep_log_mailbox_timeout(sep, "control",
					target_endpoint, opcode, "reply", skipped);
			return ret;
		}

		endpoint = FIELD_GET(T2_SEP_ENDPOINT_MASK, reply.word[0]);
		if (endpoint == T2_SEP_CONTROL_ENDPOINT &&
		    ((reply.word[0] >> 8) & 0xff) == tag)
			break;

		/* Discovery names are public metadata; other payloads stay private. */
		t2_sep_log_unrelated(sep, &reply);
		if (++skipped == 32)
			return -EOVERFLOW;
	}

	/* OOL control replies retain the target in byte 3; word 1 is status. */
	if (reply.word[1]) {
		dev_err(&sep->pdev->dev,
			"control opcode %u returned SEP status %#x\n",
			opcode, reply.word[1]);
		return -EREMOTEIO;
	}
	return 0;
}

static int t2_aks_digest(void *message, size_t length)
{
	struct t2_aks_header_v1 *header = message + sizeof(__le32);
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 digest[SHA256_DIGEST_SIZE];
	u32 header_size;
	u32 version;
	int ret;

	if (length < sizeof(__le32) + sizeof(header->digest) + sizeof(header->version))
		return -EINVAL;
	header_size = get_unaligned_le32(message);
	version = le32_to_cpu(header->version);
	if ((version == T2_SEP_AKS_HEADER_V1 &&
	     header_size != T2_SEP_AKS_HEADER_V1_SIZE) ||
	    (version == T2_SEP_AKS_HEADER_V2 &&
	     header_size != T2_SEP_AKS_HEADER_V2_SIZE) ||
	    (version != T2_SEP_AKS_HEADER_V1 &&
	     version != T2_SEP_AKS_HEADER_V2) ||
	    length < sizeof(__le32) + header_size)
		return -EPROTO;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, (u8 *)header + sizeof(header->digest),
					 header_size - sizeof(header->digest));
	if (!ret)
		ret = crypto_shash_update(desc,
					 message + sizeof(__le32) + header_size,
					 length - sizeof(__le32) - header_size);
	if (!ret)
		ret = crypto_shash_final(desc, digest);
	if (!ret)
		memcpy(header->digest, digest, sizeof(header->digest));

	memzero_explicit(digest, sizeof(digest));
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static bool t2_aks_operation_allowed(u8 operation)
{
	switch (operation) {
	case 0x01: /* create_keybag: separately phase- and shape-gated */
	case 0x02: /* copy_keybag: separately phase- and owner-gated */
		return enable_identity_provisioning;
	case 0x49: /* invalidate only the armed replacement identity */
		return enable_identity_replacement;
	case 0x03: /* load_keybag */
	case 0x04: /* change_lock_state */
	case 0x05: /* unload only the kernel-recorded runtime handle */
	case 0x06: /* read-only copy_keybag_uuid */
	case 0x0d: /* make_system_keybag */
	case 0x18: /* credential-bearing device-state transition */
	case 0x19: /* get_device_state */
	case 0x21: /* bounded verify_secret_v1, with optional ACM context */
	case 0x23: /* get_configuration for one proven negative user alias */
	case T2_SEP_AKS_GET_CAPABILITIES:
	case T2_SEP_AKS_GET_PRIMARY_IDENTITY:
		return true;
	default:
		return false;
	}
}

static int t2_aks_exchange_locked(struct t2_sep_transport *sep, u8 operation,
				  const void *request_body,
				  size_t request_body_length,
				  u8 **response_body,
				  size_t *response_body_length,
				  s8 *sep_status_out)
{
	struct t2_aks_header_v2 *header;
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	size_t request_length;
	size_t wire_size;
	u32 header_size;
	u32 header_version;
	u16 reply_length;
	s8 reply_status;
	u8 transaction;
	unsigned int skipped = 0;
	int ret;

	*sep_status_out = 0;
	if (!t2_aks_operation_allowed(operation))
		return -EACCES;
	if (operation == 0x01 &&
	    !t2_aks_identity_create_v5_request_allowed(request_body,
						       request_body_length))
		return -EACCES;
	if (operation == 0x02 &&
	    !t2_aks_identity_copy_keybag_v1_request_allowed(request_body,
							    request_body_length))
		return -EACCES;
	if (operation == 0x49 &&
	    (sep->aks_replacement_phase != T2_AKS_REPLACEMENT_PHASE_DELETE ||
	     !t2_aks_identity_delete_request_matches(
		     request_body, request_body_length,
		     sep->aks_replacement_session,
		     sep->aks_replacement_old_uuid)))
		return -EACCES;
	if (operation == 0x03 &&
	    !t2_aks_load_keybag_request_allowed(request_body,
					 request_body_length) &&
	    !(sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_RECOVER &&
	      t2_aks_identity_open_request_matches(
		      request_body, request_body_length,
		      sep->aks_replacement_session,
		      sep->aks_replacement_new_uuid)))
		return -EACCES;
	if (operation == 0x04 &&
	    (!sep->aks_runtime_handle_active || sep->aks_runtime_poisoned ||
	     !sep->aks_runtime_alias_bound ||
	     (!t2_aks_unlock_target_request_matches(
		      request_body, request_body_length,
		      sep->aks_runtime_session, sep->aks_runtime_handle) &&
	      !t2_aks_unlock_target_request_matches(
		      request_body, request_body_length,
		      sep->aks_runtime_session, sep->aks_runtime_alias))))
		return -EACCES;
	if (operation == 0x05 &&
	    !(sep->aks_runtime_handle_active &&
	      t2_aks_unload_keybag_request_matches(
		      request_body, request_body_length,
		      sep->aks_runtime_session, sep->aks_runtime_handle)) &&
	    !(sep->aks_provisioning_phase == T2_AKS_PROVISIONING_COMPLETE &&
	      !sep->aks_provisioning_handle_released &&
	      t2_aks_unload_keybag_request_matches(
		      request_body, request_body_length,
		      sep->aks_provisioning_session,
		      sep->aks_provisioning_handle)))
		return -EACCES;
	if (operation == 0x06 &&
	    !t2_aks_copy_keybag_uuid_request_allowed(request_body,
						request_body_length) &&
	    !(sep->aks_runtime_handle_active &&
	      !sep->aks_runtime_poisoned &&
	      t2_aks_copy_keybag_uuid_request_matches(
		      request_body, request_body_length,
		      sep->aks_runtime_session, sep->aks_runtime_handle)) &&
	    !(sep->aks_provisioning_phase == T2_AKS_PROVISIONING_COMPLETE &&
	      !sep->aks_provisioning_poisoned &&
	      !sep->aks_provisioning_handle_released &&
	      t2_aks_copy_keybag_uuid_request_matches(
		      request_body, request_body_length,
		      sep->aks_provisioning_session,
		      sep->aks_provisioning_handle)))
		return -EACCES;
	if (operation == 0x0d &&
	    (!sep->aks_runtime_handle_active || sep->aks_runtime_poisoned ||
	     !t2_aks_bind_alias_request_matches(
		     request_body, request_body_length,
		     sep->aks_runtime_session, sep->aks_runtime_handle)))
		return -EACCES;
	if (operation == 0x18 &&
	    (!t2_aks_acm_unlock_request_allowed(request_body,
					       request_body_length) ||
	     !sep->aks_runtime_handle_active || sep->aks_runtime_poisoned ||
	     !sep->aks_runtime_alias_bound ||
	     t2_aks_wire_get_le32(request_body + 12) !=
		     sep->aks_runtime_alias ||
	     !sep->acm_context_active || sep->acm_poisoned ||
	     !t2_aks_identity_login_context_allowed(
		     request_body, request_body_length,
		     sep->acm_identity_secret_context,
		     sep->aks_authorized_context, sep->acm_context,
		     sep->acm_identity_secret_live,
		     sep->acm_identity_secret_consumed,
		     sep->acm_identity_target_created,
		     sep->aks_password_bound)))
		return -EACCES;
	if (operation == 0x19 &&
	    (!t2_aks_get_device_state_v1_request_allowed(
		     request_body, request_body_length) ||
	     (!t2_aks_special_alias(t2_aks_wire_get_le32(request_body + 12)) &&
	      !(sep->aks_runtime_handle_active &&
		!sep->aks_runtime_poisoned &&
		t2_aks_wire_get_le32(request_body + 12) ==
			sep->aks_runtime_handle))))
		return -EACCES;
	if (operation == T2_SEP_AKS_GET_CAPABILITIES &&
	    !t2_aks_capabilities_request_allowed(request_body,
						 request_body_length))
		return -EACCES;
	if (operation == T2_SEP_AKS_GET_PRIMARY_IDENTITY &&
	    !t2_aks_get_primary_identity_request_allowed(request_body,
							 request_body_length))
		return -EACCES;
	if (operation == 0x21 &&
	    !t2_aks_verify_secret_v1_request_allowed(request_body,
						      request_body_length))
		return -EACCES;
	if (operation == 0x21 &&
	    t2_aks_verify_secret_v1_identity_request_allowed(
		    request_body, request_body_length) &&
	    (!sep->aks_runtime_handle_active || sep->aks_runtime_poisoned ||
	     !sep->aks_runtime_alias_bound ||
	     !sep->acm_context_active || sep->acm_poisoned ||
	     !sep->acm_identity_secret_set ||
	     !sep->acm_identity_secret_externalized ||
	     !sep->acm_identity_secret_live ||
	     sep->acm_identity_secret_consumed ||
	     !sep->acm_identity_target_created ||
	     !t2_aks_verify_secret_v1_identity_secret_matches(
		     request_body, request_body_length,
		     sep->acm_identity_secret_context) ||
	     !t2_aks_verify_secret_v1_context_matches(
		     request_body, request_body_length, sep->acm_context) ||
	     !t2_aks_verify_secret_v1_identity_references_distinct(
		     request_body, request_body_length) ||
	     !t2_aks_verify_secret_v1_runtime_target_matches(
		     request_body, request_body_length,
		     sep->aks_runtime_session, sep->aks_runtime_handle)))
		return -EACCES;
	if (operation == 0x21 &&
	    t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
		    request_body, request_body_length) &&
	    (!sep->aks_runtime_handle_active || sep->aks_runtime_poisoned ||
	     !sep->aks_runtime_alias_bound ||
	     !sep->acm_context_active || sep->acm_poisoned ||
	     !sep->acm_identity_secret_set ||
	     !sep->acm_identity_secret_externalized ||
	     !sep->acm_identity_secret_live ||
	     sep->acm_identity_secret_consumed ||
	     sep->acm_identity_target_created ||
	     memcmp(sep->acm_context, sep->acm_identity_secret_context,
		    sizeof(sep->acm_context)) ||
	     !t2_aks_verify_secret_v1_identity_secret_matches(
		     request_body, request_body_length,
		     sep->acm_identity_secret_context) ||
	     !t2_aks_verify_secret_v1_runtime_target_matches(
		     request_body, request_body_length,
		     sep->aks_runtime_session, sep->aks_runtime_handle)))
		return -EACCES;
	if (operation == 0x23 &&
	    !t2_aks_get_configuration_request_allowed(request_body,
						       request_body_length))
		return -EACCES;
	if (request_body_length > T2_SEP_AKS_MAX_BODY_SIZE)
		return -EMSGSIZE;

	/* Capability negotiation is v1; all other calls use negotiated state. */
	header_version = operation == T2_SEP_AKS_GET_CAPABILITIES ?
		T2_AKS_HEADER_VERSION_1 : sep->aks_header_version;
	header_size = header_version == T2_AKS_HEADER_VERSION_2 ?
		T2_SEP_AKS_HEADER_V2_SIZE : T2_SEP_AKS_HEADER_V1_SIZE;
	wire_size = sizeof(__le32) + header_size;
	request_length = wire_size + request_body_length;
	memset(sep->ool_in, 0, T2_SEP_OOL_SIZE);
	memset(sep->ool_out, 0, T2_SEP_OOL_SIZE);
	put_unaligned_le32(header_size, sep->ool_in);
	header = sep->ool_in + sizeof(__le32);
	header->v1.version = cpu_to_le32(header_version);
	header->v1.usec_time = cpu_to_le64(ktime_get_boottime_ns() /
					      NSEC_PER_USEC);
	if (header_version == T2_AKS_HEADER_VERSION_2)
		header->calendar_seconds = cpu_to_le64(ktime_get_real_seconds());
	if (operation == 0x21) {
		ret = t2_aks_stamp_verify_platform_data(header);
		if (ret)
			return ret;
	}
	if (request_body_length)
		memcpy(sep->ool_in + wire_size,
		       request_body, request_body_length);

	ret = t2_aks_digest(sep->ool_in, request_length);
	if (ret)
		return ret;

	transaction = ++sep->next_transaction;
	if (!transaction)
		transaction = ++sep->next_transaction;
	request.word[0] = T2_SEP_AKS_ENDPOINT | (operation << 8) |
		(transaction << 16);
	request.word[1] = request_length << 16;
	ret = t2_sep_send(sep, &request);
	if (ret) {
		if (ret == -ETIMEDOUT)
			t2_sep_log_mailbox_timeout(sep, "AKS",
				T2_SEP_AKS_ENDPOINT, operation, "send", 0);
		return ret;
	}

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret) {
			if (ret == -ETIMEDOUT)
				t2_sep_log_mailbox_timeout(sep, "AKS",
					T2_SEP_AKS_ENDPOINT, operation, "reply",
					skipped);
			return ret;
		}
		if ((reply.word[0] & 0xff) == T2_SEP_AKS_ENDPOINT &&
		    (((reply.word[0] >> 8) & 0xff) == (operation | 0x80)) &&
		    ((reply.word[0] >> 16) & 0xff) == transaction)
			break;
		if (++skipped == 32)
			return -EOVERFLOW;
	}

	/* EP7 reply: endpoint, operation|response, transaction, signed status. */
	reply_status = (s8)(reply.word[0] >> 24);
	if (reply_status) {
		*sep_status_out = reply_status;
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned SEP status %d (flags %#x)\n",
			operation, reply_status, reply.word[1] & 0xffff);
		return -EREMOTEIO;
	}
	reply_length = reply.word[1] >> 16;
	if (reply_length < wire_size ||
	    reply_length > T2_SEP_OOL_SIZE) {
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned invalid envelope length %u (mailbox info %#x)\n",
			operation, reply_length, reply.word[1] & 0xffff);
		return -EPROTO;
	}
	if (get_unaligned_le32(sep->ool_out) != header_size ||
	    get_unaligned_le32(sep->ool_out + sizeof(__le32) + 0x10) !=
	    header_version) {
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned invalid envelope metadata (size %#x version %#x)\n",
			operation, get_unaligned_le32(sep->ool_out),
			get_unaligned_le32(sep->ool_out + sizeof(__le32) + 0x10));
		return -EPROTO;
	}

	{
		u8 expected[16];

		memcpy(expected, sep->ool_out + sizeof(__le32), sizeof(expected));
		memset(sep->ool_out + sizeof(__le32), 0, sizeof(expected));
		ret = t2_aks_digest(sep->ool_out, reply_length);
		if (!ret && memcmp(expected,
				sep->ool_out + sizeof(__le32), sizeof(expected)))
			ret = -EBADMSG;
		memzero_explicit(expected, sizeof(expected));
	}
	if (ret)
		return ret;

	*response_body = sep->ool_out + wire_size;
	*response_body_length = reply_length - wire_size;
	if (operation == T2_SEP_AKS_GET_CAPABILITIES &&
	    *response_body_length >= 12) {
		u32 status = get_unaligned_le32(*response_body);
		u64 capability = get_unaligned_le64(*response_body + 4);

		sep->aks_header_version =
				t2_aks_header_version_after_capabilities(
					sep->aks_header_version, status, capability);
	}
	if (operation == 0x03) {
		u32 handle;

		if (!t2_aks_load_keybag_response_valid(
			    *response_body, *response_body_length, &handle))
			return -EPROTO;
	} else if (operation == 0x04) {
		if (!t2_aks_lock_state_response_valid(
			    *response_body, *response_body_length))
			return -EPROTO;
	} else if (operation == 0x0d) {
		if (!t2_aks_status_response_valid(
			    *response_body, *response_body_length))
			return -EPROTO;
	} else if (operation == 0x18) {
		if (!t2_aks_acm_unlock_response_valid(
			    *response_body, *response_body_length))
			return -EPROTO;
	} else if (operation == 0x05) {
		if (!t2_aks_status_response_valid(
			    *response_body, *response_body_length) ||
		    t2_aks_wire_get_le32(*response_body) != 0)
			return -EPROTO;
	} else if (operation == 0x49) {
		if (!t2_aks_identity_delete_response_valid(
			    *response_body, *response_body_length))
			return -EPROTO;
	} else if (operation == 0x06) {
		if (!t2_aks_copy_keybag_uuid_response_valid(
			    *response_body, *response_body_length) &&
		    !t2_aks_copy_keybag_uuid_absent_response(
			    *response_body, *response_body_length))
			return -EPROTO;
	} else if (operation == 0x19) {
		if (!t2_aks_get_device_state_v1_response_valid(
			    *response_body, *response_body_length)) {
			u32 codec_version = *response_body_length >= 4 ?
				t2_aks_wire_get_le32(*response_body) : U32_MAX;
			u32 blob_length = *response_body_length >= 8 ?
				t2_aks_wire_get_le32(*response_body + 4) : U32_MAX;

			dev_err(&sep->pdev->dev,
				"AKS operation 0x19 rejected state envelope: response_length=%zu codec_version=%#x blob_length=%u\n",
				*response_body_length, codec_version, blob_length);
			return -EPROTO;
		}
	} else if (operation == 0x23) {
		if (!t2_aks_get_configuration_response_valid(
			    *response_body, *response_body_length))
			return -EPROTO;
	}
	return 0;
}

static void t2_aks_poison_provisioning_locked(struct t2_sep_transport *sep)
{
	sep->aks_provisioning_poisoned = true;
}

static void t2_aks_clear_password_authorization_locked(
	struct t2_sep_transport *sep)
{
	sep->aks_password_bound = false;
	memzero_explicit(sep->aks_authorized_context,
			 sizeof(sep->aks_authorized_context));
}

static void t2_acm_forget_identity_secret_locked(
	struct t2_sep_transport *sep)
{
	sep->acm_identity_secret_set = false;
	sep->acm_identity_secret_externalized = false;
	sep->acm_identity_secret_live = false;
	sep->acm_identity_secret_consumed = false;
	sep->acm_identity_target_created = false;
	sep->acm_identity_secret_user_id = 0;
	memzero_explicit(sep->acm_identity_secret_context,
			 sizeof(sep->acm_identity_secret_context));
}

static void t2_aks_clear_authorization_locked(struct t2_sep_transport *sep)
{
	t2_aks_clear_password_authorization_locked(sep);
	t2_acm_forget_identity_secret_locked(sep);
}

static void t2_aks_reset_inventory_locked(struct t2_sep_transport *sep)
{
	sep->aks_stable_absence_count = 0;
	sep->aks_absence_session = 0;
}

static void t2_aks_reset_absence_locked(struct t2_sep_transport *sep)
{
	t2_aks_reset_inventory_locked(sep);
	t2_aks_clear_authorization_locked(sep);
}

static void t2_aks_clear_replacement_arm_locked(struct t2_sep_transport *sep)
{
	sep->aks_replacement_phase = T2_AKS_REPLACEMENT_PHASE_NONE;
	sep->aks_replacement_session = 0;
	memzero_explicit(sep->aks_replacement_old_uuid,
			 sizeof(sep->aks_replacement_old_uuid));
	memzero_explicit(sep->aks_replacement_new_uuid,
			 sizeof(sep->aks_replacement_new_uuid));
	memzero_explicit(sep->aks_replacement_activation_material,
			 sizeof(sep->aks_replacement_activation_material));
}

static void t2_aks_record_absence_locked(struct t2_sep_transport *sep,
					 const u8 *request)
{
	u64 session = t2_aks_wire_get_le64(request + 4);

	if (sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_DELETE ||
	    sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_CREATE)
		t2_aks_clear_password_authorization_locked(sep);
	else
		t2_aks_clear_authorization_locked(sep);
	if (sep->aks_absence_session != session) {
		sep->aks_absence_session = session;
		sep->aks_stable_absence_count = 1;
	} else if (sep->aks_stable_absence_count < 2) {
		sep->aks_stable_absence_count++;
	}
}

static void t2_aks_record_password_binding_locked(
	struct t2_sep_transport *sep, const u8 *request, size_t request_length,
	const u8 *response, size_t response_length, int exchange_result)
{
	bool provisioning_target;
	bool runtime_target;
	bool identity_references_match;
	bool identity_verify_only_matches;

	identity_references_match = sep->acm_identity_secret_set &&
		sep->acm_identity_secret_externalized &&
		sep->acm_identity_secret_live &&
		!sep->acm_identity_secret_consumed &&
		sep->acm_identity_target_created &&
		sep->acm_context_active && !sep->acm_poisoned &&
		t2_aks_verify_secret_v1_identity_secret_matches(
			request, request_length,
			sep->acm_identity_secret_context) &&
		t2_aks_verify_secret_v1_context_matches(
			request, request_length, sep->acm_context) &&
			t2_aks_verify_secret_v1_identity_references_distinct(
				request, request_length);
	identity_verify_only_matches = !sep->acm_identity_target_created &&
		sep->acm_context_active && !sep->acm_poisoned &&
		sep->acm_identity_secret_set &&
		sep->acm_identity_secret_externalized &&
		sep->acm_identity_secret_live &&
		!sep->acm_identity_secret_consumed &&
		!memcmp(sep->acm_context, sep->acm_identity_secret_context,
			sizeof(sep->acm_context)) &&
		t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
			request, request_length) &&
		t2_aks_verify_secret_v1_identity_secret_matches(
			request, request_length,
			sep->acm_identity_secret_context);
	if ((t2_aks_verify_secret_v1_identity_request_allowed(
		     request, request_length) ||
	     t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
		     request, request_length)) &&
	    sep->acm_identity_secret_live) {
		sep->acm_identity_secret_consumed = true;
		sep->acm_identity_secret_set = false;
		t2_aks_clear_password_authorization_locked(sep);
	} else {
		t2_aks_clear_authorization_locked(sep);
	}
	provisioning_target = false;
	runtime_target = false;
	if (!exchange_result &&
	    t2_aks_verify_secret_v1_request_allowed(request, request_length)) {
		provisioning_target = sep->aks_stable_absence_count >= 2 &&
			t2_aks_verify_secret_v1_selector42_request_allowed(
				request, request_length);
		runtime_target = sep->aks_runtime_handle_active &&
			sep->aks_runtime_alias_bound &&
			identity_references_match &&
			t2_aks_verify_secret_v1_runtime_target_matches(
				request, request_length,
				sep->aks_runtime_session,
				sep->aks_runtime_handle);
	}
	if (identity_verify_only_matches)
		return;
	if (exchange_result || (!provisioning_target && !runtime_target) ||
	    !sep->acm_context_active || sep->acm_poisoned ||
	    !t2_aks_verify_secret_v1_response_valid(response, response_length) ||
	    !t2_aks_verify_secret_v1_context_matches(
		    request, request_length, sep->acm_context))
		return;
	memcpy(sep->aks_authorized_context, sep->acm_context,
	       sizeof(sep->aks_authorized_context));
	sep->aks_password_bound = true;
}

static int t2_aks_provisioning_preflight_locked(
	struct t2_sep_transport *sep, u8 operation,
	const u8 *request, size_t request_length)
{
	if (sep->aks_provisioning_phase == T2_AKS_PROVISIONING_CREATED &&
	    operation != 0x02)
		return -EBUSY;

	switch (operation) {
	case 0x01:
		if (!enable_identity_provisioning)
			return -EACCES;
		if (sep->aks_provisioning_poisoned)
			return -EUCLEAN;
		if (sep->aks_provisioning_phase != T2_AKS_PROVISIONING_IDLE)
			return -EALREADY;
		if (sep->aks_header_version != T2_AKS_HEADER_VERSION_2)
			return -EPROTONOSUPPORT;
		if (!t2_aks_identity_create_v5_request_allowed(request,
							 request_length))
			return -EACCES;
		if (enable_identity_replacement &&
		    sep->aks_replacement_phase != T2_AKS_REPLACEMENT_PHASE_NONE &&
		    (sep->aks_replacement_phase !=
			    T2_AKS_REPLACEMENT_PHASE_CREATE ||
		     sep->aks_replacement_create_attempted ||
		     !t2_aks_identity_create_v5_replacement_matches(
			     request, request_length,
			     sep->aks_replacement_session,
			     sep->aks_replacement_new_uuid,
			     sep->aks_replacement_activation_material)))
			return -EACCES;
		if (sep->aks_stable_absence_count < 2 ||
		    sep->aks_absence_session !=
			    t2_aks_wire_get_le64(request + 4))
			return -EAGAIN;
		if (sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_NONE &&
		    (!sep->acm_identity_secret_set || !sep->acm_context_active ||
		     sep->acm_poisoned ||
		     memcmp(request + 24, sep->acm_identity_secret_context,
			    sizeof(sep->acm_identity_secret_context)) ||
		     memcmp(sep->acm_context, sep->acm_identity_secret_context,
			    sizeof(sep->acm_identity_secret_context))))
			return -EKEYREJECTED;
		return 0;
	case 0x02:
		if (!enable_identity_provisioning)
			return -EACCES;
		if (sep->aks_replacement_phase ==
		    T2_AKS_REPLACEMENT_PHASE_RECOVER) {
			if (sep->aks_runtime_poisoned ||
			    !sep->aks_runtime_handle_active ||
			    !t2_aks_identity_copy_keybag_v1_request_allowed(
				    request, request_length) ||
			    t2_aks_wire_get_le64(request + 4) !=
				    sep->aks_runtime_session ||
			    t2_aks_wire_get_le32(request + 12) !=
				    sep->aks_runtime_handle)
				return -EACCES;
			return 0;
		}
		if (sep->aks_provisioning_poisoned)
			return -EUCLEAN;
		if (sep->aks_provisioning_phase != T2_AKS_PROVISIONING_CREATED)
			return -ENOKEY;
		if (!t2_aks_identity_copy_keybag_v1_request_allowed(request,
							       request_length) ||
		    t2_aks_wire_get_le64(request + 4) !=
			    sep->aks_provisioning_session ||
		    t2_aks_wire_get_le32(request + 12) !=
			    sep->aks_provisioning_handle)
			return -EACCES;
		return 0;
	case 0x49:
		if (!enable_identity_replacement ||
		    sep->aks_replacement_phase !=
			    T2_AKS_REPLACEMENT_PHASE_DELETE ||
		    sep->aks_replacement_delete_attempted ||
		    !t2_aks_identity_delete_request_matches(
			    request, request_length,
			    sep->aks_replacement_session,
			    sep->aks_replacement_old_uuid))
			return -EACCES;
		return 0;
	case 0x05:
		if (sep->aks_provisioning_phase ==
			    T2_AKS_PROVISIONING_COMPLETE) {
			if (sep->aks_provisioning_poisoned ||
			    sep->aks_provisioning_handle_released ||
			    sep->aks_provisioning_unload_attempted)
				return -EUCLEAN;
			return t2_aks_unload_keybag_request_matches(
				       request, request_length,
				       sep->aks_provisioning_session,
				       sep->aks_provisioning_handle) ? 0 : -EACCES;
		}
		return 0;
	default:
		return 0;
	}
}

static int t2_aks_record_provisioning_reply_locked(
	struct t2_sep_transport *sep, u8 operation,
	const u8 *request, const u8 *response, size_t response_length)
{
	u32 handle;

	if (operation == 0x01) {
		if (!t2_aks_identity_create_v5_response_valid(
			    response, response_length, &handle))
			return -EPROTO;
		sep->aks_provisioning_session =
			t2_aks_wire_get_le64(request + 4);
		sep->aks_provisioning_handle = handle;
		sep->aks_provisioning_phase = T2_AKS_PROVISIONING_CREATED;
		sep->aks_provisioning_handle_released = false;
		sep->aks_provisioning_unload_attempted = false;
		t2_aks_reset_absence_locked(sep);
	} else if (operation == 0x02 &&
		   sep->aks_replacement_phase !=
			   T2_AKS_REPLACEMENT_PHASE_RECOVER) {
		if (!t2_aks_identity_copy_keybag_v1_response_valid(
			    response, response_length))
			return -EPROTO;
		sep->aks_provisioning_phase = T2_AKS_PROVISIONING_COMPLETE;
	} else if (operation == 0x05 &&
		   sep->aks_provisioning_phase == T2_AKS_PROVISIONING_COMPLETE &&
		   !sep->aks_provisioning_handle_released &&
		   t2_aks_unload_keybag_request_matches(
			   request, 16, sep->aks_provisioning_session,
			   sep->aks_provisioning_handle)) {
		sep->aks_provisioning_handle_released = true;
		sep->aks_provisioning_unload_attempted = false;
		sep->aks_provisioning_session = 0;
		sep->aks_provisioning_handle = 0;
		sep->aks_provisioning_phase = T2_AKS_PROVISIONING_IDLE;
	}
	return 0;
}

static int t2_aks_runtime_preflight_locked(
	struct t2_sep_transport *sep, u8 operation,
	const u8 *request, size_t request_length)
{
	switch (operation) {
	case 0x03:
		if (sep->aks_replacement_phase !=
		    T2_AKS_REPLACEMENT_PHASE_NONE) {
			if (sep->aks_replacement_phase !=
			    T2_AKS_REPLACEMENT_PHASE_RECOVER ||
			    !t2_aks_identity_open_request_matches(
				    request, request_length,
				    sep->aks_replacement_session,
				    sep->aks_replacement_new_uuid))
				return -EACCES;
		} else if (!t2_aks_load_keybag_request_allowed(request, request_length) ||
			   (request_length == 32 &&
			    t2_aks_wire_get_le32(request + 12) == 16)) {
			return -EACCES;
		}
		if (sep->aks_runtime_poisoned)
			return -EUCLEAN;
		if (sep->aks_runtime_handle_active)
			return -EALREADY;
		return 0;
	case 0x05:
		if (sep->aks_provisioning_phase ==
		    T2_AKS_PROVISIONING_COMPLETE)
			return 0;
		if (!sep->aks_runtime_handle_active)
			return -ENOKEY;
		if (sep->aks_runtime_unload_attempted)
			return -EALREADY;
		return t2_aks_unload_keybag_request_matches(
			request, request_length, sep->aks_runtime_session,
			sep->aks_runtime_handle) ? 0 : -EACCES;
	case 0x04:
		if (sep->aks_runtime_poisoned)
			return -EUCLEAN;
		if (!sep->aks_runtime_handle_active ||
		    !sep->aks_runtime_alias_bound)
			return -ENOKEY;
		return t2_aks_unlock_target_request_matches(
			       request, request_length, sep->aks_runtime_session,
			       sep->aks_runtime_handle) ||
		       t2_aks_unlock_target_request_matches(
			       request, request_length, sep->aks_runtime_session,
			       sep->aks_runtime_alias) ? 0 : -EACCES;
	case 0x0d:
		if (sep->aks_runtime_poisoned)
			return -EUCLEAN;
		return sep->aks_runtime_handle_active ? 0 : -ENOKEY;
	case 0x18:
		if (sep->aks_runtime_poisoned)
			return -EUCLEAN;
		if (!sep->aks_runtime_handle_active ||
		    !sep->aks_runtime_alias_bound)
			return -ENOKEY;
		if (sep->aks_runtime_unlock_attempted)
			return -EALREADY;
		if (!sep->acm_context_active || sep->acm_poisoned)
			return -EKEYREJECTED;
		if (!t2_aks_acm_unlock_request_allowed(request, request_length) ||
		    t2_aks_wire_get_le32(request + 12) !=
			    sep->aks_runtime_alias)
			return -EACCES;
		return t2_aks_identity_login_context_allowed(
			       request, request_length,
			       sep->acm_identity_secret_context,
			       sep->aks_authorized_context, sep->acm_context,
			       sep->acm_identity_secret_live,
			       sep->acm_identity_secret_consumed,
			       sep->acm_identity_target_created,
			       sep->aks_password_bound) ?
			       0 : -EKEYREJECTED;
	default:
		return 0;
	}
}

static int t2_aks_record_runtime_reply_locked(
	struct t2_sep_transport *sep, u8 operation, const u8 *request,
	const u8 *response, size_t response_length)
{
	u32 handle;

	if (operation == 0x03) {
		if (!t2_aks_load_keybag_response_valid(
			    response, response_length, &handle))
			return -EPROTO;
		sep->aks_runtime_session = t2_aks_wire_get_le64(request + 4);
		sep->aks_runtime_handle = handle;
		sep->aks_runtime_handle_active = true;
		sep->aks_runtime_unload_attempted = false;
		sep->aks_runtime_alias_bound = false;
		sep->aks_runtime_unlock_attempted = false;
		sep->aks_runtime_alias = 0;
	} else if (operation == 0x0d) {
		if (!t2_aks_status_response_valid(response, response_length))
			return -EPROTO;
		if (t2_aks_wire_get_le32(response) == 0) {
			sep->aks_runtime_alias =
				t2_aks_wire_get_le32(request + 16);
			sep->aks_runtime_alias_bound = true;
		}
	} else if (operation == 0x05 && sep->aks_runtime_handle_active &&
		   t2_aks_unload_keybag_request_matches(
			   request, 16, sep->aks_runtime_session,
			   sep->aks_runtime_handle)) {
		if (!t2_aks_status_response_valid(response, response_length) ||
		    t2_aks_wire_get_le32(response) != 0)
			return -EPROTO;
		sep->aks_runtime_handle_active = false;
		sep->aks_runtime_session = 0;
		sep->aks_runtime_handle = 0;
		sep->aks_runtime_unload_attempted = false;
		sep->aks_runtime_alias_bound = false;
		sep->aks_runtime_unlock_attempted = false;
		sep->aks_runtime_alias = 0;
	}
	return 0;
}

static long t2_aks_get_info(struct t2_sep_transport *sep,
			    void __user *user_argument)
{
	struct t2_aks_ioc_info info = { };
	int ret;

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		return ret;
	memcpy(info.connection_generation, sep->aks_connection_generation,
	       sizeof(info.connection_generation));
	if (sep->ool_in_registered && sep->ool_out_registered)
		info.flags |= T2_AKS_INFO_F_OOL_REGISTERED;
	if (sep->acm_ool_in_registered && sep->acm_ool_out_registered)
		info.flags |= T2_AKS_INFO_F_ACM_REGISTERED;
	if (enable_identity_provisioning)
		info.flags |= T2_AKS_INFO_F_PROVISIONING_ENABLED;
	if (sep->aks_provisioning_poisoned)
		info.flags |= T2_AKS_INFO_F_PROVISIONING_POISONED;
	if (inventory_only)
		info.flags |= T2_AKS_INFO_F_INVENTORY_ONLY;
	if (sep->aks_password_bound)
		info.flags |= T2_AKS_INFO_F_PASSWORD_BOUND;
	if (sep->acm_identity_secret_set)
		info.flags |= T2_AKS_INFO_F_IDENTITY_SECRET_SET;
	if (sep->aks_runtime_handle_active)
		info.flags |= T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE;
	if (sep->aks_runtime_poisoned)
		info.flags |= T2_AKS_INFO_F_RUNTIME_POISONED;
	if (enable_identity_replacement)
		info.flags |= T2_AKS_INFO_F_REPLACEMENT_ENABLED;
	if (sep->aks_replacement_phase != T2_AKS_REPLACEMENT_PHASE_NONE)
		info.flags |= T2_AKS_INFO_F_REPLACEMENT_ARMED;
	info.header_version = sep->aks_header_version;
	info.provisioning_phase = sep->aks_provisioning_phase;
	info.stable_absence_count = sep->aks_stable_absence_count;
	mutex_unlock(&sep->exchange_lock);

	return copy_to_user(user_argument, &info, sizeof(info)) ? -EFAULT : 0;
}

static long t2_aks_arm_replacement(struct t2_sep_transport *sep,
				   void __user *user_argument)
{
	struct t2_aks_ioc_replacement arm;
	int ret;

	if (!enable_identity_replacement)
		return -EACCES;
	if (copy_from_user(&arm, user_argument, sizeof(arm)))
		return -EFAULT;
	if (arm.reserved0 || !arm.session ||
	    (arm.phase != T2_AKS_REPLACEMENT_PHASE_DELETE &&
	     arm.phase != T2_AKS_REPLACEMENT_PHASE_CREATE &&
	     arm.phase != T2_AKS_REPLACEMENT_PHASE_RECOVER) ||
	    !memchr_inv(arm.old_account_uuid, 0,
			sizeof(arm.old_account_uuid)) ||
	    !memchr_inv(arm.new_account_uuid, 0,
			sizeof(arm.new_account_uuid)) ||
	    (arm.phase != T2_AKS_REPLACEMENT_PHASE_RECOVER &&
	     !memchr_inv(arm.activation_material, 0,
			 sizeof(arm.activation_material))) ||
	    (arm.phase == T2_AKS_REPLACEMENT_PHASE_RECOVER &&
	     memchr_inv(arm.activation_material, 0,
			 sizeof(arm.activation_material))) ||
	    !memcmp(arm.old_account_uuid, arm.new_account_uuid,
		    sizeof(arm.old_account_uuid))) {
		ret = -EINVAL;
		goto out_wipe;
	}

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		goto out_wipe;
	if (sep->aks_replacement_phase != T2_AKS_REPLACEMENT_PHASE_NONE &&
	    !(sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_DELETE &&
	      arm.phase == T2_AKS_REPLACEMENT_PHASE_CREATE &&
	      sep->aks_replacement_delete_attempted &&
	      sep->aks_replacement_session == arm.session &&
	      !memcmp(sep->aks_replacement_old_uuid, arm.old_account_uuid,
		      sizeof(arm.old_account_uuid)) &&
	      !memcmp(sep->aks_replacement_new_uuid, arm.new_account_uuid,
		      sizeof(arm.new_account_uuid)) &&
	      !memcmp(sep->aks_replacement_activation_material,
		      arm.activation_material,
		      sizeof(arm.activation_material)))) {
		ret = -EALREADY;
		goto out_unlock;
	}
	if (sep->aks_header_version != T2_AKS_HEADER_VERSION_2) {
		ret = -EPROTONOSUPPORT;
		goto out_unlock;
	}
	if (sep->aks_provisioning_poisoned || sep->aks_runtime_poisoned) {
		ret = -EUCLEAN;
		goto out_unlock;
	}
	if (sep->aks_provisioning_phase != T2_AKS_PROVISIONING_IDLE ||
	    sep->aks_runtime_handle_active) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (arm.phase == T2_AKS_REPLACEMENT_PHASE_DELETE &&
	    (!sep->acm_identity_secret_set ||
	     !sep->acm_identity_secret_externalized ||
	     !sep->acm_identity_secret_live || !sep->acm_context_active ||
	     sep->acm_poisoned ||
	     memcmp(arm.activation_material, sep->acm_identity_secret_context,
		    sizeof(arm.activation_material)))) {
		ret = -EKEYREJECTED;
		goto out_unlock;
	}
	if (arm.phase == T2_AKS_REPLACEMENT_PHASE_DELETE &&
	    sep->aks_replacement_delete_attempted) {
		ret = -EALREADY;
		goto out_unlock;
	}
	if (arm.phase == T2_AKS_REPLACEMENT_PHASE_CREATE &&
	    (sep->aks_replacement_create_attempted ||
	     sep->aks_stable_absence_count < 2 ||
	     sep->aks_absence_session != arm.session)) {
		ret = sep->aks_replacement_create_attempted ? -EALREADY : -EAGAIN;
		goto out_unlock;
	}

	sep->aks_replacement_phase = arm.phase;
	sep->aks_replacement_session = arm.session;
	memcpy(sep->aks_replacement_old_uuid, arm.old_account_uuid,
	       sizeof(sep->aks_replacement_old_uuid));
	memcpy(sep->aks_replacement_new_uuid, arm.new_account_uuid,
	       sizeof(sep->aks_replacement_new_uuid));
	memcpy(sep->aks_replacement_activation_material,
	       arm.activation_material,
	       sizeof(sep->aks_replacement_activation_material));
	ret = 0;

out_unlock:
	mutex_unlock(&sep->exchange_lock);
out_wipe:
	memzero_explicit(&arm, sizeof(arm));
	return ret;
}

static long t2_aks_ioctl(struct file *file, unsigned int command,
			 unsigned long argument)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, aks_miscdev);
	struct t2_aks_ioc_exchange exchange;
	void __user *user_argument = (void __user *)argument;
	void *request = NULL;
	u8 *response = NULL;
	size_t response_length = 0;
	bool provisioning_attempted = false;
	bool runtime_attempted = false;
	bool provisioning_unload = false;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (command == T2_AKS_IOC_GET_INFO)
		return t2_aks_get_info(sep, user_argument);
	if (command == T2_AKS_IOC_ARM_REPLACEMENT)
		return t2_aks_arm_replacement(sep, user_argument);
	if (command != T2_AKS_IOC_EXCHANGE)
		return -ENOTTY;
	if (copy_from_user(&exchange, user_argument, sizeof(exchange)))
		return -EFAULT;
	if (exchange.sep_status ||
	    memchr_inv(exchange.reserved0, 0, sizeof(exchange.reserved0)))
		return -EINVAL;
	if (inventory_only &&
	    exchange.operation != T2_SEP_AKS_GET_PRIMARY_IDENTITY)
		return -EACCES;
	if (exchange.request_length > T2_SEP_AKS_MAX_BODY_SIZE ||
	    exchange.response_capacity > T2_SEP_AKS_MAX_BODY_SIZE)
		return -EMSGSIZE;
	if ((exchange.operation == 0x21 && exchange.response_capacity != 12) ||
	    (exchange.operation == 0x04 && exchange.response_capacity != 16) ||
	    (exchange.operation == 0x18 && exchange.response_capacity != 20) ||
	    (exchange.operation == 0x49 && exchange.response_capacity != 4) ||
	    (exchange.operation == 0x03 && exchange.response_capacity != 8) ||
	    (exchange.operation == 0x0d && exchange.response_capacity != 4) ||
	    (exchange.response_capacity && !exchange.response))
		return -EACCES;
	if (exchange.request_length) {
		request = memdup_user(u64_to_user_ptr(exchange.request),
				      exchange.request_length);
		if (IS_ERR(request))
			return PTR_ERR(request);
	}

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		goto out_free;
	ret = t2_aks_provisioning_preflight_locked(
		sep, exchange.operation, request, exchange.request_length);
	if (ret) {
		if (exchange.operation == 0x02 &&
		    sep->aks_provisioning_phase == T2_AKS_PROVISIONING_CREATED)
			t2_aks_poison_provisioning_locked(sep);
		goto out_unlock;
	}
	ret = t2_aks_runtime_preflight_locked(
		sep, exchange.operation, request, exchange.request_length);
	if (ret)
		goto out_unlock;
	provisioning_unload = exchange.operation == 0x05 &&
		sep->aks_provisioning_phase == T2_AKS_PROVISIONING_COMPLETE;
	provisioning_attempted = exchange.operation == 0x01 ||
		(exchange.operation == 0x02 &&
		 sep->aks_replacement_phase !=
			 T2_AKS_REPLACEMENT_PHASE_RECOVER) ||
		provisioning_unload;
	runtime_attempted = exchange.operation == 0x03 ||
		(exchange.operation == 0x05 && !provisioning_unload) ||
		(exchange.operation == 0x02 &&
		 sep->aks_replacement_phase ==
			 T2_AKS_REPLACEMENT_PHASE_RECOVER);
	if (exchange.operation == 0x05) {
		if (provisioning_unload)
			sep->aks_provisioning_unload_attempted = true;
		else
			sep->aks_runtime_unload_attempted = true;
	}
	if (exchange.operation == 0x18)
		sep->aks_runtime_unlock_attempted = true;
	if (exchange.operation == 0x49) {
		sep->aks_replacement_delete_attempted = true;
		t2_aks_reset_inventory_locked(sep);
	}
	/* Initial provisioning must not consume the later replacement attempt. */
	if (exchange.operation == 0x01 && enable_identity_replacement &&
	    sep->aks_replacement_phase == T2_AKS_REPLACEMENT_PHASE_CREATE)
		sep->aks_replacement_create_attempted = true;
	if (exchange.operation != T2_SEP_AKS_GET_PRIMARY_IDENTITY &&
	    exchange.operation != 0x21 && exchange.operation != 0x01 &&
	    exchange.operation != 0x02 && exchange.operation != 0x18 &&
	    exchange.operation != 0x49)
		t2_aks_reset_absence_locked(sep);
	ret = t2_aks_exchange_locked(sep, exchange.operation, request,
				     exchange.request_length, &response,
				     &response_length, &exchange.sep_status);
	if (exchange.operation == T2_SEP_AKS_GET_PRIMARY_IDENTITY) {
		if ((ret && exchange.sep_status == -3) ||
		    (!ret && t2_aks_get_primary_identity_absent_response(
			     response, response_length)))
			t2_aks_record_absence_locked(sep, request);
		else
			t2_aks_reset_absence_locked(sep);
	}
	if (exchange.operation == 0x21)
		t2_aks_record_password_binding_locked(
			sep, request, exchange.request_length, response,
			response_length, ret);
	if (ret) {
		if (exchange.sep_status &&
		    copy_to_user(user_argument, &exchange, sizeof(exchange)))
			ret = -EFAULT;
		goto out_unlock;
	}
	ret = t2_aks_record_provisioning_reply_locked(
		sep, exchange.operation, request, response, response_length);
	if (ret)
		goto out_unlock;
	ret = t2_aks_record_runtime_reply_locked(
		sep, exchange.operation, request, response, response_length);
	if (ret)
		goto out_unlock;
	if (response_length > exchange.response_capacity) {
		ret = -ENOSPC;
		goto out_set_length;
	}
	if (response_length && copy_to_user(u64_to_user_ptr(exchange.response),
					 response, response_length)) {
		ret = -EFAULT;
		goto out_unlock;
	}

out_set_length:
	exchange.response_length = response_length;
	if (copy_to_user(user_argument, &exchange, sizeof(exchange)))
		ret = -EFAULT;
out_unlock:
	if (provisioning_attempted && ret)
		t2_aks_poison_provisioning_locked(sep);
	if (runtime_attempted && ret)
		sep->aks_runtime_poisoned = true;
	/* The reply may contain a private keybag UUID or state dictionary. */
	memzero_explicit(sep->ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->ool_out, T2_SEP_OOL_SIZE);
	mutex_unlock(&sep->exchange_lock);
out_free:
	if (request) {
		memzero_explicit(request, exchange.request_length);
		kfree(request);
	}
	return ret;
}

static int t2_aks_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, aks_miscdev);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (atomic_cmpxchg(&sep->aks_opened, 0, 1))
		return -EBUSY;
	ret = nonseekable_open(inode, file);
	if (ret) {
		atomic_set(&sep->aks_opened, 0);
		return ret;
	}
	mutex_lock(&sep->exchange_lock);
	t2_aks_reset_absence_locked(sep);
	t2_aks_clear_replacement_arm_locked(sep);
	mutex_unlock(&sep->exchange_lock);
	return ret;
}

static int t2_aks_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, aks_miscdev);

	(void)inode;
	mutex_lock(&sep->exchange_lock);
	if (retain_runtime_handle && sep->aks_runtime_handle_active &&
	    sep->aks_runtime_alias_bound && !sep->aks_runtime_poisoned &&
	    !sep->aks_runtime_unload_attempted) {
		dev_dbg(&sep->pdev->dev,
			"retaining bound compatibility runtime handle after root helper close\n");
	} else if (sep->aks_runtime_handle_active &&
	    !sep->aks_runtime_unload_attempted) {
		u8 request[16] = { };
		u8 *response = NULL;
		size_t response_length = 0;
		s8 sep_status = 0;
		int ret;

		put_unaligned_le64(sep->aks_runtime_session, request + 4);
		put_unaligned_le32(sep->aks_runtime_handle, request + 12);
		sep->aks_runtime_unload_attempted = true;
		ret = t2_aks_exchange_locked(sep, 0x05, request,
					     sizeof(request), &response,
					     &response_length, &sep_status);
		if (!ret)
			ret = t2_aks_record_runtime_reply_locked(
				sep, 0x05, request, response, response_length);
		if (ret) {
			sep->aks_runtime_poisoned = true;
			dev_warn(&sep->pdev->dev,
				 "AKS owner closed with live handle; bounded unload failed (%d, SEP status %d); runtime activation disabled until reboot\n",
				 ret, sep_status);
		}
		memzero_explicit(request, sizeof(request));
	} else if (sep->aks_runtime_handle_active) {
		dev_warn(&sep->pdev->dev,
			 "AKS owner closed after an ambiguous unload; not retrying before reboot\n");
	}
	if (sep->aks_provisioning_phase == T2_AKS_PROVISIONING_COMPLETE &&
	    !sep->aks_provisioning_handle_released) {
		if (!sep->aks_provisioning_unload_attempted) {
			u8 request[16] = { };
			u8 *response = NULL;
			size_t response_length = 0;
			s8 sep_status = 0;
			int ret;

			put_unaligned_le64(sep->aks_provisioning_session,
					   request + 4);
			put_unaligned_le32(sep->aks_provisioning_handle,
					   request + 12);
			sep->aks_provisioning_unload_attempted = true;
			ret = t2_aks_exchange_locked(
				sep, 0x05, request, sizeof(request), &response,
				&response_length, &sep_status);
			if (!ret)
				ret = t2_aks_record_provisioning_reply_locked(
					sep, 0x05, request, response,
					response_length);
			if (ret) {
				t2_aks_poison_provisioning_locked(sep);
				dev_warn(&sep->pdev->dev,
					 "replacement owner closed with created handle; bounded unload failed (%d, SEP status %d); reconcile after reboot\n",
					 ret, sep_status);
			}
			memzero_explicit(request, sizeof(request));
		} else {
			dev_warn(&sep->pdev->dev,
				 "replacement owner closed after ambiguous created-handle unload; not retrying before reboot\n");
		}
	}
	if (sep->aks_provisioning_phase == T2_AKS_PROVISIONING_CREATED &&
	    !sep->aks_provisioning_poisoned) {
		dev_warn(&sep->pdev->dev,
			 "identity provisioning owner closed before export; provisioning disabled until reboot\n");
		t2_aks_poison_provisioning_locked(sep);
	}
	memzero_explicit(sep->ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->ool_out, T2_SEP_OOL_SIZE);
	t2_aks_reset_absence_locked(sep);
	t2_aks_clear_replacement_arm_locked(sep);
	mutex_unlock(&sep->exchange_lock);
	atomic_set(&sep->aks_opened, 0);
	return 0;
}

static const struct file_operations t2_aks_fops = {
	.owner = THIS_MODULE,
	.open = t2_aks_open,
	.release = t2_aks_release,
	.unlocked_ioctl = t2_aks_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static bool t2_acm_command_allowed(const u8 *request, size_t length)
{
	static const u8 prefix[] = { 'D', 'R', 'C', 'S' };

	if (length < 8 || memcmp(request, prefix, sizeof(prefix)) ||
	    request[5] != 0 || request[6] != 0 || request[7] != 1)
		return false;
	switch (request[4]) {
	case 0x01: /* legacy context create */
	case 0x24: /* context create with tracking */
		return length == 12; /* command header + appended effective UID */
	case 0x02: /* context destroy */
	case 0x13: /* externalize the active context */
		return length == 24; /* command header + 16-byte context */
	case 0x03: /* TouchIdEnrollment policy, empty parameter array */
		return length == 51 &&
			!memcmp(request + 24, "TouchIdEnrollment\0", 18) &&
			request[42] <= 1 &&
			!memchr_inv(request + 43, 0, 8);
	case 0x28: /* request-10 type-5 identity secret, no parameters */
		return length >= 37 && length <= 36 + 0x80 &&
			get_unaligned_le32(request + 24) == 5 &&
			get_unaligned_le32(request + 28) == length - 36 &&
			!memchr_inv(request + length - 4, 0, 4);
	default:
		return false;
	}
}

static bool t2_acm_response_buffer_valid(const u8 *request,
					 u32 capacity, u64 response)
{
	return t2_acm_response_capacity_allowed(request[4], capacity,
						response != 0);
}

static bool t2_acm_identity_secret_is_current_locked(
	const struct t2_sep_transport *sep)
{
	return sep->acm_identity_secret_live && sep->acm_context_active &&
		!memcmp(sep->acm_context, sep->acm_identity_secret_context,
			sizeof(sep->acm_context));
}

static bool t2_acm_split_target_create_allowed_locked(
	const struct t2_sep_transport *sep, const u8 *request)
{
	return t2_acm_split_target_create_allowed(
		request[4], sep->acm_context_active,
		sep->acm_identity_secret_live,
		sep->acm_identity_secret_externalized,
		sep->acm_identity_secret_consumed,
		sep->acm_identity_target_created,
		sep->aks_runtime_handle_active,
		sep->aks_runtime_alias_bound,
		t2_acm_identity_secret_is_current_locked(sep),
		get_unaligned_le32(request + 8) ==
			sep->acm_identity_secret_user_id);
}

static void t2_acm_clear_context_locked(struct t2_sep_transport *sep)
{
	t2_aks_clear_authorization_locked(sep);
	memzero_explicit(sep->acm_context, sizeof(sep->acm_context));
	sep->acm_context_active = false;
	sep->acm_context_user_id = 0;
}

static void t2_acm_restore_identity_secret_locked(
	struct t2_sep_transport *sep)
{
	t2_aks_clear_password_authorization_locked(sep);
	memcpy(sep->acm_context, sep->acm_identity_secret_context,
	       sizeof(sep->acm_context));
	sep->acm_context_user_id = sep->acm_identity_secret_user_id;
	sep->acm_context_active = true;
}

static void t2_acm_poison_locked(struct t2_sep_transport *sep)
{
	sep->acm_poisoned = true;
	if (!++sep->acm_generation)
		++sep->acm_generation;
	t2_acm_clear_context_locked(sep);
}

static int t2_acm_validate_context_locked(struct t2_sep_transport *sep,
					  const u8 *request)
{
	if (t2_acm_split_target_create_allowed_locked(sep, request))
		return 0;
	switch (t2_acm_context_preflight(request[4],
					 sep->acm_context_active)) {
	case T2_ACM_CONTEXT_ALLOW:
		return 0;
	case T2_ACM_CONTEXT_BUSY:
		return -EBUSY;
	case T2_ACM_CONTEXT_STALE:
		return -ESTALE;
	case T2_ACM_CONTEXT_MATCH_REQUIRED:
		return memcmp(request + 8, sep->acm_context,
			      sizeof(sep->acm_context)) ? -EACCES : 0;
	case T2_ACM_CONTEXT_DENY:
		return -EACCES;
	}
	return -EACCES;
}

static int t2_acm_record_reply_locked(struct t2_sep_transport *sep,
				      const u8 *request, const u8 *response,
				      size_t response_length, u32 response_info)
{
	bool split_target_create =
		t2_acm_split_target_create_allowed_locked(sep, request);

	switch (t2_acm_reply_action(request[4], response_length,
				   response_info)) {
	case T2_ACM_REPLY_ACCEPT:
		if (request[4] == 0x28) {
			t2_aks_clear_authorization_locked(sep);
			memcpy(sep->acm_identity_secret_context,
			       sep->acm_context,
			       sizeof(sep->acm_identity_secret_context));
			sep->acm_identity_secret_user_id =
				sep->acm_context_user_id;
			sep->acm_identity_secret_set = true;
			sep->acm_identity_secret_live = true;
			sep->acm_identity_secret_consumed = false;
		} else if (request[4] == 0x13 &&
			   sep->acm_identity_secret_set &&
			   !memcmp(sep->acm_context,
				   sep->acm_identity_secret_context,
				   sizeof(sep->acm_context))) {
			sep->acm_identity_secret_externalized = true;
		}
		return 0;
	case T2_ACM_REPLY_REJECT:
		return -EPROTO;
	case T2_ACM_REPLY_POISON:
		/* SEP may have created a context whose handle is unavailable. */
		t2_acm_poison_locked(sep);
		return -EPROTO;
	case T2_ACM_REPLY_SET_CONTEXT:
		if (split_target_create &&
		    !memcmp(response, sep->acm_identity_secret_context,
			    sizeof(sep->acm_identity_secret_context))) {
			t2_acm_poison_locked(sep);
			return -EPROTO;
		}
		if (!split_target_create)
			t2_aks_clear_authorization_locked(sep);
		else
			sep->acm_identity_target_created = true;
		memcpy(sep->acm_context, response, sizeof(sep->acm_context));
		sep->acm_context_user_id = get_unaligned_le32(request + 8);
		sep->acm_context_active = true;
		return 0;
	case T2_ACM_REPLY_SET_CONTEXT_AND_REJECT:
		if (split_target_create &&
		    !memcmp(response, sep->acm_identity_secret_context,
			    sizeof(sep->acm_identity_secret_context))) {
			t2_acm_poison_locked(sep);
			return -EPROTO;
		}
		if (!split_target_create)
			t2_aks_clear_authorization_locked(sep);
		else
			sep->acm_identity_target_created = true;
		memcpy(sep->acm_context, response, sizeof(sep->acm_context));
		sep->acm_context_user_id = get_unaligned_le32(request + 8);
		sep->acm_context_active = true;
		return -EPROTO;
	case T2_ACM_REPLY_CLEAR_CONTEXT:
		if (sep->acm_identity_secret_live &&
		    sep->acm_identity_target_created &&
		    memcmp(request + 8, sep->acm_identity_secret_context,
			   sizeof(sep->acm_identity_secret_context)))
			t2_acm_restore_identity_secret_locked(sep);
		else
			t2_acm_clear_context_locked(sep);
		return 0;
	case T2_ACM_REPLY_CLEAR_CONTEXT_AND_REJECT:
		t2_acm_poison_locked(sep);
		return -EPROTO;
	}
	return -EPROTO;
}

static int t2_acm_exchange_locked(struct t2_sep_transport *sep,
				  u8 request_code, u32 request_info,
				  const void *request_body,
				  size_t request_body_length,
				  u8 **response_body,
				  size_t *response_body_length,
				  u32 *response_info)
{
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	unsigned int skipped = 0;
	u16 reply_length;
	int ret;

	if (request_code != 1 || request_info != 0 ||
	    request_body_length > T2_SEP_OOL_SIZE ||
	    !t2_acm_command_allowed(request_body, request_body_length))
		return -EACCES;

	memset(sep->acm_ool_in, 0, T2_SEP_OOL_SIZE);
	memset(sep->acm_ool_out, 0, T2_SEP_OOL_SIZE);
	memcpy(sep->acm_ool_in, request_body, request_body_length);
	request.word[0] = T2_SEP_ACM_ENDPOINT | (request_code << 8) |
		(request_body_length << 16);
	request.word[1] = request_info;
	ret = t2_sep_send(sep, &request);
	if (ret) {
		if (ret == -ETIMEDOUT)
			t2_sep_log_mailbox_timeout(sep, "ACM",
				T2_SEP_ACM_ENDPOINT,
				request_code, "send", 0);
		return ret;
	}

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret) {
			t2_acm_poison_locked(sep);
			return ret;
		}
		if ((reply.word[0] & 0xff) == T2_SEP_ACM_ENDPOINT &&
		    ((reply.word[0] >> 8) & 0xff) == request_code)
			break;
		if (++skipped == 32) {
			t2_acm_poison_locked(sep);
			return -EOVERFLOW;
		}
	}

	reply_length = reply.word[0] >> 16;
	if (reply_length > T2_SEP_OOL_SIZE) {
		t2_acm_poison_locked(sep);
		return -EPROTO;
	}
	*response_body = sep->acm_ool_out;
	*response_body_length = reply_length;
	*response_info = reply.word[1];
	return 0;
}

static long t2_acm_ioctl(struct file *file, unsigned int command,
			 unsigned long argument)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	void __user *user_argument = (void __user *)argument;
	struct t2_acm_ioc_exchange exchange;
	struct t2_acm_ioc_info info = { };
	void *request = NULL;
	u8 *response = NULL;
	size_t response_length = 0;
	u32 response_info = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (command == T2_ACM_IOC_GET_INFO) {
		ret = mutex_lock_interruptible(&sep->exchange_lock);
		if (ret)
			return ret;
		info.generation = sep->acm_generation;
		info.capacity = T2_SEP_OOL_SIZE;
		if (sep->acm_poisoned)
			info.flags |= T2_ACM_INFO_F_POISONED;
		mutex_unlock(&sep->exchange_lock);
		return copy_to_user(user_argument, &info, sizeof(info)) ?
			-EFAULT : 0;
	}
	if (command != T2_ACM_IOC_EXCHANGE)
		return -ENOTTY;
	if (copy_from_user(&exchange, user_argument, sizeof(exchange)))
		return -EFAULT;
	if (memchr_inv(exchange.reserved0, 0, sizeof(exchange.reserved0)) ||
	    !exchange.request_length ||
	    exchange.request_length > T2_SEP_OOL_SIZE ||
	    exchange.response_capacity > T2_SEP_OOL_SIZE || !exchange.request)
		return -EINVAL;
	request = memdup_user(u64_to_user_ptr(exchange.request),
			      exchange.request_length);
	if (IS_ERR(request))
		return PTR_ERR(request);
	if (!t2_acm_command_allowed(request, exchange.request_length) ||
	    !t2_acm_response_buffer_valid(request, exchange.response_capacity,
					  exchange.response)) {
		ret = -EACCES;
		goto out;
	}

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		goto out;
	if (exchange.generation != sep->acm_generation) {
		exchange.generation = sep->acm_generation;
		ret = -ESTALE;
		goto out_copy_exchange;
	}
	if (sep->acm_poisoned) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	ret = t2_acm_validate_context_locked(sep, request);
	if (ret)
		goto out_unlock;
	ret = t2_acm_exchange_locked(sep, exchange.request_code,
			exchange.request_info, request, exchange.request_length,
			&response, &response_length, &response_info);
	if (ret)
		goto out_unlock;
	exchange.response_length = response_length;
	exchange.response_info = response_info;
	ret = t2_acm_record_reply_locked(sep, request, response,
					 response_length, response_info);
	if (ret)
		goto out_copy_exchange;
	if (response_length > exchange.response_capacity) {
		ret = -ENOSPC;
		goto out_copy_exchange;
	}
	if (response_length && copy_to_user(u64_to_user_ptr(exchange.response),
					 response, response_length)) {
		ret = -EFAULT;
		goto out_unlock;
	}
out_copy_exchange:
	if (copy_to_user(user_argument, &exchange, sizeof(exchange)))
		ret = -EFAULT;
out_unlock:
	memzero_explicit(sep->acm_ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->acm_ool_out, T2_SEP_OOL_SIZE);
	mutex_unlock(&sep->exchange_lock);
out:
	memzero_explicit(request, exchange.request_length);
	kfree(request);
	return ret;
}

static int t2_acm_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (atomic_cmpxchg(&sep->acm_opened, 0, 1))
		return -EBUSY;
	ret = nonseekable_open(inode, file);
	if (ret)
		atomic_set(&sep->acm_opened, 0);
	return ret;
}

static int t2_acm_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	u8 request[8 + T2_ACM_CONTEXT_SIZE] = {
		'D', 'R', 'C', 'S', 0x02, 0, 0, 1,
	};
	u8 *response = NULL;
	size_t response_length = 0;
	u32 response_info = 0;
	unsigned int cleanup_attempts = 0;
	int ret = 0;

	(void)inode;

	mutex_lock(&sep->exchange_lock);
	while (sep->acm_context_active && !sep->acm_poisoned &&
	       cleanup_attempts++ < 2) {
		memcpy(request + 8, sep->acm_context,
		       sizeof(sep->acm_context));
		response = NULL;
		response_length = 0;
		response_info = 0;
		ret = t2_acm_exchange_locked(sep, 1, 0, request,
					     sizeof(request), &response,
					     &response_length, &response_info);
		if (!ret && !response_info && !response_length)
			ret = t2_acm_record_reply_locked(
				sep, request, response, response_length,
				response_info);
		else if (!ret)
			ret = -EREMOTEIO;
		if (ret) {
			dev_warn(&sep->pdev->dev,
				 "automatic ACM context cleanup failed; endpoint disabled until reboot\n");
			if (!sep->acm_poisoned)
				t2_acm_poison_locked(sep);
			break;
		}
	}
	if (sep->acm_context_active && !sep->acm_poisoned) {
		dev_warn(&sep->pdev->dev,
			 "automatic ACM context cleanup exceeded its fixed bound; endpoint disabled until reboot\n");
		t2_acm_poison_locked(sep);
	}
	t2_aks_clear_authorization_locked(sep);
	memzero_explicit(sep->acm_ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->acm_ool_out, T2_SEP_OOL_SIZE);
	mutex_unlock(&sep->exchange_lock);
	memzero_explicit(request, sizeof(request));
	atomic_set(&sep->acm_opened, 0);
	return 0;
}

static const struct file_operations t2_acm_fops = {
	.owner = THIS_MODULE,
	.open = t2_acm_open,
	.release = t2_acm_release,
	.unlocked_ioctl = t2_acm_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static int t2_aks_probe_capabilities(struct t2_sep_transport *sep)
{
	u8 request[16] = { };
	u8 *response = NULL;
	size_t response_length = 0;
	s8 sep_status = 0;
	u32 status;
	u64 capability;
	int ret;

	/* Request payload: result=0, selector=1, empty input blob. */
	put_unaligned_le64(1, request + sizeof(__le32));
	ret = t2_aks_exchange_locked(sep, T2_SEP_AKS_GET_CAPABILITIES,
				     request, sizeof(request), &response,
				     &response_length, &sep_status);
	if (ret)
		return ret;
	if (response_length < 12)
		return -EPROTO;
	status = get_unaligned_le32(response);
	capability = get_unaligned_le64(response + sizeof(__le32));
	if (status) {
		dev_warn(&sep->pdev->dev,
			 "AppleKeyStore capability query returned status %#x\n",
			 status);
		return -EREMOTEIO;
	}

	dev_info(&sep->pdev->dev,
		 "AppleKeyStore capability reply passed integrity check: value=%#llx length=%zu negotiated_header=v%u\n",
		 (unsigned long long)capability, response_length,
		 sep->aks_header_version);
	return 0;
}

static void t2_sep_free_ool(struct t2_sep_transport *sep)
{
	if (sep->acm_ool_out)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->acm_ool_out, sep->acm_ool_out_dma);
	if (sep->acm_ool_in)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->acm_ool_in, sep->acm_ool_in_dma);
	if (sep->ool_out)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->ool_out, sep->ool_out_dma);
	if (sep->ool_in)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->ool_in, sep->ool_in_dma);
}

static int t2_sep_probe(struct pci_dev *pdev,
			const struct pci_device_id *id)
{
	struct t2_sep_transport *sep;
	u32 inbox, outbox;
	int ret;

	if (pci_resource_len(pdev, T2_SEP_MAILBOX_BAR) < T2_SEP_BAR_MIN_SIZE)
		return -ENODEV;

	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "cannot enable PCI function\n");

	ret = pcim_iomap_regions(pdev, BIT(T2_SEP_MAILBOX_BAR),
				 "t2_sep_transport");
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "cannot map BAR4\n");

	sep = devm_kzalloc(&pdev->dev, sizeof(*sep), GFP_KERNEL);
	if (!sep)
		return -ENOMEM;
	sep->pdev = pdev;
	sep->bar = pcim_iomap_table(pdev)[T2_SEP_MAILBOX_BAR];
	if (!sep->bar)
		return -ENODEV;
	mutex_init(&sep->exchange_lock);
	atomic_set(&sep->aks_opened, 0);
	atomic_set(&sep->acm_opened, 0);
	sep->aks_header_version = T2_AKS_HEADER_VERSION_1;
	get_random_bytes(sep->aks_connection_generation,
			 sizeof(sep->aks_connection_generation));
	if (!memchr_inv(sep->aks_connection_generation, 0,
			sizeof(sep->aks_connection_generation)))
		sep->aks_connection_generation[0] = 1;
	pci_set_drvdata(pdev, sep);

	inbox = readl(sep->bar + T2_SEP_INBOX_STATUS);
	outbox = readl(sep->bar + T2_SEP_OUTBOX_STATUS);
	dev_info(&pdev->dev, "mailbox inbox=%#x empty=%u outbox=%#x full=%u\n",
		 inbox, !!(inbox & T2_SEP_INBOX_EMPTY),
		 outbox, !!(outbox & T2_SEP_OUTBOX_FULL));

	if (mirror_apple_start)
		t2_sep_mirror_apple_start(sep);
	if (inventory_only &&
	    (!register_ool || register_acm || probe_capabilities))
		return dev_err_probe(&pdev->dev, -EINVAL,
			"inventory_only requires register_ool=1 with ACM and capability probing disabled\n");
	if (enable_identity_provisioning &&
	    (!register_ool || !register_acm || !probe_capabilities ||
	     inventory_only))
		return dev_err_probe(&pdev->dev, -EINVAL,
			"identity provisioning requires endpoint-7 and ACM OOL, successful capability probing, and inventory_only=0\n");
	if (enable_identity_replacement && !enable_identity_provisioning)
		return dev_err_probe(&pdev->dev, -EINVAL,
			"identity replacement requires identity provisioning to be enabled\n");
	if (retain_runtime_handle &&
	    (!register_ool || !register_acm || inventory_only ||
	     enable_identity_provisioning || enable_identity_replacement))
		return dev_err_probe(&pdev->dev, -EINVAL,
			"compatibility runtime retention requires endpoint-7 and ACM only\n");

	if (!register_ool) {
		dev_info(&pdev->dev,
			 "observation-only mode; no DMA allocation or mailbox writes%s\n",
			 mirror_apple_start ? " after the requested start sequence" : "");
		return 0;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev,
					DMA_BIT_MASK(T2_SEP_DMA_BITS));
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "no usable 44-bit DMA mask\n");
	pci_set_master(pdev);
	sep->ool_in = dma_alloc_coherent(&pdev->dev, T2_SEP_OOL_SIZE,
					 &sep->ool_in_dma, GFP_KERNEL);
	if (!sep->ool_in) {
		ret = -ENOMEM;
		goto err_free_ool;
	}
	sep->ool_out = dma_alloc_coherent(&pdev->dev, T2_SEP_OOL_SIZE,
					  &sep->ool_out_dma, GFP_KERNEL);
	if (!sep->ool_out) {
		ret = -ENOMEM;
		goto err_free_ool;
	}
	if (register_acm) {
		sep->acm_ool_in = dma_alloc_coherent(&pdev->dev,
			T2_SEP_OOL_SIZE, &sep->acm_ool_in_dma, GFP_KERNEL);
		if (!sep->acm_ool_in) {
			ret = -ENOMEM;
			goto err_free_ool;
		}
		sep->acm_ool_out = dma_alloc_coherent(&pdev->dev,
			T2_SEP_OOL_SIZE, &sep->acm_ool_out_dma, GFP_KERNEL);
		if (!sep->acm_ool_out) {
			ret = -ENOMEM;
			goto err_free_ool;
		}
	}
	ret = t2_sep_control(sep, T2_SEP_AKS_ENDPOINT,
			 T2_SEP_CMSG_SET_OOL_IN, 1,
				 sep->ool_in_dma, T2_SEP_OOL_SIZE);
	if (ret) {
		goto err_free_ool;
	}
	sep->ool_in_registered = true;
	ret = t2_sep_control(sep, T2_SEP_AKS_ENDPOINT,
			 T2_SEP_CMSG_SET_OOL_OUT, 2,
				 sep->ool_out_dma, T2_SEP_OOL_SIZE);
	if (ret) {
		/*
		 * SEP now retains ool_in_dma.  Never free or unload backing memory
		 * after a successful registration, even when the second control call
		 * fails.  A reboot clears the volatile SEP registration.
		 */
		dev_err(&pdev->dev,
			"OOL input registered but output registration failed; reboot before retry\n");
		__module_get(THIS_MODULE);
		return 0;
	}
	sep->ool_out_registered = true;
	if (register_acm) {
		ret = t2_sep_control(sep, T2_SEP_ACM_ENDPOINT,
				 T2_SEP_CMSG_SET_OOL_IN, 3,
				 sep->acm_ool_in_dma, T2_SEP_OOL_SIZE);
		if (ret) {
			dev_err(&pdev->dev,
				"endpoint-7 registered but ACM input registration failed; reboot before retry\n");
			__module_get(THIS_MODULE);
			return 0;
		}
		sep->acm_ool_in_registered = true;
		ret = t2_sep_control(sep, T2_SEP_ACM_ENDPOINT,
				 T2_SEP_CMSG_SET_OOL_OUT, 4,
				 sep->acm_ool_out_dma, T2_SEP_OOL_SIZE);
		if (ret) {
			dev_err(&pdev->dev,
				"ACM input registered but output registration failed; reboot before retry\n");
			__module_get(THIS_MODULE);
			return 0;
		}
		sep->acm_ool_out_registered = true;
		sep->acm_generation = 1;
	}
	/* SEP retains both DMA addresses, so prevent unsafe module removal. */
	__module_get(THIS_MODULE);

	dev_info(&pdev->dev,
		 "registered 16 KiB endpoint-7 OOL input/output buffers\n");
	if (probe_capabilities) {
		ret = t2_aks_probe_capabilities(sep);
		if (ret) {
			/*
			 * The DMA registrations are live and pinned, but endpoint 7 did
			 * not complete its read-only v1 negotiation.  Do not expose an
			 * exchange device that can only time out; a reboot is required
			 * before registration can be attempted again safely.
			 */
			dev_err(&pdev->dev,
				"AppleKeyStore capability negotiation failed: %d; /dev/t2-aks disabled until reboot\n",
				ret);
			return 0;
		}
		sep->next_transaction = 1;
	}

	sep->aks_miscdev.minor = MISC_DYNAMIC_MINOR;
	sep->aks_miscdev.name = "t2-aks";
	sep->aks_miscdev.fops = &t2_aks_fops;
	sep->aks_miscdev.parent = &pdev->dev;
	sep->aks_miscdev.mode = 0600;
	ret = misc_register(&sep->aks_miscdev);
	if (ret)
		dev_warn(&pdev->dev,
			 "cannot register root-only AppleKeyStore exchange device: %d\n",
			 ret);
	else {
		sep->misc_registered = true;
		if (inventory_only)
			dev_info(&pdev->dev,
				 "root-only /dev/t2-aks enabled for primary-identity inventory only\n");
		else
			dev_info(&pdev->dev,
				 "root-only /dev/t2-aks exchange enabled for whitelisted operations\n");
	}
	if (register_acm) {
		sep->acm_miscdev.minor = MISC_DYNAMIC_MINOR;
		sep->acm_miscdev.name = "t2-acm";
		sep->acm_miscdev.fops = &t2_acm_fops;
		sep->acm_miscdev.parent = &pdev->dev;
		sep->acm_miscdev.mode = 0600;
		ret = misc_register(&sep->acm_miscdev);
		if (ret)
			dev_warn(&pdev->dev,
				 "cannot register root-only ACM exchange device: %d\n",
				 ret);
		else {
			sep->acm_misc_registered = true;
			dev_info(&pdev->dev,
				 "root-only generation-pinned /dev/t2-acm enabled\n");
		}
	}
	return 0;

err_free_ool:
	t2_sep_free_ool(sep);
	sep->ool_in = NULL;
	sep->ool_out = NULL;
	pci_clear_master(pdev);
	return ret;
}

static void t2_sep_remove(struct pci_dev *pdev)
{
	struct t2_sep_transport *sep = pci_get_drvdata(pdev);

	if (!sep || !register_ool)
		return;
	if (sep->misc_registered)
		misc_deregister(&sep->aks_miscdev);
	if (sep->acm_misc_registered)
		misc_deregister(&sep->acm_miscdev);
	if (sep->ool_in_registered || sep->ool_out_registered ||
	    sep->acm_ool_in_registered || sep->acm_ool_out_registered) {
		dev_warn(&pdev->dev,
			 "retaining SEP-registered DMA memory until reboot\n");
		return;
	}
	t2_sep_free_ool(sep);
	pci_clear_master(pdev);
}

static const struct pci_device_id t2_sep_ids[] = {
	{ PCI_DEVICE(T2_SEP_VENDOR_ID, T2_SEP_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, t2_sep_ids);

static struct pci_driver t2_sep_driver = {
	.name = "t2_sep_transport",
	.id_table = t2_sep_ids,
	.probe = t2_sep_probe,
	.remove = t2_sep_remove,
};
module_pci_driver(t2_sep_driver);

MODULE_AUTHOR("T2 Touch ID Linux research project");
MODULE_DESCRIPTION("Staged Apple T2 SEP mailbox and OOL transport");
MODULE_LICENSE("GPL");
