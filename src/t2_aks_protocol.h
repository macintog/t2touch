/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef T2_AKS_PROTOCOL_H
#define T2_AKS_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
typedef u8 t2_aks_wire_u8;
typedef u32 t2_aks_wire_u32;
typedef u64 t2_aks_wire_u64;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t t2_aks_wire_u8;
typedef uint32_t t2_aks_wire_u32;
typedef uint64_t t2_aks_wire_u64;
#endif

#define T2_AKS_HEADER_VERSION_1 1U
#define T2_AKS_HEADER_VERSION_2 2U
#define T2_AKS_SAVED_KEYBAG_MAX 16000U
#define T2_AKS_UNLOCK_SECRET_MAX 1023U
#define T2_AKS_ACM_EXTERNAL_FORM_SIZE 16U

static inline t2_aks_wire_u32
t2_aks_wire_get_le32(const t2_aks_wire_u8 *value)
{
	return (t2_aks_wire_u32)value[0] |
	       ((t2_aks_wire_u32)value[1] << 8) |
	       ((t2_aks_wire_u32)value[2] << 16) |
	       ((t2_aks_wire_u32)value[3] << 24);
}

static inline t2_aks_wire_u64
t2_aks_wire_get_le64(const t2_aks_wire_u8 *value)
{
	return (t2_aks_wire_u64)t2_aks_wire_get_le32(value) |
	       ((t2_aks_wire_u64)t2_aks_wire_get_le32(value + 4) << 32);
}

static inline bool t2_aks_special_alias(t2_aks_wire_u32 handle)
{
	/* Linux user aliases are the proven signed range -10 .. INT32_MIN. */
	return handle >= 0x80000000U && handle <= 0xfffffff6U;
}

static inline bool
t2_aks_zero_padding(const t2_aks_wire_u8 *value, size_t length,
		    size_t padded_length)
{
	size_t index;

	if (!value || padded_length < length)
		return false;
	for (index = length; index < padded_length; index++) {
		if (value[index])
			return false;
	}
	return true;
}

static inline bool
t2_aks_load_keybag_request_allowed(const t2_aks_wire_u8 *request,
				   size_t length)
{
	size_t blob_length, padded_length;

	if (!request || length < 20 || t2_aks_wire_get_le32(request) != 0 ||
	    t2_aks_wire_get_le64(request + 4) != 1)
		return false;
	blob_length = t2_aks_wire_get_le32(request + 12);
	if (!blob_length || blob_length > T2_AKS_SAVED_KEYBAG_MAX)
		return false;
	padded_length = (blob_length + 3U) & ~(size_t)3U;
	return length == 16 + padded_length &&
	       t2_aks_zero_padding(request + 16, blob_length, padded_length);
}

static inline bool
t2_aks_load_keybag_response_valid(const t2_aks_wire_u8 *response,
				  size_t length,
				  t2_aks_wire_u32 *handle_out)
{
	t2_aks_wire_u32 handle;

	if (!response || !handle_out || length != 8 ||
	    t2_aks_wire_get_le32(response) != 0)
		return false;
	handle = t2_aks_wire_get_le32(response + 4);
	if (!handle || handle > 0x7fffffffU)
		return false;
	*handle_out = handle;
	return true;
}

static inline bool
t2_aks_unload_keybag_request_matches(const t2_aks_wire_u8 *request,
				     size_t length,
				     t2_aks_wire_u64 session,
				     t2_aks_wire_u32 handle)
{
	/* Match the kernel-owned session: creation/recovery need not use 1. */
	return request && length == 16 && session && handle &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       t2_aks_wire_get_le32(request + 12) == handle;
}

static inline bool
t2_aks_status_response_valid(const t2_aks_wire_u8 *response, size_t length)
{
	return response && length == 4;
}

static inline bool
t2_aks_lock_state_response_valid(const t2_aks_wire_u8 *response, size_t length)
{
	/* Result word followed by lock-state value and 64-bit flags. */
	return response && length == 16;
}

static inline bool
t2_aks_bind_alias_request_matches(const t2_aks_wire_u8 *request,
				  size_t length,
				  t2_aks_wire_u64 session,
				  t2_aks_wire_u32 handle)
{
	return request && length == 24 && session == 1 && handle &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       t2_aks_wire_get_le32(request + 12) == handle &&
	       t2_aks_special_alias(t2_aks_wire_get_le32(request + 16)) &&
	       t2_aks_wire_get_le32(request + 20) == 0;
}

static inline bool
t2_aks_unlock_target_request_matches(const t2_aks_wire_u8 *request,
				     size_t length,
				     t2_aks_wire_u64 session,
				     t2_aks_wire_u32 target)
{
	size_t secret_length, padded_length;

	if (!request || length < 28 || t2_aks_wire_get_le32(request) != 0 ||
	    session != 1 || !target ||
	    t2_aks_wire_get_le64(request + 4) != session ||
	    t2_aks_wire_get_le32(request + 12) != target ||
	    t2_aks_wire_get_le32(request + 16) != 0)
		return false;
	secret_length = t2_aks_wire_get_le32(request + 20);
	if (!secret_length || secret_length > T2_AKS_UNLOCK_SECRET_MAX)
		return false;
	padded_length = (secret_length + 3U) & ~(size_t)3U;
	return length == 24 + padded_length &&
	       t2_aks_zero_padding(request + 24, secret_length, padded_length);
}

static inline bool
t2_aks_unlock_alias_request_allowed(const t2_aks_wire_u8 *request,
				    size_t length)
{
	return request &&
	       t2_aks_special_alias(t2_aks_wire_get_le32(request + 12)) &&
	       t2_aks_unlock_target_request_matches(
		       request, length, 1,
		       t2_aks_wire_get_le32(request + 12));
}

/*
 * Raw operation 0x18 is the matching AppleKeyStore kext's credential-bearing
 * device-state transition.  Selector 0x9a supplies transition zero, flag
 * 0x100, and the exact 16-byte original ACM login credential.  A separately
 * authorized policy target must remain live while Linux admits this request.
 * Linux admits no other transition, flag combination, alias class, or
 * credential shape.
 */
static inline bool
t2_aks_acm_unlock_request_allowed(const t2_aks_wire_u8 *request, size_t length)
{
	size_t index;
	bool nonzero = false;

	if (!request || length != 48 ||
	    t2_aks_wire_get_le32(request) != 0 ||
	    t2_aks_wire_get_le64(request + 4) != 1 ||
	    !t2_aks_special_alias(t2_aks_wire_get_le32(request + 12)) ||
	    t2_aks_wire_get_le32(request + 16) != 0 ||
	    t2_aks_wire_get_le64(request + 20) != 0x100 ||
	    t2_aks_wire_get_le32(request + 28) !=
		    T2_AKS_ACM_EXTERNAL_FORM_SIZE)
		return false;
	for (index = 0; index < T2_AKS_ACM_EXTERNAL_FORM_SIZE; index++)
		nonzero |= request[32 + index] != 0;
	return nonzero;
}

static inline bool
t2_aks_acm_unlock_context_matches(const t2_aks_wire_u8 *request,
				  size_t length,
				  const t2_aks_wire_u8 *context)
{
	return context && t2_aks_acm_unlock_request_allowed(request, length) &&
	       !memcmp(request + 32, context, T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

static inline bool
t2_aks_identity_login_context_allowed(
	const t2_aks_wire_u8 *request, size_t length,
	const t2_aks_wire_u8 *identity_input,
	const t2_aks_wire_u8 *authorized_target,
	const t2_aks_wire_u8 *active_target, bool identity_input_live,
	bool identity_input_consumed, bool identity_target_created,
	bool password_bound)
{
	return identity_input_live && identity_input_consumed &&
	       identity_target_created && password_bound && identity_input &&
	       authorized_target && active_target &&
	       memcmp(identity_input, active_target,
		      T2_AKS_ACM_EXTERNAL_FORM_SIZE) &&
	       !memcmp(authorized_target, active_target,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE) &&
	       t2_aks_acm_unlock_context_matches(request, length,
					 identity_input);
}

static inline bool
t2_aks_acm_unlock_response_valid(const t2_aks_wire_u8 *response,
				 size_t length)
{
	return response && length == 20 &&
	       t2_aks_wire_get_le32(response) == 0;
}

static inline bool
t2_aks_get_device_state_v1_request_allowed(const t2_aks_wire_u8 *request,
					   size_t length)
{
	return request && length == 24 &&
	       t2_aks_wire_get_le32(request) == 1 &&
	       t2_aks_wire_get_le64(request + 4) == 1 &&
	       t2_aks_wire_get_le32(request + 12) != 0 &&
	       t2_aks_wire_get_le32(request + 16) == 0 &&
	       t2_aks_wire_get_le32(request + 20) == 0;
}

static inline bool
t2_aks_get_device_state_v1_response_valid(const t2_aks_wire_u8 *response,
					  size_t length)
{
	size_t blob_length, padded_length;

	if (!response || length < 12 || t2_aks_wire_get_le32(response) != 1)
		return false;
	blob_length = t2_aks_wire_get_le32(response + 4);
	if (!blob_length)
		return false;
	padded_length = (blob_length + 3U) & ~(size_t)3U;
	return length == 8 + padded_length &&
	       t2_aks_zero_padding(response + 8, blob_length, padded_length);
}

static inline bool
t2_aks_copy_keybag_uuid_response_valid(const t2_aks_wire_u8 *response,
				       size_t length)
{
	size_t index;
	bool nonzero = false;

	if (!response || length != 24 ||
	    t2_aks_wire_get_le32(response) != 0 ||
	    t2_aks_wire_get_le32(response + 4) != 16)
		return false;
	for (index = 0; index < 16; index++)
		nonzero |= response[8 + index] != 0;
	return nonzero;
}

static inline bool
t2_aks_copy_keybag_uuid_absent_response(const t2_aks_wire_u8 *response,
					size_t length)
{
	return response && length == 8 &&
	       t2_aks_wire_get_le32(response) == (t2_aks_wire_u32)-3 &&
	       t2_aks_wire_get_le32(response + 4) == 0;
}

/*
 * Raw operation 0x23 is the matching AppleKeyStore kext's get_configuration
 * IPC.  Its request codec is the same session-1 negative-alias shape as
 * copy_keybag_uuid.  The successful response is a status-zero opaque blob;
 * Linux validates its envelope and never interprets or publishes the blob.
 */
static inline bool
t2_aks_get_configuration_request_allowed(const t2_aks_wire_u8 *request,
					 size_t length)
{
	return request && length == 16 &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == 1 &&
	       t2_aks_special_alias(t2_aks_wire_get_le32(request + 12));
}

static inline bool
t2_aks_get_configuration_response_valid(const t2_aks_wire_u8 *response,
					size_t length)
{
	size_t blob_length, padded_length;

	if (!response || length < 12 || t2_aks_wire_get_le32(response) != 0)
		return false;
	blob_length = t2_aks_wire_get_le32(response + 4);
	if (!blob_length)
		return false;
	padded_length = (blob_length + 3U) & ~(size_t)3U;
	return padded_length >= blob_length && length == 8 + padded_length &&
	       t2_aks_zero_padding(response + 8, blob_length, padded_length);
}

/*
 * Capability negotiation itself always uses v1.  The matching Apple host
 * starts at v1 and upgrades only after a successful capability reply; a
 * timeout or malformed reply must therefore leave normal traffic on v1.
 */
static inline t2_aks_wire_u32
t2_aks_header_version_after_capabilities(t2_aks_wire_u32 current_version,
					  t2_aks_wire_u32 status,
					  t2_aks_wire_u64 capability)
{
	if (current_version != T2_AKS_HEADER_VERSION_1 &&
	    current_version != T2_AKS_HEADER_VERSION_2)
		return T2_AKS_HEADER_VERSION_1;
	if (status)
		return current_version;
	return capability >= T2_AKS_HEADER_VERSION_2 ?
		T2_AKS_HEADER_VERSION_2 : T2_AKS_HEADER_VERSION_1;
}

static inline bool
t2_aks_capabilities_request_allowed(const t2_aks_wire_u8 *request,
				    size_t length)
{
	return request && length == 16 &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == 1 &&
	       t2_aks_wire_get_le32(request + 12) == 0;
}

/*
 * Raw operation 0x06 is the matching AppleKeyStore kext's read-only
 * copy_keybag_uuid IPC.  Linux permits only the proven session-1 request:
 * zero result placeholder, owning session, and a proven negative user alias.
 * A positive live handle is admitted separately only when the kernel recorded
 * it from this descriptor's exact load-keybag success reply.
 */
static inline bool
t2_aks_copy_keybag_uuid_request_allowed(const t2_aks_wire_u8 *request,
					 size_t length)
{
	return request && length == 16 &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == 1 &&
	       t2_aks_special_alias(t2_aks_wire_get_le32(request + 12));
}

static inline bool
t2_aks_copy_keybag_uuid_request_matches(const t2_aks_wire_u8 *request,
					 size_t length,
					 t2_aks_wire_u64 session,
					 t2_aks_wire_u32 handle)
{
	return request && length == 16 && session && handle &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       t2_aks_wire_get_le32(request + 12) == handle;
}

/*
 * Raw operation 0x51 multiplexes three identity operations.  Permit only
 * identity_get_primary's read-only operation-0 record: result placeholder,
 * nonzero generation session, operation 0, two -1 selectors, and two empty
 * input blobs.  This exact check keeps transfer-primary operations 1 and 2
 * outside the Linux ABI.
 */
static inline bool
t2_aks_get_primary_identity_request_allowed(const t2_aks_wire_u8 *request,
					     size_t length)
{
	return request && length == 36 &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) != 0 &&
	       t2_aks_wire_get_le64(request + 12) == 0 &&
	       t2_aks_wire_get_le32(request + 20) == (t2_aks_wire_u32)-1 &&
	       t2_aks_wire_get_le32(request + 24) == 0 &&
	       t2_aks_wire_get_le32(request + 28) == (t2_aks_wire_u32)-1 &&
	       t2_aks_wire_get_le32(request + 32) == 0;
}

static inline bool
t2_aks_get_primary_identity_absent_response(const t2_aks_wire_u8 *response,
					     size_t length)
{
	return response && length == 8 &&
	       t2_aks_wire_get_le32(response) == (t2_aks_wire_u32)-3 &&
	       t2_aks_wire_get_le32(response + 4) == 0;
}

/*
 * Matching identity_delete uses operation 0x49 with one empty compatibility
 * blob followed by the exact 16-byte durable account UUID.  The state machine
 * must additionally match that UUID and session against its replacement
 * transaction; these helpers alone do not expose the mutating operation.
 */
static inline bool
t2_aks_identity_delete_request_allowed(const t2_aks_wire_u8 *request,
				       size_t length)
{
	size_t index;
	bool nonzero = false;

	if (!request || length != 36 ||
	    t2_aks_wire_get_le32(request) != 0 ||
	    t2_aks_wire_get_le64(request + 4) == 0 ||
	    t2_aks_wire_get_le32(request + 12) != 0 ||
	    t2_aks_wire_get_le32(request + 16) !=
		    T2_AKS_ACM_EXTERNAL_FORM_SIZE)
		return false;
	for (index = 0; index < T2_AKS_ACM_EXTERNAL_FORM_SIZE; index++)
		nonzero |= request[20 + index] != 0;
	return nonzero;
}

static inline bool
t2_aks_identity_delete_request_matches(
	const t2_aks_wire_u8 *request, size_t length, t2_aks_wire_u64 session,
	const t2_aks_wire_u8 account_uuid[T2_AKS_ACM_EXTERNAL_FORM_SIZE])
{
	return account_uuid && session &&
	       t2_aks_identity_delete_request_allowed(request, length) &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       !memcmp(request + 20, account_uuid,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

static inline bool
t2_aks_identity_delete_response_valid(const t2_aks_wire_u8 *response,
				      size_t length)
{
	return response && length == 4 &&
	       t2_aks_wire_get_le32(response) == 0;
}

/*
 * Recovery identity_open reuses operation 0x03 but only with the journaled
 * new account UUID, never an arbitrary saved-keybag blob.  It therefore has
 * a fixed 32-byte body and the ordinary positive-handle response envelope.
 */
static inline bool
t2_aks_identity_open_request_allowed(const t2_aks_wire_u8 *request,
				     size_t length)
{
	size_t index;
	bool nonzero = false;

	if (!request || length != 32 ||
	    t2_aks_wire_get_le32(request) != 0 ||
	    t2_aks_wire_get_le64(request + 4) == 0 ||
	    t2_aks_wire_get_le32(request + 12) !=
		    T2_AKS_ACM_EXTERNAL_FORM_SIZE)
		return false;
	for (index = 0; index < T2_AKS_ACM_EXTERNAL_FORM_SIZE; index++)
		nonzero |= request[16 + index] != 0;
	return nonzero;
}

static inline bool
t2_aks_identity_open_request_matches(
	const t2_aks_wire_u8 *request, size_t length, t2_aks_wire_u64 session,
	const t2_aks_wire_u8 account_uuid[T2_AKS_ACM_EXTERNAL_FORM_SIZE])
{
	return account_uuid && session &&
	       t2_aks_identity_open_request_allowed(request, length) &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       !memcmp(request + 16, account_uuid,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

/*
 * Exact internal-storage request-10 identity-create candidate.  These
 * validators are deliberately not sufficient to expose operations 0x01/0x02:
 * the transport additionally requires an off-by-default provisioning mode,
 * negotiated v2 headers, and one kernel-owned create/export phase.
 */
static inline bool
t2_aks_identity_create_v5_request_allowed(const t2_aks_wire_u8 *request,
					   size_t length)
{
	size_t index;
	bool account_nonzero = false;
	bool context_nonzero = false;

	if (!request || length != 88 ||
	    t2_aks_wire_get_le32(request) != 5 ||
	    t2_aks_wire_get_le64(request + 4) == 0 ||
	    t2_aks_wire_get_le32(request + 12) != 0x4100 ||
	    t2_aks_wire_get_le32(request + 16) != (t2_aks_wire_u32)-1 ||
	    t2_aks_wire_get_le32(request + 20) != 16 ||
	    t2_aks_wire_get_le32(request + 40) != 0 ||
	    t2_aks_wire_get_le32(request + 44) != 16 ||
	    t2_aks_wire_get_le32(request + 64) != 0 ||
	    t2_aks_wire_get_le64(request + 68) != 6 ||
	    t2_aks_wire_get_le64(request + 76) != 0 ||
	    t2_aks_wire_get_le32(request + 84) != 0)
		return false;
	for (index = 0; index < 16; index++) {
		context_nonzero |= request[24 + index] != 0;
		account_nonzero |= request[48 + index] != 0;
	}
	return context_nonzero && account_nonzero;
}

static inline bool
t2_aks_identity_create_v5_replacement_matches(
	const t2_aks_wire_u8 *request, size_t length, t2_aks_wire_u64 session,
	const t2_aks_wire_u8 account_uuid[T2_AKS_ACM_EXTERNAL_FORM_SIZE],
	const t2_aks_wire_u8 activation_material[T2_AKS_ACM_EXTERNAL_FORM_SIZE])
{
	return account_uuid && activation_material && session &&
	       t2_aks_identity_create_v5_request_allowed(request, length) &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       !memcmp(request + 24, activation_material,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE) &&
	       !memcmp(request + 48, account_uuid,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

static inline bool
t2_aks_identity_copy_keybag_v1_request_allowed(const t2_aks_wire_u8 *request,
						 size_t length)
{
	return request && length == 20 &&
	       t2_aks_wire_get_le32(request) == 1 &&
	       t2_aks_wire_get_le64(request + 4) != 0 &&
	       t2_aks_wire_get_le32(request + 12) != 0 &&
	       t2_aks_wire_get_le32(request + 16) == 0;
}

static inline bool
t2_aks_identity_create_v5_response_valid(const t2_aks_wire_u8 *response,
					  size_t length,
					  t2_aks_wire_u32 *handle_out)
{
	t2_aks_wire_u32 handle, blob_length;
	size_t padded_length, index;

	if (!response || !handle_out || length < 12 ||
	    t2_aks_wire_get_le32(response) != 5)
		return false;
	handle = t2_aks_wire_get_le32(response + 4);
	blob_length = t2_aks_wire_get_le32(response + 8);
	padded_length = (blob_length + 3U) & ~(size_t)3U;
	if (!handle || handle > 0x7fffffffU || padded_length < blob_length ||
	    length != 12 + padded_length)
		return false;
	for (index = blob_length; index < padded_length; index++) {
		if (response[12 + index] != 0)
			return false;
	}
	*handle_out = handle;
	return true;
}

static inline bool
t2_aks_identity_copy_keybag_v1_response_valid(
	const t2_aks_wire_u8 *response, size_t length)
{
	t2_aks_wire_u32 blob_length;
	size_t padded_length, index;

	if (!response || length < 8 || t2_aks_wire_get_le32(response) != 1)
		return false;
	blob_length = t2_aks_wire_get_le32(response + 4);
	padded_length = (blob_length + 3U) & ~(size_t)3U;
	if (!blob_length || padded_length < blob_length ||
	    length != 8 + padded_length)
		return false;
	for (index = blob_length; index < padded_length; index++) {
		if (response[8 + index] != 0)
			return false;
	}
	return true;
}

/*
 * Root-only operation 0x21 is intentionally narrower than the Apple ABI.
 * Selector 42 uses plaintext option 0x200 with either the exact 16-byte ACM
 * external form or the zero-context stage-isolation diagnostic.  Apple's
 * identity-verification path uses option 0x100: its secret is one exact
 * 16-byte externalized ACM input reference containing type-5 password data.
 * The verify-only form omits an output context; the authorization form names
 * a distinct exact context being authorized.
 * Live handle and both reference lifetimes are checked by the transport phase
 * machine.
 */
static inline bool
t2_aks_verify_secret_v1_request_allowed(const t2_aks_wire_u8 *request,
					    size_t length)
{
	size_t password_length, padded_length, context_length, expected_length;
	t2_aks_wire_u64 options, session;
	t2_aks_wire_u32 handle;
	size_t offset;

	if (!request || length < 36 || t2_aks_wire_get_le32(request) != 1)
		return false;
	session = t2_aks_wire_get_le64(request + 4);
	handle = t2_aks_wire_get_le32(request + 12);
	if (session != 1 || handle == 0)
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	if (!password_length || password_length > 128)
		return false;
	padded_length = (password_length + 3) & ~(size_t)3;
	if (length < 32 + padded_length)
		return false;
	for (offset = password_length; offset < padded_length; offset++) {
		if (request[20 + offset] != 0)
			return false;
	}
	context_length = t2_aks_wire_get_le32(request + 20 + padded_length);
	if (context_length != 0 && context_length != 16)
		return false;
	expected_length = 32 + padded_length + context_length;
	if (length != expected_length)
		return false;
	options = t2_aks_wire_get_le64(request + 24 + padded_length +
				       context_length);
	return options == 0x200 ||
	       (options == 0x100 &&
		password_length == T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

static inline bool
t2_aks_verify_secret_v1_identity_request_allowed(
	const t2_aks_wire_u8 *request, size_t length)
{
	size_t password_length, padded_length, context_length;

	if (!t2_aks_verify_secret_v1_request_allowed(request, length))
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	padded_length = (password_length + 3U) & ~(size_t)3U;
	context_length = t2_aks_wire_get_le32(request + 20 + padded_length);
	return password_length == T2_AKS_ACM_EXTERNAL_FORM_SIZE &&
	       context_length == T2_AKS_ACM_EXTERNAL_FORM_SIZE &&
	       t2_aks_wire_get_le64(request + 24 + padded_length +
				     context_length) == 0x100;
}

static inline bool
t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
	const t2_aks_wire_u8 *request, size_t length)
{
	size_t password_length, padded_length, context_length;

	if (!t2_aks_verify_secret_v1_request_allowed(request, length))
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	padded_length = (password_length + 3U) & ~(size_t)3U;
	context_length = t2_aks_wire_get_le32(request + 20 + padded_length);
	return password_length == T2_AKS_ACM_EXTERNAL_FORM_SIZE &&
	       context_length == 0 &&
	       t2_aks_wire_get_le64(request + 24 + padded_length) == 0x100;
}

static inline bool
t2_aks_verify_secret_v1_selector42_request_allowed(
	const t2_aks_wire_u8 *request, size_t length)
{
	size_t password_length, padded_length, context_length;

	if (!t2_aks_verify_secret_v1_request_allowed(request, length))
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	padded_length = (password_length + 3U) & ~(size_t)3U;
	context_length = t2_aks_wire_get_le32(request + 20 + padded_length);
	return t2_aks_wire_get_le64(request + 24 + padded_length +
				     context_length) == 0x200;
}

static inline bool
t2_aks_verify_secret_v1_context_matches(const t2_aks_wire_u8 *request,
					 size_t length,
					 const t2_aks_wire_u8 context[16])
{
	size_t password_length, padded_length, context_offset, index;

	if (!context ||
	    !t2_aks_verify_secret_v1_request_allowed(request, length))
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	padded_length = (password_length + 3U) & ~(size_t)3U;
	if (t2_aks_wire_get_le32(request + 20 + padded_length) != 16)
		return false;
	context_offset = 24 + padded_length;
	for (index = 0; index < 16; index++) {
		if (request[context_offset + index] != context[index])
			return false;
	}
	return true;
}

static inline bool
t2_aks_verify_secret_v1_identity_secret_matches(
	const t2_aks_wire_u8 *request, size_t length,
	const t2_aks_wire_u8 secret_reference[T2_AKS_ACM_EXTERNAL_FORM_SIZE])
{
	if (!secret_reference ||
	    (!t2_aks_verify_secret_v1_identity_request_allowed(request, length) &&
	     !t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
		     request, length)))
		return false;
	return !memcmp(request + 20, secret_reference,
		       T2_AKS_ACM_EXTERNAL_FORM_SIZE);
}

static inline bool
t2_aks_verify_secret_v1_identity_references_distinct(
	const t2_aks_wire_u8 *request, size_t length)
{
	if (!t2_aks_verify_secret_v1_identity_request_allowed(request, length))
		return false;
	return memcmp(request + 20, request + 40,
		      T2_AKS_ACM_EXTERNAL_FORM_SIZE) != 0;
}

static inline bool
t2_aks_verify_secret_v1_runtime_target_matches(
	const t2_aks_wire_u8 *request, size_t length,
	t2_aks_wire_u64 session, t2_aks_wire_u32 target_handle)
{
	return (t2_aks_verify_secret_v1_identity_request_allowed(request, length) ||
		t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
			request, length)) &&
	       t2_aks_wire_get_le64(request + 4) == session &&
	       t2_aks_wire_get_le32(request + 12) == target_handle;
}

static inline bool
t2_aks_verify_secret_v1_response_valid(const t2_aks_wire_u8 *response,
					 size_t length)
{
	return response && length == 12 &&
	       t2_aks_wire_get_le32(response) == 1;
}

#endif /* T2_AKS_PROTOCOL_H */
