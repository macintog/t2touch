// SPDX-License-Identifier: GPL-2.0-only
#include "../src/t2_aks_protocol.h"
#include "../src/t2_sep_transport_uapi.h"

#include <assert.h>
#include <string.h>

static void put_le32(unsigned char *value, uint32_t number)
{
	value[0] = number;
	value[1] = number >> 8;
	value[2] = number >> 16;
	value[3] = number >> 24;
}

static void put_le64(unsigned char *value, uint64_t number)
{
	put_le32(value, (uint32_t)number);
	put_le32(value + 4, (uint32_t)(number >> 32));
}

static size_t make_request(unsigned char request[176], size_t password_length,
			   size_t context_length)
{
	size_t padded_length = (password_length + 3) & ~(size_t)3;
	size_t length = 32 + padded_length + context_length;

	memset(request, 0, 176);
	put_le32(request, 1);
	put_le64(request + 4, 1);
	put_le32(request + 12, (uint32_t)-501);
	put_le32(request + 16, (uint32_t)password_length);
	memset(request + 20, 'x', password_length);
	put_le32(request + 20 + padded_length, (uint32_t)context_length);
	memset(request + 24 + padded_length, 0xa5, context_length);
	put_le64(request + 24 + padded_length + context_length, 0x200);
	return length;
}

int main(void)
{
	assert(sizeof(struct t2_aks_ioc_replacement) == 64);
	assert(T2_AKS_REPLACEMENT_PHASE_DELETE == 1);
	assert(T2_AKS_REPLACEMENT_PHASE_CREATE == 2);
	assert(T2_AKS_REPLACEMENT_PHASE_RECOVER == 3);
	unsigned char request[176];
	unsigned char context[16];
	unsigned char authorization_target[16];
	unsigned char identity_reference[16];
	unsigned char verify_response[12] = { 0 };
	unsigned char create_request[88] = { 0 };
	unsigned char create_response[16] = { 0 };
	unsigned char export_request[20] = { 0 };
	unsigned char export_response[12] = { 0 };
	unsigned char capabilities_request[16] = { 0 };
	unsigned char primary_request[36] = { 0 };
	unsigned char primary_absent_response[8] = { 0 };
	unsigned char identity_delete_request[36] = { 0 };
	unsigned char identity_delete_response[4] = { 0 };
	unsigned char identity_open_request[32] = { 0 };
	unsigned char replacement_uuid[16] = { 1 };
	unsigned char uuid_request[16] = { 0 };
	unsigned char runtime_request[32] = { 0 };
	unsigned char runtime_response[24] = { 0 };
	unsigned char lock_state_response[16] = { 0 };
	unsigned char acm_unlock_request[48] = { 0 };
	unsigned char acm_unlock_response[20] = { 0 };
	uint32_t handle = 0;
	size_t length, index;

	put_le64(capabilities_request + 4, 1);
	assert(t2_aks_capabilities_request_allowed(capabilities_request,
						    sizeof(capabilities_request)));
	assert(!t2_aks_capabilities_request_allowed(capabilities_request, 15));
	put_le32(capabilities_request, 1);
	assert(!t2_aks_capabilities_request_allowed(capabilities_request,
						     sizeof(capabilities_request)));
	put_le32(capabilities_request, 0);
	put_le64(capabilities_request + 4, 2);
	assert(!t2_aks_capabilities_request_allowed(capabilities_request,
						     sizeof(capabilities_request)));
	put_le64(capabilities_request + 4, 1);
	put_le32(capabilities_request + 12, 1);
	assert(!t2_aks_capabilities_request_allowed(capabilities_request,
						     sizeof(capabilities_request)));
	assert(!t2_aks_capabilities_request_allowed(NULL, 16));

	assert(t2_aks_header_version_after_capabilities(1, 1, 2) == 1);
	assert(t2_aks_header_version_after_capabilities(1, 0, 0) == 1);
	assert(t2_aks_header_version_after_capabilities(1, 0, 1) == 1);
	assert(t2_aks_header_version_after_capabilities(1, 0, 2) == 2);
	assert(t2_aks_header_version_after_capabilities(1, 0, 3) == 2);
	assert(t2_aks_header_version_after_capabilities(2, 1, 1) == 2);
	assert(t2_aks_header_version_after_capabilities(99, 0, 2) == 1);

	put_le64(uuid_request + 4, 1);
	put_le32(uuid_request + 12, (uint32_t)-501);
	assert(t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request, 15));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request, 17));
	put_le32(uuid_request, 1);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	put_le32(uuid_request, 0);
	put_le64(uuid_request + 4, 2);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	put_le64(uuid_request + 4, 1);
	put_le32(uuid_request + 12, 0);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(NULL,
							 sizeof(uuid_request)));
	put_le64(uuid_request + 4, 7);
	put_le32(uuid_request + 12, 42);
	assert(t2_aks_copy_keybag_uuid_request_matches(
		uuid_request, sizeof(uuid_request), 7, 42));
	assert(!t2_aks_copy_keybag_uuid_request_matches(
		uuid_request, sizeof(uuid_request), 7, 41));

	put_le64(runtime_request + 4, 1);
	put_le32(runtime_request + 12, 3);
	memcpy(runtime_request + 16, "bag", 3);
	assert(t2_aks_load_keybag_request_allowed(runtime_request, 20));
	runtime_request[19] = 1;
	assert(!t2_aks_load_keybag_request_allowed(runtime_request, 20));
	runtime_request[19] = 0;
	put_le32(runtime_response + 4, 9);
	assert(t2_aks_load_keybag_response_valid(runtime_response, 8, &handle));
	assert(handle == 9);
	assert(t2_aks_unload_keybag_request_matches(
		runtime_request, 16, 1, 3));

	memset(runtime_request, 0, sizeof(runtime_request));
	put_le64(runtime_request + 4, 1);
	put_le32(runtime_request + 12, 9);
	put_le32(runtime_request + 16, (uint32_t)-501);
	assert(t2_aks_bind_alias_request_matches(runtime_request, 24, 1, 9));
	assert(t2_aks_lock_state_response_valid(
		lock_state_response, sizeof(lock_state_response)));
	assert(!t2_aks_lock_state_response_valid(lock_state_response, 4));
	put_le32(runtime_request + 20, 1);
	assert(!t2_aks_bind_alias_request_matches(runtime_request, 24, 1, 9));

	memset(runtime_request, 0, sizeof(runtime_request));
	put_le64(runtime_request + 4, 1);
	put_le32(runtime_request + 12, (uint32_t)-501);
	put_le32(runtime_request + 20, 3);
	memcpy(runtime_request + 24, "pw!", 3);
	assert(t2_aks_unlock_alias_request_allowed(runtime_request, 28));
	assert(t2_aks_unlock_target_request_matches(
		runtime_request, 28, 1, (uint32_t)-501));
	assert(!t2_aks_unlock_target_request_matches(
		runtime_request, 28, 1, 9));
	put_le32(runtime_request + 12, 9);
	assert(!t2_aks_unlock_alias_request_allowed(runtime_request, 28));
	assert(t2_aks_unlock_target_request_matches(
		runtime_request, 28, 1, 9));
	runtime_request[27] = 1;
	assert(!t2_aks_unlock_target_request_matches(
		runtime_request, 28, 1, 9));

	memset(context, 0xa5, sizeof(context));
	memset(authorization_target, 0x5a, sizeof(authorization_target));
	put_le64(acm_unlock_request + 4, 1);
	put_le32(acm_unlock_request + 12, (uint32_t)-501);
	put_le64(acm_unlock_request + 20, 0x100);
	put_le32(acm_unlock_request + 28, sizeof(context));
	memcpy(acm_unlock_request + 32, context, sizeof(context));
	assert(t2_aks_acm_unlock_request_allowed(
		acm_unlock_request, sizeof(acm_unlock_request)));
	assert(t2_aks_acm_unlock_context_matches(
		acm_unlock_request, sizeof(acm_unlock_request), context));
	assert(t2_aks_identity_login_context_allowed(
		acm_unlock_request, sizeof(acm_unlock_request), context,
		authorization_target, authorization_target, true, true, true,
		true));
	assert(!t2_aks_identity_login_context_allowed(
		acm_unlock_request, sizeof(acm_unlock_request),
		authorization_target, authorization_target, authorization_target,
		true, true, true, true));
	assert(!t2_aks_identity_login_context_allowed(
		acm_unlock_request, sizeof(acm_unlock_request), context,
		authorization_target, authorization_target, true, false, true,
		true));
	assert(t2_aks_acm_unlock_response_valid(
		acm_unlock_response, sizeof(acm_unlock_response)));
	put_le64(acm_unlock_request + 20, 0x101);
	assert(!t2_aks_acm_unlock_request_allowed(
		acm_unlock_request, sizeof(acm_unlock_request)));
	put_le64(acm_unlock_request + 20, 0x100);
	context[0] = 0x5a;
	assert(!t2_aks_acm_unlock_context_matches(
		acm_unlock_request, sizeof(acm_unlock_request), context));
	put_le32(acm_unlock_response, 1);
	assert(!t2_aks_acm_unlock_response_valid(
		acm_unlock_response, sizeof(acm_unlock_response)));

	memset(runtime_request, 0, sizeof(runtime_request));
	put_le32(runtime_request, 1);
	put_le64(runtime_request + 4, 1);
	put_le32(runtime_request + 12, (uint32_t)-501);
	assert(t2_aks_get_device_state_v1_request_allowed(runtime_request, 24));
	memset(runtime_response, 0, sizeof(runtime_response));
	put_le32(runtime_response, 1);
	put_le32(runtime_response + 4, 3);
	memcpy(runtime_response + 8, "der", 3);
	assert(t2_aks_get_device_state_v1_response_valid(runtime_response, 12));
	runtime_response[11] = 1;
	assert(!t2_aks_get_device_state_v1_response_valid(runtime_response, 12));

	memset(runtime_response, 0, sizeof(runtime_response));
	put_le32(runtime_response + 4, 16);
	runtime_response[8] = 1;
	assert(t2_aks_copy_keybag_uuid_response_valid(runtime_response, 24));
	put_le32(runtime_response, (uint32_t)-3);
	put_le32(runtime_response + 4, 0);
	assert(t2_aks_copy_keybag_uuid_absent_response(runtime_response, 8));

	memset(uuid_request, 0, sizeof(uuid_request));
	put_le64(uuid_request + 4, 1);
	put_le32(uuid_request + 12, (uint32_t)-501);
	assert(t2_aks_get_configuration_request_allowed(uuid_request,
						       sizeof(uuid_request)));
	memset(runtime_response, 0, sizeof(runtime_response));
	put_le32(runtime_response + 4, 3);
	memcpy(runtime_response + 8, "der", 3);
	assert(t2_aks_get_configuration_response_valid(runtime_response, 12));
	runtime_response[11] = 1;
	assert(!t2_aks_get_configuration_response_valid(runtime_response, 12));

	put_le64(primary_request + 4, 1);
	put_le32(primary_request + 20, (uint32_t)-1);
	put_le32(primary_request + 28, (uint32_t)-1);
	assert(t2_aks_get_primary_identity_request_allowed(primary_request,
							    sizeof(primary_request)));
	assert(!t2_aks_get_primary_identity_request_allowed(primary_request, 35));
	/* D132 proved that a third empty-blob word is rejected by the SEP codec. */
	assert(!t2_aks_get_primary_identity_request_allowed(primary_request, 40));
	put_le64(primary_request + 12, 1);
	assert(!t2_aks_get_primary_identity_request_allowed(primary_request,
							     sizeof(primary_request)));
	put_le64(primary_request + 12, 0);
	put_le32(primary_request + 24, 1);
	assert(!t2_aks_get_primary_identity_request_allowed(primary_request,
							     sizeof(primary_request)));
	put_le32(primary_request + 24, 0);
	put_le32(primary_request + 28, 0);
	assert(!t2_aks_get_primary_identity_request_allowed(primary_request,
							     sizeof(primary_request)));
	assert(!t2_aks_get_primary_identity_request_allowed(NULL,
							     sizeof(primary_request)));
	put_le32(primary_absent_response, (uint32_t)-3);
	assert(t2_aks_get_primary_identity_absent_response(
		primary_absent_response, sizeof(primary_absent_response)));
	put_le32(primary_absent_response + 4, 1);
	assert(!t2_aks_get_primary_identity_absent_response(
		primary_absent_response, sizeof(primary_absent_response)));

	put_le64(identity_delete_request + 4, 7);
	put_le32(identity_delete_request + 16, 16);
	memcpy(identity_delete_request + 20, replacement_uuid, 16);
	assert(t2_aks_identity_delete_request_allowed(
		identity_delete_request, sizeof(identity_delete_request)));
	assert(t2_aks_identity_delete_request_matches(
		identity_delete_request, sizeof(identity_delete_request), 7,
		replacement_uuid));
	assert(!t2_aks_identity_delete_request_matches(
		identity_delete_request, sizeof(identity_delete_request), 8,
		replacement_uuid));
	identity_delete_request[12] = 1;
	assert(!t2_aks_identity_delete_request_allowed(
		identity_delete_request, sizeof(identity_delete_request)));
	identity_delete_request[12] = 0;
	assert(t2_aks_identity_delete_response_valid(
		identity_delete_response, sizeof(identity_delete_response)));
	identity_delete_response[0] = 1;
	assert(!t2_aks_identity_delete_response_valid(
		identity_delete_response, sizeof(identity_delete_response)));

	put_le64(identity_open_request + 4, 7);
	put_le32(identity_open_request + 12, 16);
	memcpy(identity_open_request + 16, replacement_uuid, 16);
	assert(t2_aks_identity_open_request_allowed(
		identity_open_request, sizeof(identity_open_request)));
	assert(t2_aks_identity_open_request_matches(
		identity_open_request, sizeof(identity_open_request), 7,
		replacement_uuid));
	identity_open_request[16] = 0;
	assert(!t2_aks_identity_open_request_matches(
		identity_open_request, sizeof(identity_open_request), 7,
		replacement_uuid));

	put_le32(create_request, 5);
	put_le64(create_request + 4, 1);
	put_le32(create_request + 12, 0x4100);
	put_le32(create_request + 16, (uint32_t)-1);
	put_le32(create_request + 20, 16);
	create_request[24] = 1;
	put_le32(create_request + 44, 16);
	create_request[48] = 1;
	put_le64(create_request + 68, 6);
	assert(t2_aks_identity_create_v5_request_allowed(create_request,
							  sizeof(create_request)));
	assert(t2_aks_identity_create_v5_replacement_matches(
		create_request, sizeof(create_request), 1, create_request + 48,
		create_request + 24));
	assert(!t2_aks_identity_create_v5_replacement_matches(
		create_request, sizeof(create_request), 2, create_request + 48,
		create_request + 24));
	assert(!t2_aks_identity_create_v5_request_allowed(create_request, 87));
	create_request[48] = 0;
	assert(!t2_aks_identity_create_v5_request_allowed(create_request,
							   sizeof(create_request)));
	create_request[48] = 1;
	put_le32(create_request + 40, 1);
	assert(!t2_aks_identity_create_v5_request_allowed(create_request,
							   sizeof(create_request)));
	put_le32(create_request + 40, 0);
	put_le32(create_response, 5);
	put_le32(create_response + 4, 42);
	put_le32(create_response + 8, 3);
	memset(create_response + 12, 0xa5, 3);
	assert(t2_aks_identity_create_v5_response_valid(
		create_response, sizeof(create_response), &handle));
	assert(handle == 42);
	create_response[15] = 1;
	assert(!t2_aks_identity_create_v5_response_valid(
		create_response, sizeof(create_response), &handle));
	create_response[15] = 0;

	put_le32(export_request, 1);
	put_le64(export_request + 4, 1);
	put_le32(export_request + 12, 42);
	assert(t2_aks_identity_copy_keybag_v1_request_allowed(export_request,
							       sizeof(export_request)));
	put_le32(export_request + 16, 1);
	assert(!t2_aks_identity_copy_keybag_v1_request_allowed(export_request,
								sizeof(export_request)));
	assert(!t2_aks_identity_copy_keybag_v1_request_allowed(NULL,
								sizeof(export_request)));
	put_le32(export_response, 1);
	put_le32(export_response + 4, 3);
	memset(export_response + 8, 0x5a, 3);
	assert(t2_aks_identity_copy_keybag_v1_response_valid(
		export_response, sizeof(export_response)));
	export_response[11] = 1;
	assert(!t2_aks_identity_copy_keybag_v1_response_valid(
		export_response, sizeof(export_response)));

	length = make_request(request, 5, 0);
	assert(length == 40);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	for (index = 0; index < length; index++)
		assert(!t2_aks_verify_secret_v1_request_allowed(request, index));
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length + 1));

	length = make_request(request, 5, 16);
	assert(length == 56);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	assert(t2_aks_verify_secret_v1_selector42_request_allowed(
		request, length));
	assert(!t2_aks_verify_secret_v1_identity_request_allowed(
		request, length));
	assert(!t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, (uint32_t)-501));
	put_le64(request + 48, 0x100);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	assert(!t2_aks_verify_secret_v1_identity_request_allowed(
		request, length));
	length = make_request(request, 16, 16);
	put_le64(request + 56, 0x100);
	assert(t2_aks_verify_secret_v1_identity_request_allowed(
		request, length));
	assert(!t2_aks_verify_secret_v1_selector42_request_allowed(
		request, length));
	assert(t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, (uint32_t)-501));
	assert(!t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 2, (uint32_t)-501));
	assert(!t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, (uint32_t)-502));
	put_le32(request + 12, 9);
	assert(t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, 9));
	assert(!t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, (uint32_t)-501));
	put_le32(request + 12, (uint32_t)-501);
	memset(context, 0xa5, sizeof(context));
	memset(identity_reference, 'x', sizeof(identity_reference));
	assert(t2_aks_verify_secret_v1_context_matches(
		request, length, context));
	assert(t2_aks_verify_secret_v1_identity_secret_matches(
		request, length, identity_reference));
	assert(!t2_aks_verify_secret_v1_identity_secret_matches(
		request, length, context));
	assert(t2_aks_verify_secret_v1_identity_references_distinct(
		request, length));
	memcpy(request + 20, context, sizeof(context));
	assert(t2_aks_verify_secret_v1_identity_secret_matches(
		request, length, context));
	assert(!t2_aks_verify_secret_v1_identity_references_distinct(
		request, length));
	context[0] = 0;
	assert(!t2_aks_verify_secret_v1_context_matches(
		request, length, context));

	length = make_request(request, 16, 0);
	put_le64(request + 40, 0x100);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	assert(t2_aks_verify_secret_v1_identity_verify_only_request_allowed(
		request, length));
	assert(!t2_aks_verify_secret_v1_identity_request_allowed(
		request, length));
	assert(t2_aks_verify_secret_v1_identity_secret_matches(
		request, length, identity_reference));
	assert(t2_aks_verify_secret_v1_runtime_target_matches(
		request, length, 1, (uint32_t)-501));
	assert(!t2_aks_verify_secret_v1_context_matches(
		request, length, context));
	put_le64(request + 40, 0x300);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le64(request + 40, 0x100);
	put_le32(verify_response, 1);
	assert(t2_aks_verify_secret_v1_response_valid(
		verify_response, sizeof(verify_response)));
	assert(!t2_aks_verify_secret_v1_response_valid(verify_response, 11));

	put_le32(request, 2);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le32(request, 1);
	put_le64(request + 4, 2);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le64(request + 4, 1);
	put_le32(request + 12, 0);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));

	length = make_request(request, 5, 0);
	request[25] = 1;
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 5, 0);
	put_le32(request + 28, 1);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 5, 0);
	put_le64(request + 32, 0x100);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 5, 0);
	put_le64(request + 32, 0x280);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));

	length = make_request(request, 1, 0);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 128, 16);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le32(request + 16, 129);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, 36));
	put_le32(request + 16, 0);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, 36));
	assert(!t2_aks_verify_secret_v1_request_allowed(NULL, 36));
	return 0;
}
