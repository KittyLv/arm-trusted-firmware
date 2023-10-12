#include <stdint.h>
#include <stddef.h>
#include <string.h>


/* SiP status response */
#define INTEL_SIP_SMC_STATUS_OK					0
#define INTEL_SIP_SMC_STATUS_BUSY				0x1
#define INTEL_SIP_SMC_STATUS_REJECTED				0x2
#define INTEL_SIP_SMC_STATUS_NO_RESPONSE			0x3
#define INTEL_SIP_SMC_STATUS_ERROR				0x4
#define INTEL_SIP_SMC_RSU_ERROR					0x7



typedef struct fcs_crypto_service_aes_data_t {
	uint32_t session_id;
	uint32_t context_id;
	uint32_t param_size;
	uint32_t key_id;
	uint32_t crypto_param[7];
	uint8_t is_updated;
} fcs_crypto_service_aes_data;

static fcs_crypto_service_aes_data fcs_aes_init_payload;



void *memset(void *dst, int val, size_t count)
{
	uint8_t *ptr = dst;
	uint64_t *ptr64;
	uint64_t fill = (unsigned char)val;

	/* Simplify code below by making sure we write at least one byte. */
	if (count == 0U) {
		return dst;
	}

	/* Handle the first part, until the pointer becomes 64-bit aligned. */
	while (((uintptr_t)ptr & 7U) != 0U) {
		*ptr = (uint8_t)val;
		ptr++;
		if (--count == 0U) {
			return dst;
		}
	}

	/* Duplicate the fill byte to the rest of the 64-bit word. */
	fill |= fill << 8;
	fill |= fill << 16;
	fill |= fill << 32;

	/* Use 64-bit writes for as long as possible. */
	ptr64 = (uint64_t *)ptr;
	for (; count >= 8U; count -= 8) {
		*ptr64 = fill;
		ptr64++;
	}

	/* Handle the remaining part byte-per-byte. */
	ptr = (uint8_t *)ptr64;
	while (count-- > 0U)  {
		*ptr = (uint8_t)val;
		ptr++;
	}

	return dst;
}


int intel_fcs_aes_crypt_init(uint32_t session_id, uint32_t context_id,
				uint32_t key_id, uint64_t param_addr,
				uint32_t param_size, uint32_t *mbox_error)
{
#define FCS_CRYPTO_ECB_BUFFER_SIZE			12U
#define FCS_CRYPTO_CBC_CTR_BUFFER_SIZE			28U
#define FCS_CRYPTO_BLOCK_MODE_MASK			0x07
#define FCS_CRYPTO_ECB_MODE			0x00
#define FCS_CRYPTO_CBC_MODE			0x01
#define FCS_CRYPTO_CTR_MODE			0x02


	/* ptr to get param_addr value */
	uint64_t *param_addr_ptr;

	param_addr_ptr = (uint64_t *) param_addr;

	if (mbox_error == NULL) {
		return INTEL_SIP_SMC_STATUS_REJECTED;
	}

	/*
	 * Check if not ECB, CBC and CTR mode, addr ptr is NULL.
	 * Return "Reject" status
	 */
	if ((param_addr_ptr == NULL) ||
		(((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) != FCS_CRYPTO_ECB_MODE) &&
		((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) != FCS_CRYPTO_CBC_MODE) &&
		((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) != FCS_CRYPTO_CTR_MODE))) {
		return INTEL_SIP_SMC_STATUS_REJECTED;
	}

	/*
	 * Since crypto param size vary between mode.
	 * Check CBC/CTR here and limit to size 28 bytes
	 */
	if ((((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) == FCS_CRYPTO_CBC_MODE) ||
		((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) == FCS_CRYPTO_CTR_MODE)) &&
		(param_size > FCS_CRYPTO_CBC_CTR_BUFFER_SIZE)) {
		return INTEL_SIP_SMC_STATUS_REJECTED;
	}

	/*
	 * Since crypto param size vary between mode.
	 * Check ECB here and limit to size 12 bytes
	 */
	if (((*param_addr_ptr & FCS_CRYPTO_BLOCK_MODE_MASK) == FCS_CRYPTO_ECB_MODE) &&
		(param_size > FCS_CRYPTO_ECB_BUFFER_SIZE)) {
		return INTEL_SIP_SMC_STATUS_REJECTED;
	}



	memset((void *)&fcs_aes_init_payload, 0U, sizeof(fcs_aes_init_payload));

	fcs_aes_init_payload.session_id = session_id;
	fcs_aes_init_payload.context_id = context_id;
	fcs_aes_init_payload.param_size = param_size;
	fcs_aes_init_payload.key_id	= key_id;

	memcpy((uint8_t *) fcs_aes_init_payload.crypto_param,
		(uint8_t *) param_addr, param_size);

	fcs_aes_init_payload.is_updated = 0;

	*mbox_error = 0;

	return INTEL_SIP_SMC_STATUS_OK;
}
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if(Data== NULL || Size== 0 || Size < 48) return 0;

  uint32_t x1=((uint32_t*)Data)[0];
  uint32_t x2=((uint32_t*)Data)[1];
  uint32_t x3=((uint32_t*)Data)[2];
  uint64_t x4=((uint64_t*)Data)[3];
  uint32_t x5=((uint32_t*)Data)[4];
  uint32_t mbox_error=((uint32_t*)Data)[5];
  

 if (x4==0 || x4> 0xFFFFFFFFFF  ) {
 return 0;
}

if (mbox_error> 0xF || mbox_error!= 0x3ff  ) {
 return 0;
}


/*
 if (x5> 12 || x5> 28  ) {
 return 0;
}

 if (x5> 12 || x5> 28  ) {
 return 0;
}

 if (x1> sizeof(uint32_t)) {
 return 0;
}
 if (x2> sizeof(uint32_t)) {
 return 0;
}
 if (x3> sizeof(uint32_t)) {
 return 0;
}
*/


  int status = INTEL_SIP_SMC_STATUS_OK;
  status = intel_fcs_aes_crypt_init(x1, x2, x3, x4, x5,	&mbox_error);
  return status;

}