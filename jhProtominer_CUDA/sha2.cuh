#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#ifndef SHA2_CUH
#define SHA2_CUH

#ifndef SHA2_TYPES
#define SHA2_TYPES
typedef unsigned char uint8;
typedef unsigned int  uint32;
typedef unsigned long long uint64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef union __align__(32){
	uint8 c[64];
    uint64 h[8];
} cu_sha512_ctx;

typedef cu_sha512_ctx cu_sha512_digest;

typedef union __align__(32){
	uint8 c[128];
	uint32 i[32];
	uint64 h[16];
} cu_sha512_message;

typedef struct {
	uint32 n;
	union {
		uint32 tempHash[8];
		uint64 tempHash64[4];
	};
} cu_session;

#ifdef __cplusplus
}
#endif

#endif /* !SHA2_H */