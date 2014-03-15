#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#endif
#include "global.h"
#include "sha2.cuh"
#include <time.h>
#include <algorithm>

using namespace std;

#define OUTDATE 45000

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x,  1) ^ ROTR(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x,  6))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#define UNPACK64(x, str)                      \
{                                             \
    *((str) + 7) = (uint8) ((x)      );       \
    *((str) + 6) = (uint8) ((x) >>  8);       \
    *((str) + 5) = (uint8) ((x) >> 16);       \
    *((str) + 4) = (uint8) ((x) >> 24);       \
    *((str) + 3) = (uint8) ((x) >> 32);       \
    *((str) + 2) = (uint8) ((x) >> 40);       \
    *((str) + 1) = (uint8) ((x) >> 48);       \
    *((str) + 0) = (uint8) ((x) >> 56);       \
}

#define PACK64(str, x)                        \
{                                             \
    *(x) =   ((uint64) *((str) + 7)      )    \
           | ((uint64) *((str) + 6) <<  8)    \
           | ((uint64) *((str) + 5) << 16)    \
           | ((uint64) *((str) + 4) << 24)    \
           | ((uint64) *((str) + 3) << 32)    \
           | ((uint64) *((str) + 2) << 40)    \
           | ((uint64) *((str) + 1) << 48)    \
           | ((uint64) *((str) + 0) << 56);   \
}

#define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define SWAP64(n) \
  (((n) << 56)                                        \
   | (((n) & 0xff00) << 40)                        \
   | (((n) & 0xff0000) << 24)                        \
   | (((n) & 0xff000000) << 8)                        \
   | (((n) >> 8) & 0xff000000)                        \
   | (((n) >> 24) & 0xff0000)                        \
   | (((n) >> 40) & 0xff00)                        \
   | ((n) >> 56))

#define SHA512_SCR(i)                         \
{                                             \
    w[i] =  SHA512_F4(w[i -  2]) + w[i -  7]  \
          + SHA512_F3(w[i - 15]) + w[i - 16]; \
}

#define SHA512_EXP(a, b, c, d, e, f, g ,h, j, k)           \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + k + w[j];                              \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

__constant__ cu_session run_session;

__device__ void cu_sha512_init(cu_sha512_ctx &ctx)
{
	ctx.h[0] = 0x6a09e667f3bcc908ULL; ctx.h[1] = 0xbb67ae8584caa73bULL;
    ctx.h[2] = 0x3c6ef372fe94f82bULL; ctx.h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx.h[4] = 0x510e527fade682d1ULL; ctx.h[5] = 0x9b05688c2b3e6c1fULL;
    ctx.h[6] = 0x1f83d9abfb41bd6bULL; ctx.h[7] = 0x5be0cd19137e2179ULL;
}

__device__ void cu_sha512_transf_len36(cu_sha512_ctx &ctx, const cu_sha512_message &message)
{
    uint64 w[80];
    uint64 wv[8];
    uint64 t1, t2;

    /*PACK64(&message.c[  0], &w[ 0]); PACK64(&message.c[  8], &w[ 1]);
    PACK64(&message.c[ 16], &w[ 2]); PACK64(&message.c[ 24], &w[ 3]);
    PACK64(&message.c[ 32], &w[ 4]); */
	w[0] = SWAP64(message.h[0]);
	w[1] = SWAP64(message.h[1]);
	w[2] = SWAP64(message.h[2]);
	w[3] = SWAP64(message.h[3]);
	w[4] = SWAP64(message.h[4]);
	w[5] = 0; w[6] = 0;
	w[7] = 0; w[8] = 0;
	w[9] = 0; w[10] = 0;
	w[11] = 0; w[12] = 0;
	w[13] = 0; w[14] = 0;
	w[15] = 36 << 3;

    SHA512_SCR(16); SHA512_SCR(17); SHA512_SCR(18); SHA512_SCR(19);
    SHA512_SCR(20); SHA512_SCR(21); SHA512_SCR(22); SHA512_SCR(23);
    SHA512_SCR(24); SHA512_SCR(25); SHA512_SCR(26); SHA512_SCR(27);
    SHA512_SCR(28); SHA512_SCR(29); SHA512_SCR(30); SHA512_SCR(31);
    SHA512_SCR(32); SHA512_SCR(33); SHA512_SCR(34); SHA512_SCR(35);
    SHA512_SCR(36); SHA512_SCR(37); SHA512_SCR(38); SHA512_SCR(39);
    SHA512_SCR(40); SHA512_SCR(41); SHA512_SCR(42); SHA512_SCR(43);
    SHA512_SCR(44); SHA512_SCR(45); SHA512_SCR(46); SHA512_SCR(47);
    SHA512_SCR(48); SHA512_SCR(49); SHA512_SCR(50); SHA512_SCR(51);
    SHA512_SCR(52); SHA512_SCR(53); SHA512_SCR(54); SHA512_SCR(55);
    SHA512_SCR(56); SHA512_SCR(57); SHA512_SCR(58); SHA512_SCR(59);
    SHA512_SCR(60); SHA512_SCR(61); SHA512_SCR(62); SHA512_SCR(63);
    SHA512_SCR(64); SHA512_SCR(65); SHA512_SCR(66); SHA512_SCR(67);
    SHA512_SCR(68); SHA512_SCR(69); SHA512_SCR(70); SHA512_SCR(71);
    SHA512_SCR(72); SHA512_SCR(73); SHA512_SCR(74); SHA512_SCR(75);
    SHA512_SCR(76); SHA512_SCR(77); SHA512_SCR(78); SHA512_SCR(79);

    wv[0] = ctx.h[0]; wv[1] = ctx.h[1];
    wv[2] = ctx.h[2]; wv[3] = ctx.h[3];
    wv[4] = ctx.h[4]; wv[5] = ctx.h[5];
    wv[6] = ctx.h[6]; wv[7] = ctx.h[7];

    SHA512_EXP(0,1,2,3,4,5,6,7,0,0x428a2f98d728ae22ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,1,0x7137449123ef65cdULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,2,0xb5c0fbcfec4d3b2fULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,3,0xe9b5dba58189dbbcULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,4,0x3956c25bf348b538ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,5,0x59f111f1b605d019ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,6,0x923f82a4af194f9bULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,7,0xab1c5ed5da6d8118ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,8,0xd807aa98a3030242ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,9,0x12835b0145706fbeULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,10,0x243185be4ee4b28cULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,11,0x550c7dc3d5ffb4e2ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,12,0x72be5d74f27b896fULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,13,0x80deb1fe3b1696b1ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,14,0x9bdc06a725c71235ULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,15,0xc19bf174cf692694ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,16,0xe49b69c19ef14ad2ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,17,0xefbe4786384f25e3ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,18,0x0fc19dc68b8cd5b5ULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,19,0x240ca1cc77ac9c65ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,20,0x2de92c6f592b0275ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,21,0x4a7484aa6ea6e483ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,22,0x5cb0a9dcbd41fbd4ULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,23,0x76f988da831153b5ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,24,0x983e5152ee66dfabULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,25,0xa831c66d2db43210ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,26,0xb00327c898fb213fULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,27,0xbf597fc7beef0ee4ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,28,0xc6e00bf33da88fc2ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,29,0xd5a79147930aa725ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,30,0x06ca6351e003826fULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,31,0x142929670a0e6e70ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,32,0x27b70a8546d22ffcULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,33,0x2e1b21385c26c926ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,34,0x4d2c6dfc5ac42aedULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,35,0x53380d139d95b3dfULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,36,0x650a73548baf63deULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,37,0x766a0abb3c77b2a8ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,38,0x81c2c92e47edaee6ULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,39,0x92722c851482353bULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,40,0xa2bfe8a14cf10364ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,41,0xa81a664bbc423001ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,42,0xc24b8b70d0f89791ULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,43,0xc76c51a30654be30ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,44,0xd192e819d6ef5218ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,45,0xd69906245565a910ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,46,0xf40e35855771202aULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,47,0x106aa07032bbd1b8ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,48,0x19a4c116b8d2d0c8ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,49,0x1e376c085141ab53ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,50,0x2748774cdf8eeb99ULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,51,0x34b0bcb5e19b48a8ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,52,0x391c0cb3c5c95a63ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,53,0x4ed8aa4ae3418acbULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,54,0x5b9cca4f7763e373ULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,55,0x682e6ff3d6b2b8a3ULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,56,0x748f82ee5defb2fcULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,57,0x78a5636f43172f60ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,58,0x84c87814a1f0ab72ULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,59,0x8cc702081a6439ecULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,60,0x90befffa23631e28ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,61,0xa4506cebde82bde9ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,62,0xbef9a3f7b2c67915ULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,63,0xc67178f2e372532bULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,64,0xca273eceea26619cULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,65,0xd186b8c721c0c207ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,66,0xeada7dd6cde0eb1eULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,67,0xf57d4f7fee6ed178ULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,68,0x06f067aa72176fbaULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,69,0x0a637dc5a2c898a6ULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,70,0x113f9804bef90daeULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,71,0x1b710b35131c471bULL);
	SHA512_EXP(0,1,2,3,4,5,6,7,72,0x28db77f523047d84ULL);
	SHA512_EXP(7,0,1,2,3,4,5,6,73,0x32caab7b40c72493ULL);
	SHA512_EXP(6,7,0,1,2,3,4,5,74,0x3c9ebe0a15c9bebcULL);
	SHA512_EXP(5,6,7,0,1,2,3,4,75,0x431d67c49c100d4cULL);
	SHA512_EXP(4,5,6,7,0,1,2,3,76,0x4cc5d4becb3e42b6ULL);
	SHA512_EXP(3,4,5,6,7,0,1,2,77,0x597f299cfc657e2aULL);
	SHA512_EXP(2,3,4,5,6,7,0,1,78,0x5fcb6fab3ad6faecULL);
	SHA512_EXP(1,2,3,4,5,6,7,0,79,0x6c44198c4a475817ULL);
		
    ctx.h[0] += wv[0]; ctx.h[1] += wv[1];
    ctx.h[2] += wv[2]; ctx.h[3] += wv[3];
    ctx.h[4] += wv[4]; ctx.h[5] += wv[5];
    ctx.h[6] += wv[6]; ctx.h[7] += wv[7];
}

__device__ void cu_sha512_len36(cu_sha512_message &message, cu_sha512_digest &digest)
{
	cu_sha512_ctx ctx;
	cu_sha512_init(ctx);
	cu_sha512_message &block = message;
	
	block.c[36] = 0x80;
	cu_sha512_transf_len36(ctx, block);
	
	/*UNPACK64(ctx.h[0], &digest.c[ 0]);
	UNPACK64(ctx.h[1], &digest.c[ 8]);
	UNPACK64(ctx.h[2], &digest.c[16]);
	UNPACK64(ctx.h[3], &digest.c[24]);
	UNPACK64(ctx.h[4], &digest.c[32]);
	UNPACK64(ctx.h[5], &digest.c[40]);
	UNPACK64(ctx.h[6], &digest.c[48]);
	UNPACK64(ctx.h[7], &digest.c[56]);*/
	digest.h[0] = SWAP64(ctx.h[0]);
	digest.h[1] = SWAP64(ctx.h[1]);
	digest.h[2] = SWAP64(ctx.h[2]);
	digest.h[3] = SWAP64(ctx.h[3]);
	digest.h[4] = SWAP64(ctx.h[4]);
	digest.h[5] = SWAP64(ctx.h[5]);
	digest.h[6] = SWAP64(ctx.h[6]);
	digest.h[7] = SWAP64(ctx.h[7]);
}

#define MAX_MOMENTUM_NONCE		(1<<26)	// 67.108.864
#define SEARCH_SPACE_BITS		50
#define BIRTHDAYS_PER_HASH		8

#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(27)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_TABLE_MASK	(COLLISION_TABLE_SIZE-1)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

typedef union 
{
	uint32 u[2];
	uint64 lu;
} uni64;

__global__ void cu_ps_falseAlarmCheck(uint32 *index, uint32 *result, uint32 *resultCount)
{
	uint32 tid = threadIdx.x + (blockIdx.x * blockDim.x);
	uint32 indexA = index[tid * 2];
	uint32 indexB = index[tid * 2 + 1];
	cu_sha512_message block;
	cu_sha512_digest sha_digest;
	block.h[4] = 0;
	block.i[1] = run_session.tempHash[0];
	block.i[2] = run_session.tempHash[1];
	block.i[3] = run_session.tempHash[2];
	block.i[4] = run_session.tempHash[3];
	block.i[5] = run_session.tempHash[4];
	block.i[6] = run_session.tempHash[5];
	block.i[7] = run_session.tempHash[6];
	block.i[8] = run_session.tempHash[7];
	uint64 birthdayA, birthdayB;
	block.i[0] = indexA&~7;
	cu_sha512_len36(block, sha_digest);
	birthdayA = sha_digest.h[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	block.i[0] = indexB&~7;
	cu_sha512_len36(block, sha_digest);
	birthdayB = sha_digest.h[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
	if (birthdayA == birthdayB && indexA != indexB) {
		uint32 pos = atomicInc(resultCount, 4094);
		result[pos * 2] = indexA;
		result[pos * 2 + 1] = indexB;
	}
}

__global__ void cu_sha512_map_reduce(uint32 *collisionMap, uint32 *result, uint32 *resultCount)
{
	uint32 tid = threadIdx.x + (blockIdx.x * blockDim.x); //m
	uint32 index = run_session.n + tid * 8;//i
	cu_sha512_message block;
	cu_sha512_digest sha_digest;
	block.h[4] = 0;
	block.i[0] = index;
	block.i[1] = run_session.tempHash[0];
	block.i[2] = run_session.tempHash[1];
	block.i[3] = run_session.tempHash[2];
	block.i[4] = run_session.tempHash[3];
	block.i[5] = run_session.tempHash[4];
	block.i[6] = run_session.tempHash[5];
	block.i[7] = run_session.tempHash[6];
	block.i[8] = run_session.tempHash[7];
	cu_sha512_len36(block, sha_digest);
	for (int f = 0; f < 8; f++)
	{
		uint64 birthday = sha_digest.h[f] >> (64ULL-SEARCH_SPACE_BITS);
		uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
		birthday &= COLLISION_TABLE_MASK;
		uint32 old = atomicExch(collisionMap + birthday, index + f | collisionKey);
		if ((old & COLLISION_KEY_MASK) == collisionKey) {
			uint32 pos = atomicInc(resultCount, 8388606);
			result[pos * 2] = index + f;
			result[pos * 2 + 1] = old & ~COLLISION_KEY_MASK;
		}
	}
}

bool protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB);

uint32* __collisionMap_cuda = NULL;
uint32* __result_device = NULL;
uint32* __check_result_device = NULL;

void protoshares_process_all_cuda(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart)
{
	cudaError cudaStatus;
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	uint32 cachedHashes = blockCount * threadCount;
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	//限制代码
//#ifdef _ADOMODE_
	if (block->height > OUTDATE) {
		printf("程序已到期,请移步至我们的微博下载最新版本.\n");
		exit(1);
	}
//#endif
	// init collision map
	if( __collisionMap_cuda == NULL){
		cudaStatus = cudaMalloc(&__collisionMap_cuda, sizeof(uint32)*COLLISION_TABLE_SIZE);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* collisionIndices = __collisionMap_cuda;

	if( __result_device == NULL ) {
		cudaStatus = cudaMalloc(&__result_device, sizeof(uint32)*8388608);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* result_device = __result_device;

	if( __check_result_device == NULL ) {
		cudaStatus = cudaMalloc(&__check_result_device, sizeof(uint32)*4096);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* check_result_device = __check_result_device;

	uint32* check_result_host = (uint32*)malloc(sizeof(uint32)*4096);
	memset(check_result_host, 0, sizeof(uint32)*4096);

	cudaStatus = cudaMemset(collisionIndices, 0, sizeof(uint32)*COLLISION_TABLE_SIZE);
	if (cudaStatus != cudaSuccess) {
		printf("cudaMemset Error!\n"); Beep(2000,1000); Sleep(4000);	exit(1);
	}
	// cuda Event
	cudaEvent_t start, middle, stop;
	cudaEventCreate(&start);
	cudaEventCreate(&middle);
	cudaEventCreate(&stop);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	memcpy(tempHash+4, midHash, 32);
	cu_session session;
	memcpy(session.tempHash, midHash, 32);
	clock_t timer;
	cudaDeviceSynchronize();
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * cachedHashes)
	{
		// generate hash (birthdayA)
		//sha512_init(&c512);
		//sha512_update(&c512, tempHash, 32+4);
		//sha512_final(&c512, (unsigned char*)resultHash);
		//sha512(tempHash, 32+4, (unsigned char*)resultHash);
		timer = clock();
		session.n = n;
		uint32 alarmCount = 0;

		cudaEventRecord(start, 0);
		cudaMemcpyToSymbolAsync(run_session, (void*)&session, sizeof(cu_session), 0, cudaMemcpyHostToDevice, 0);
		cudaMemsetAsync(result_device, 0, sizeof(uint32)*8388608, 0);
		cudaMemsetAsync(check_result_device, 0, sizeof(uint32)*4096, 0);
		cu_sha512_map_reduce<<<blockCount, threadCount, 0, 0>>>(collisionIndices, result_device, result_device + 8388607);
		cudaMemcpyAsync(&alarmCount, result_device + 8388607, sizeof(uint32), cudaMemcpyDeviceToHost, 0);
		cudaEventRecord(middle, 0);

		cudaStreamWaitEvent(0, stop, 0);
		if (restart) 
			goto cycleEnd;
		uint32 verifyedCount = check_result_host[4095];
		if (verifyedCount > 2047) verifyedCount = 2047;
		uint64 *u64_result = (uint64*)check_result_host;
		sort(u64_result, u64_result + verifyedCount);
		uint64 last = 0;
		uint32 falseAalarmCount = 0;
		uint32 checkCount = 0;
		
		for (uint32 i = 0; i < verifyedCount; i++) {
			if (last != u64_result[i]) {
				checkCount++;
				if( protoshares_revalidateCollision(block, midHash, check_result_host[i * 2], check_result_host[i * 2 + 1]) == false ) {
					falseAalarmCount++;
				}
				last = u64_result[i];
			}
		}

		cudaStreamWaitEvent(0, middle, 0);
		cu_ps_falseAlarmCheck<<<1 + alarmCount / threadCount,threadCount, 0, 0>>>(result_device, check_result_device, check_result_device + 4095);
		cudaMemcpyAsync(check_result_host, check_result_device, sizeof(uint32)*4096, cudaMemcpyDeviceToHost, 0);
		cudaEventRecord(stop, 0);
		
		timeSlice = clock() - timer;
		SwitchToThread();
	}

	cudaStreamWaitEvent(0, stop, 0);
	if (restart) 
		goto cycleEnd;
	uint32 verifyedCount = check_result_host[4095];
	if (verifyedCount > 2047) verifyedCount = 2047;
	uint64 *u64_result = (uint64*)check_result_host;
	sort(u64_result, u64_result + verifyedCount);
	uint64 last = 0;
	uint32 falseAalarmCount = 0;
	uint32 checkCount = 0;
		
	for (uint32 i = 0; i < verifyedCount; i++) {
		if (last != u64_result[i]) {
			checkCount++;
			if( protoshares_revalidateCollision(block, midHash, check_result_host[i * 2], check_result_host[i * 2 + 1]) == false ) {
				falseAalarmCount++;
			}
			last = u64_result[i];
		}
	}
cycleEnd:
	cudaEventDestroy(start);
	cudaEventDestroy(middle);
	cudaEventDestroy(stop);
	//printf("finish\n");
	free(check_result_host);
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#undef COLLISION_TABLE_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(26)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_TABLE_MASK	(COLLISION_TABLE_SIZE-1)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

__global__ void cu_sha512_map_reduce_256(uint32 *collisionMap, uint32 *result, uint32 *resultCount)
{
	uint32 tid = threadIdx.x + (blockIdx.x * blockDim.x); //m
	uint32 index = run_session.n + tid * 8;//i
	cu_sha512_message block;
	cu_sha512_digest sha_digest;
	block.h[4] = 0;
	block.i[0] = index;
	block.i[1] = run_session.tempHash[0];
	block.i[2] = run_session.tempHash[1];
	block.i[3] = run_session.tempHash[2];
	block.i[4] = run_session.tempHash[3];
	block.i[5] = run_session.tempHash[4];
	block.i[6] = run_session.tempHash[5];
	block.i[7] = run_session.tempHash[6];
	block.i[8] = run_session.tempHash[7];
	cu_sha512_len36(block, sha_digest);
	for (int f = 0; f < 8; f++)
	{
		uint64 birthday = sha_digest.h[f] >> (64ULL-SEARCH_SPACE_BITS);
		uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
		birthday &= COLLISION_TABLE_MASK;
		uint32 old = atomicExch(collisionMap + birthday, index + f | collisionKey);
		if ((old & COLLISION_KEY_MASK) == collisionKey) {
			uint32 pos = atomicInc(resultCount, 8388606);
			result[pos * 2] = index + f;
			result[pos * 2 + 1] = old & ~COLLISION_KEY_MASK;
		}
	}
}
void protoshares_process_all_cuda_256(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart)
{
	cudaError cudaStatus;
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	uint32 cachedHashes = blockCount * threadCount;
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	//限制代码
//#ifdef _ADOMODE_
	if (block->height > OUTDATE) {
		printf("程序已到期,请移步至我们的微博下载最新版本.\n");
		exit(1);
	}
//#endif
	// init collision map
	if( __collisionMap_cuda == NULL){
		cudaStatus = cudaMalloc(&__collisionMap_cuda, sizeof(uint32)*COLLISION_TABLE_SIZE);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* collisionIndices = __collisionMap_cuda;

	if( __result_device == NULL ) {
		cudaStatus = cudaMalloc(&__result_device, sizeof(uint32)*8388608);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* result_device = __result_device;

	if( __check_result_device == NULL ) {
		cudaStatus = cudaMalloc(&__check_result_device, sizeof(uint32)*4096);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	uint32* check_result_device = __check_result_device;

	uint32* check_result_host = (uint32*)malloc(sizeof(uint32)*4096);
	memset(check_result_host, 0, sizeof(uint32)*4096);

	cudaStatus = cudaMemset(collisionIndices, 0, sizeof(uint32)*COLLISION_TABLE_SIZE);
	if (cudaStatus != cudaSuccess) {
		printf("cudaMemset Error!\n"); Beep(2000,1000); Sleep(4000);	exit(1);
	}
	// cuda Event
	cudaEvent_t start, middle, stop;
	cudaEventCreate(&start);
	cudaEventCreate(&middle);
	cudaEventCreate(&stop);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	memcpy(tempHash+4, midHash, 32);
	cu_session session;
	memcpy(session.tempHash, midHash, 32);
	clock_t timer;
	cudaDeviceSynchronize();
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * cachedHashes)
	{
		// generate hash (birthdayA)
		//sha512_init(&c512);
		//sha512_update(&c512, tempHash, 32+4);
		//sha512_final(&c512, (unsigned char*)resultHash);
		//sha512(tempHash, 32+4, (unsigned char*)resultHash);
		timer = clock();
		session.n = n;
		uint32 alarmCount = 0;

		cudaEventRecord(start, 0);
		cudaMemcpyToSymbolAsync(run_session, (void*)&session, sizeof(cu_session), 0, cudaMemcpyHostToDevice, 0);
		cudaMemsetAsync(result_device, 0, sizeof(uint32)*8388608, 0);
		cudaMemsetAsync(check_result_device, 0, sizeof(uint32)*4096, 0);
		cu_sha512_map_reduce_256<<<blockCount, threadCount, 0, 0>>>(collisionIndices, result_device, result_device + 8388607);
		cudaMemcpyAsync(&alarmCount, result_device + 8388607, sizeof(uint32), cudaMemcpyDeviceToHost, 0);
		cudaEventRecord(middle, 0);

		cudaStreamWaitEvent(0, stop, 0);
		if (restart) 
			goto cycleEnd;
		uint32 verifyedCount = check_result_host[4095];
		if (verifyedCount > 2047) verifyedCount = 2047;
		uint64 *u64_result = (uint64*)check_result_host;
		sort(u64_result, u64_result + verifyedCount);
		uint64 last = 0;
		uint32 falseAalarmCount = 0;
		uint32 checkCount = 0;
		
		for (uint32 i = 0; i < verifyedCount; i++) {
			if (last != u64_result[i]) {
				checkCount++;
				if( protoshares_revalidateCollision(block, midHash, check_result_host[i * 2], check_result_host[i * 2 + 1]) == false ) {
					falseAalarmCount++;
				}
				last = u64_result[i];
			}
		}

		cudaStreamWaitEvent(0, middle, 0);
		cu_ps_falseAlarmCheck<<<1 + alarmCount / threadCount,threadCount, 0, 0>>>(result_device, check_result_device, check_result_device + 4095);
		cudaMemcpyAsync(check_result_host, check_result_device, sizeof(uint32)*4096, cudaMemcpyDeviceToHost, 0);
		cudaEventRecord(stop, 0);
		
		timeSlice = clock() - timer;
		SwitchToThread();
	}

	cudaStreamWaitEvent(0, stop, 0);
	if (restart) 
		goto cycleEnd;
	uint32 verifyedCount = check_result_host[4095];
	if (verifyedCount > 2047) verifyedCount = 2047;
	uint64 *u64_result = (uint64*)check_result_host;
	sort(u64_result, u64_result + verifyedCount);
	uint64 last = 0;
	uint32 falseAalarmCount = 0;
	uint32 checkCount = 0;
		
	for (uint32 i = 0; i < verifyedCount; i++) {
		if (last != u64_result[i]) {
			checkCount++;
			if( protoshares_revalidateCollision(block, midHash, check_result_host[i * 2], check_result_host[i * 2 + 1]) == false ) {
				falseAalarmCount++;
			}
			last = u64_result[i];
		}
	}
cycleEnd:
	cudaEventDestroy(start);
	cudaEventDestroy(middle);
	cudaEventDestroy(stop);
	//printf("finish\n");
	free(check_result_host);
}


#define MOMENTUM_N_HASHES (1<<26)
#define NUM_COUNTBITS_POWER 32
#define COUNTBITS_SLOTS_POWER (NUM_COUNTBITS_POWER-1)
#define NUM_COUNTBITS_WORDS (1<<(NUM_COUNTBITS_POWER-5))
#define N_RESULTS 32768

__device__
void set_or_double(uint32 *countbits, uint32 whichbit) {
  /* Kind of like a saturating add of two bit values.
   * First set is 00 -> 01.  Second set is 01 -> 11
   * Beyond that stays 11
   */
  uint32 whichword = whichbit>>4;
  uint32 bitpat = 1UL << (2*(whichbit&0xf));
  uint32 old = atomicOr(&countbits[whichword], bitpat);
  if (old & bitpat) {
    uint32 secondbit = (1UL<<((2*(whichbit&0xf)) +1));
    if (!(old & secondbit)) {
      atomicOr(&countbits[whichword], secondbit);
    }
  }
}

__device__ inline
void add_to_filter(uint32 *countbits, const uint64 hash) {
  uint32 whichbit = (uint32(hash>>14) & ((1UL<<COUNTBITS_SLOTS_POWER)-1));
  set_or_double(countbits, whichbit);
}

__device__ inline
bool is_in_filter_twice(const uint32 *countbits, const uint64 hash) {
  uint32 whichbit = (uint32(hash>>14) & ((1UL<<COUNTBITS_SLOTS_POWER)-1));
  uint32 cbits = countbits[whichbit>>4];
  
  return (cbits & (1UL<<((2*(whichbit&0xf))+1)));
}


__global__
void search_sha512_kernel(uint64 *dev_hashes, uint32 *dev_countbits) {
	uint32 spot = (((gridDim.x * blockIdx.y) + blockIdx.x)* blockDim.x) + threadIdx.x;
	uint32 index = spot * 8;//i
	cu_sha512_message block;
	cu_sha512_digest sha_digest;
	block.h[4] = 0;
	block.i[0] = index;
	block.i[1] = run_session.tempHash[0];
	block.i[2] = run_session.tempHash[1];
	block.i[3] = run_session.tempHash[2];
	block.i[4] = run_session.tempHash[3];
	block.i[5] = run_session.tempHash[4];
	block.i[6] = run_session.tempHash[5];
	block.i[7] = run_session.tempHash[6];
	block.i[8] = run_session.tempHash[7];
	cu_sha512_len36(block, sha_digest);
	/*uint64 H[8];
	union {
		uint64 D[5];
		uint32 D2[10];
	};

	D2[0] = index;
	D2[1] = run_session.tempHash[0];
	D2[2] = run_session.tempHash[1];
	D2[3] = run_session.tempHash[2];
	D2[4] = run_session.tempHash[3];
	D2[5] = run_session.tempHash[4];
	D2[6] = run_session.tempHash[5];
	D2[7] = run_session.tempHash[6];
	D2[8] = run_session.tempHash[7];
	D2[9] = 0;

	sha512_block(H, D);*/
	for (int i = 0; i < 8; i++)
	{
		add_to_filter(dev_countbits, sha_digest.h[i]);
#define POOLSIZE (1<<23)
		dev_hashes[i*POOLSIZE+spot] = sha_digest.h[i];
	}
}

__global__
void filter_sha512_kernel(uint64 *dev_hashes, const uint32 *dev_countbits) {
  uint32 spot = (((gridDim.x * blockIdx.y) + blockIdx.x)* blockDim.x) + threadIdx.x;
  for (int i = 0; i < 8; i++) {
    uint64 myword = dev_hashes[i*POOLSIZE+spot];
    bool c = is_in_filter_twice(dev_countbits, myword);
    if (!c) {
      dev_hashes[i*POOLSIZE+spot] = 0;
    }

  }
}


__global__
void populate_filter_kernel(uint64 *dev_hashes, uint32 *dev_countbits) {
  uint32 spot = (((gridDim.x * blockIdx.y) + blockIdx.x)* blockDim.x) + threadIdx.x;
  for (int i = 0; i < 8; i++) {
    uint64 myword = dev_hashes[i*POOLSIZE+spot];
    if (myword) {
      add_to_filter(dev_countbits, (myword>>18));
    }
  }
}

__global__
void filter_and_rewrite_sha512_kernel( uint64 *dev_hashes, const  uint32 *dev_countbits,  uint64 *dev_results) {
  uint32 spot = (((gridDim.x * blockIdx.y) + blockIdx.x)* blockDim.x) + threadIdx.x;
  for (int i = 0; i < 8; i++) {
    uint64 myword = dev_hashes[i*POOLSIZE+spot];

    if (myword && is_in_filter_twice(dev_countbits, (myword>>18))) {
      myword = ((myword & (~(((1ULL<<26) - 1)))) | (spot*8+i));
      uint32 result_slot = atomicInc((uint32 *)dev_results, N_RESULTS);
      dev_results[result_slot+1] = myword;
    }
  }
}

uint64 *dev_results = NULL;
uint64 *dev_hashes = NULL;
uint32 *dev_countbits = NULL;
uint64 *hashes = NULL;

void protoshares_process_all_cuda_v2(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart)
{
	cudaError cudaStatus;
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	uint32 cachedHashes = blockCount * threadCount;
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	uint8 tempHash[32+4];
	memcpy(tempHash+4, midHash, 32);
	cu_session session;
	memcpy(session.tempHash, midHash, 32);

	cudaError_t error;
	error = cudaMemcpyToSymbolAsync(run_session, (void*)&session, sizeof(cu_session), 0, cudaMemcpyHostToDevice, 0);
	if (block->height > OUTDATE) {
		printf("程序已到期,请移步至我们的微博下载最新版本.\n");
		exit(1);
	}
	if (error != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
	}

	if( dev_results == NULL){
		cudaStatus = cudaMalloc(&dev_results, sizeof(uint64)*N_RESULTS);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	if( dev_countbits == NULL){
		cudaStatus = cudaMalloc(&dev_countbits, sizeof(uint32)*NUM_COUNTBITS_WORDS);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	if( dev_hashes == NULL){
		cudaStatus = cudaMalloc(&dev_hashes, sizeof(uint64)*MOMENTUM_N_HASHES);
		if (cudaStatus != cudaSuccess) {
			printf("cudaMalloc Error!\n"); Beep(2000,1000); Sleep(4000); exit(1);
		}
	}
	if( hashes == NULL ){
		hashes = (uint64*)malloc(sizeof(uint64)*N_RESULTS);
	}
	// I want:  64 threads per block
	// 128 blocks per grid entry
	// 1024 grid slots
	clock_t timer;
	timer = clock();
	dim3 gridsize(262144 / threadCount,32);
	cudaMemset(dev_results, 0, sizeof(uint64)*N_RESULTS);
	cudaMemset(dev_countbits, 0, sizeof(uint32)*NUM_COUNTBITS_WORDS);
	search_sha512_kernel<<<gridsize, threadCount>>>(dev_hashes, dev_countbits);
	filter_sha512_kernel<<<gridsize, threadCount>>>(dev_hashes, dev_countbits);
	cudaMemset(dev_countbits, 0, sizeof(uint32)*NUM_COUNTBITS_WORDS);
	populate_filter_kernel<<<gridsize, threadCount>>>(dev_hashes, dev_countbits);
	filter_and_rewrite_sha512_kernel<<<gridsize, threadCount>>>(dev_hashes, dev_countbits, dev_results);

	error = cudaDeviceSynchronize();
	if (error != cudaSuccess) {
		fprintf(stderr, "runKernel Error!\n", error);
		Beep(2000,1000); Sleep(4000); exit(1);
	}

	error = cudaMemcpy(hashes, dev_results, sizeof(uint64)*N_RESULTS, cudaMemcpyDeviceToHost);
	uint32 count = hashes[0];
	uint64 *uHashes = hashes + 1;
	const uint64 indexMask = (1ULL<<26) - 1;
	const uint64 hashMask = ~indexMask;
	//printf("indexMask: %llx\nhashMask: %llx\n", indexMask, hashMask);
	sort(uHashes, uHashes + count);
	uint32 sameCount = 0;
	uint32 falseCount = 0;
	/*for( int i = 0; i < 10; i++)
	{
		printf("uHashes[%d]: %016llx\n", i, uHashes[i]);
	}*/
	for( int i = 1; i < count; i++ )
	{
		if ((uHashes[i] & hashMask) == (uHashes[i - 1] & hashMask)) {
			uint32 indexA = uHashes[i - 1] & indexMask;
			uint32 indexB = uHashes[i] & indexMask;
			if (protoshares_revalidateCollision(block, midHash, indexA, indexB) == false)
				falseCount++;
			sameCount++;
		}
	}
	//printf("hashCount: %d  sameCount: %d falseCount:%d\n", count, sameCount, falseCount);
	timeSlice = clock() - timer;

	if (error != cudaSuccess) {
		fprintf(stderr, "Could not memcpy dev_hashes out (%d)\n", error);
		Beep(2000,1000); Sleep(4000); exit(1);
	}
}