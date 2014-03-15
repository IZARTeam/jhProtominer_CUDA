void protoshares_process_512(minerProtosharesBlock_t* block);
void protoshares_process_all_cuda(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart);
void protoshares_process_all_cuda_256(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart);
void protoshares_process_all_cuda_v2(minerProtosharesBlock_t* block, int blockCount, int threadCount, volatile bool &restart);