#include "../jhProtoMiner_CUDA/global.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"


void jhProtominer_submitShare(minerProtosharesBlock_t* block)
{
	//dummy
}

void print_Usage()
{
	puts("Usage: benchmark.exe <deviceID> [times=4]");
}

float GetCycleTime(int blockCount, int threadCount, int times)
{
	minerProtosharesBlock_t block = {0};
	volatile bool restart = false;
	clock_t cycle_start = clock();
	for (int i = 0; i < times; i++) {
		
		protoshares_process_all_cuda(&block, blockCount, threadCount, restart);
	}
	return (clock() - cycle_start) * 1000.0 / CLOCKS_PER_SEC / times;
}

int main(int argc, char** argv)
{
	if (argc <= 1) {
		print_Usage();
		exit(1);
	}
	//Init
	cudaError cudaStatus;
	cudaDeviceProp prop;
	int deviceID = atoi(argv[1]);
	int times = 4;
	if (argc == 3)
		times = atoi(argv[2]);

	cudaStatus = cudaGetDeviceProperties(&prop, deviceID);
	if (cudaStatus != cudaSuccess) {
		printf("Get device(%d) info failed!\n", deviceID);
		exit(1);
	}

	printf("Device: %s\n", prop.name);
	printf("Core Clock: %.2fMHz\tMemory Clock: %.2fMhz\n", prop.clockRate / 1000.0, prop.memoryClockRate / 1000.0);
	printf("Memory Bus Width: %d\n", prop.memoryBusWidth);
	printf("Mulitprocessor Count: %d\n", prop.multiProcessorCount);

	cudaStatus = cudaSetDevice(deviceID);
	if (cudaStatus != cudaSuccess) {
		printf("Set device(%d) failed!\n", deviceID);
	}
	//Start Benchmark
	printf("Searching for best thread count.\n");
	const int workCount = 524288;
	int threadCount = 16;
	int bestThreadCount = 16;
	float bestCycleTime = 1000000;
	while (threadCount < 1024) {
		int blockCount = workCount / threadCount;
		printf("Block Count: %d, Thread Count: %d", blockCount, threadCount);
		float cycleTime = GetCycleTime(blockCount, threadCount, times);
		printf(", CycleTime: %.2fms\n", cycleTime);
		if (cycleTime < bestCycleTime) {
			bestCycleTime = cycleTime;
			bestThreadCount = threadCount;
		}
		threadCount *= 2;
	}
	printf("\nBest thread count is: %d\n\n", bestThreadCount);
	printf("Searching for max performance block count");
	int blockCount = 512;
	int maxPerformanceBlockCount = 0;
	int smoothBlockCount = 0;
	bestCycleTime = 1000000;
	while (blockCount < 65536)
	{
		printf("Block Count: %d, Thread Count: %d", blockCount, bestThreadCount);
		float cycleTime = GetCycleTime(blockCount, bestThreadCount, times);
		float GPUTime = timeSlice * 1000 / CLOCKS_PER_SEC;
		printf(", CycleTime: %.2fms, GPU Time: %.2f\n", cycleTime, GPUTime);
		if (smoothBlockCount == 0 && GPUTime > 16) {
			smoothBlockCount = blockCount / 2;
		}
		if (cycleTime < bestCycleTime) {
			bestCycleTime = cycleTime;
			maxPerformanceBlockCount = blockCount;
		}
		blockCount *= 2;
	}
	printf("\nTesting device speed...\n");
	float finalCycleTime = GetCycleTime(maxPerformanceBlockCount, bestThreadCount, times * 16);
	printf("Average cycle time: %.2f, Speed: %.2f\n", finalCycleTime, 200000 / finalCycleTime);
	printf("Best parameter: -d %d -t %d -b %d -b2 %d\n", deviceID, bestThreadCount, smoothBlockCount, maxPerformanceBlockCount);
}
