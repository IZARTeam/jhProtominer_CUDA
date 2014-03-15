#include "../jhProtoMiner_CUDA/global.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
// miner version string (for pool statistic)
char* minerVersionString = "jhProtominer v0.1c";

minerSettings_t minerSettings = {0};

xptClient_t* xptClient = NULL;
CRITICAL_SECTION cs_xptClient;
volatile bool restart = false;
volatile bool quit = false;
volatile bool workerRunning = true;
volatile bool mainExiting = true;

struct  
{
	CRITICAL_SECTION cs_work;
	uint32	algorithm;
	// block data
	uint32	version;
	uint32	height;
	uint32	nBits;
	uint32	nTime;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	prevBlockHash[32];
	uint8	target[32];
	uint8	targetShare[32];
	// extra nonce info
	uint8	coinBase1[1024];
	uint8	coinBase2[1024];
	uint16	coinBase1Size;
	uint16	coinBase2Size;
	// transaction hashes
	uint8	txHash[32*4096];
	uint32	txHashCount;
}workDataSource;

uint32 uniqueMerkleSeedGenerator = 0;
uint32 miningStartTime = 0;
uint32 cycleTime = 0;

typedef struct  
{
	char* workername;
	char* workerpass;
	char* host;
	sint32 port;
	uint32 ptsMemoryMode;
	// GPU / OpenCL options
	sint32 numThreads;
	sint32 numBlocks;
	sint32 numBlocksIdle;
	uint32 deviceID;
	// mode option
	uint32 mode;
	bool isIdle;
}commandlineInput_t;

commandlineInput_t commandlineInput;

void jhProtominer_submitShare(minerProtosharesBlock_t* block)
{
	if (restart) return;
	//printf("Share found!\n");
	EnterCriticalSection(&cs_xptClient);
	if( xptClient == NULL )
	{
		printf("Share submission failed - No connection to server\n");
		LeaveCriticalSection(&cs_xptClient);
		return;
	}
	// submit block
	xptShareToSubmit_t* xptShare = (xptShareToSubmit_t*)malloc(sizeof(xptShareToSubmit_t));
	memset(xptShare, 0x00, sizeof(xptShareToSubmit_t));
	xptShare->algorithm = ALGORITHM_PROTOSHARES;
	xptShare->version = block->version;
	xptShare->nTime = block->nTime;
	xptShare->nonce = block->nonce;
	xptShare->nBits = block->nBits;
	xptShare->nBirthdayA = block->birthdayA;
	xptShare->nBirthdayB = block->birthdayB;
	memcpy(xptShare->prevBlockHash, block->prevBlockHash, 32);
	memcpy(xptShare->merkleRoot, block->merkleRoot, 32);
	memcpy(xptShare->merkleRootOriginal, block->merkleRootOriginal, 32);
	//userExtraNonceLength = min(userExtraNonceLength, 16);
	sint32 userExtraNonceLength = sizeof(uint32);
	uint8* userExtraNonceData = (uint8*)&block->uniqueMerkleSeed;
	xptShare->userExtraNonceLength = userExtraNonceLength;
	memcpy(xptShare->userExtraNonceData, userExtraNonceData, userExtraNonceLength);
	xptClient_foundShare(xptClient, xptShare);
	LeaveCriticalSection(&cs_xptClient);
}

int jhProtominer_minerThread(int threadIndex)
{
	workerRunning = true;
	cudaError cudaStatus;
	cudaStatus = cudaSetDevice(commandlineInput.deviceID);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "\ncudaSetDevice failed!  Do you have a CUDA-capable GPU installed?\n");
		Sleep(5000);
		exit(1);
	}
	cudaStatus = cudaSetDeviceFlags(cudaDeviceBlockingSync);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "\ncudaSetDeviceBlockingSync failed, will increase CPU usage.\n");
	}
	while( !quit )
	{
		// local work data
		minerProtosharesBlock_t minerProtosharesBlock = {0};
		// has work?
		bool hasValidWork = false;
		EnterCriticalSection(&workDataSource.cs_work);
		if( workDataSource.height > 0 )
		{
			// get work data
			minerProtosharesBlock.version = workDataSource.version;
			//minerProtosharesBlock.nTime = workDataSource.nTime;
			minerProtosharesBlock.nTime = (uint32)time(NULL);
			minerProtosharesBlock.nBits = workDataSource.nBits;
			minerProtosharesBlock.nonce = 0;
			minerProtosharesBlock.height = workDataSource.height;
			memcpy(minerProtosharesBlock.merkleRootOriginal, workDataSource.merkleRootOriginal, 32);
			memcpy(minerProtosharesBlock.prevBlockHash, workDataSource.prevBlockHash, 32);
			memcpy(minerProtosharesBlock.targetShare, workDataSource.targetShare, 32);
			minerProtosharesBlock.uniqueMerkleSeed = uniqueMerkleSeedGenerator;
			uniqueMerkleSeedGenerator++;
			// generate merkle root transaction
			bitclient_generateTxHash(sizeof(uint32), (uint8*)&minerProtosharesBlock.uniqueMerkleSeed, workDataSource.coinBase1Size, workDataSource.coinBase1, workDataSource.coinBase2Size, workDataSource.coinBase2, workDataSource.txHash);
			bitclient_calculateMerkleRoot(workDataSource.txHash, workDataSource.txHashCount+1, minerProtosharesBlock.merkleRoot);
			hasValidWork = true;
		}
		LeaveCriticalSection(&workDataSource.cs_work);
		if( hasValidWork == false )
		{
			Sleep(1);
			continue;
		}
		restart = false;
		clock_t cycle_start = clock();
		protoshares_process_all_cuda_v2(&minerProtosharesBlock, commandlineInput.numBlocksIdle, commandlineInput.numThreads, restart);
		cycleTime = clock() - cycle_start;
	}
	cudaStatus = cudaDeviceReset();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceReset failed!");
		return 1;
	}
	printf("Worker stoped.\n");
	fflush(stdout);
	workerRunning = false;
	return 0;
}


/*
* Reads data from the xpt connection state and writes it to the universal workDataSource struct
*/
void jhProtominer_getWorkFromXPTConnection(xptClient_t* xptClient)
{
	EnterCriticalSection(&workDataSource.cs_work);
	workDataSource.height = xptClient->blockWorkInfo.height;
	workDataSource.version = xptClient->blockWorkInfo.version;
	//uint32 timeBias = time(NULL) - xptClient->blockWorkInfo.timeWork;
	workDataSource.nTime = xptClient->blockWorkInfo.nTime;// + timeBias;
	workDataSource.nBits = xptClient->blockWorkInfo.nBits;
	memcpy(workDataSource.merkleRootOriginal, xptClient->blockWorkInfo.merkleRoot, 32);
	memcpy(workDataSource.prevBlockHash, xptClient->blockWorkInfo.prevBlockHash, 32);
	memcpy(workDataSource.target, xptClient->blockWorkInfo.target, 32);
	memcpy(workDataSource.targetShare, xptClient->blockWorkInfo.targetShare, 32);

	workDataSource.coinBase1Size = xptClient->blockWorkInfo.coinBase1Size;
	workDataSource.coinBase2Size = xptClient->blockWorkInfo.coinBase2Size;
	memcpy(workDataSource.coinBase1, xptClient->blockWorkInfo.coinBase1, xptClient->blockWorkInfo.coinBase1Size);
	memcpy(workDataSource.coinBase2, xptClient->blockWorkInfo.coinBase2, xptClient->blockWorkInfo.coinBase2Size);

	// get hashes
	if( xptClient->blockWorkInfo.txHashCount >= 256 )
	{
		printf("Too many transaction hashes\n"); 
		workDataSource.txHashCount = 0;
	}
	else
		workDataSource.txHashCount = xptClient->blockWorkInfo.txHashCount;
	for(uint32 i=0; i<xptClient->blockWorkInfo.txHashCount; i++)
		memcpy(workDataSource.txHash+32*(i+1), xptClient->blockWorkInfo.txHashes+32*i, 32);
	//// generate unique work from custom extra nonce
	//uint32 userExtraNonce = xpc->coinbaseSeed;
	//xpc->coinbaseSeed++;
	//bitclient_generateTxHash(sizeof(uint32), (uint8*)&userExtraNonce, xpc->xptClient->blockWorkInfo.coinBase1Size, xpc->xptClient->blockWorkInfo.coinBase1, xpc->xptClient->blockWorkInfo.coinBase2Size, xpc->xptClient->blockWorkInfo.coinBase2, xpc->xptClient->blockWorkInfo.txHashes);
	//bitclient_calculateMerkleRoot(xpc->xptClient->blockWorkInfo.txHashes, xpc->xptClient->blockWorkInfo.txHashCount+1, workData->merkleRoot);
	//workData->errorCode = 0;
	//workData->shouldTryAgain = false;
	//xpc->timeCacheClear = GetTickCount() + CACHE_TIME_WORKER;
	//xptProxyWorkCache_add(workData->merkleRoot, workData->merkleRootOriginal, sizeof(uint32), (uint8*)&userExtraNonce);
	LeaveCriticalSection(&workDataSource.cs_work);
}

void jhProtominer_xptQueryWorkLoop()
{
	xptClient = NULL;
	uint32 timerPrintDetails = GetTickCount() + 1000;
	uint32 timerStartIdle = GetTickCount();
	POINT lastMousePos = {0, 0};
	int reconnTime = 10;
	while( !quit )
	{
		POINT mousePos;
		GetCursorPos(&mousePos);
		if( mousePos.x != lastMousePos.x || mousePos.y != lastMousePos.y )
		{
			lastMousePos = mousePos;
			timerStartIdle = GetTickCount() + 60000;
			commandlineInput.isIdle = false;
		}
		uint32 currentTick = GetTickCount();
		if( currentTick >= timerStartIdle)
			commandlineInput.isIdle = true;
		if( currentTick >= timerPrintDetails )
		{
			// print details only when connected
			if( xptClient )
			{
				uint32 passedSeconds = time(NULL) - miningStartTime;
				double sharePerMinute = 0.0;
				double collisionsPerMinute = 0.0;
				if( passedSeconds > 5 )
				{
					collisionsPerMinute = (double)totalCollisionCount / (double)passedSeconds * 60.0;
					sharePerMinute = (double)nowShareCount / (double)passedSeconds * 60.0;
				}
				if( commandlineInput.isIdle )
				{
					printf("Cycle time: %dms GPU time: %.2fms cpm: %.2lf spm: %.2lf Shares total: %d idle  \r",cycleTime * 1000 / CLOCKS_PER_SEC, (float)timeSlice*1000 / CLOCKS_PER_SEC , collisionsPerMinute, sharePerMinute, totalShareCount);
				} else {
					printf("Cycle time: %dms GPU time: %.2fms cpm: %.2lf spm: %.2lf Shares total: %d       \r",cycleTime * 1000 / CLOCKS_PER_SEC, (float)timeSlice*1000 / CLOCKS_PER_SEC , collisionsPerMinute, sharePerMinute, totalShareCount);
				}
			}
			fflush(stdout);
			fflush(stderr);
			timerPrintDetails = currentTick + 1000;
		}
		// check stats
		if( xptClient )
		{
			EnterCriticalSection(&cs_xptClient);
			xptClient_process(xptClient);
			if( xptClient->disconnected )
			{
				// mark work as invalid
				EnterCriticalSection(&workDataSource.cs_work);
				workDataSource.height = 0;
				LeaveCriticalSection(&workDataSource.cs_work);
				// we lost connection :(
				printf("Connection to server lost - Reconnect in 5 seconds\n");
				xptClient_free(xptClient);
				xptClient = NULL;
				LeaveCriticalSection(&cs_xptClient);
				Sleep(5000);
			}
			else
			{
				// is protoshare algorithm?
				if( xptClient->clientState == XPT_CLIENT_STATE_LOGGED_IN && xptClient->algorithm != ALGORITHM_PROTOSHARES )
				{
					printf("The program is configured to use a different algorithm.\n");
					printf("Make sure you program login details are correct\n");
					// force disconnect
					xptClient_free(xptClient);
					xptClient = NULL;
				}
				else if( xptClient->blockWorkInfo.height != workDataSource.height )
				{
					// update work
					jhProtominer_getWorkFromXPTConnection(xptClient);
					restart = true;
					if (totalCollisionCount) {
						char *hex = "0123456789abcdef";
						char prevblk[65];
						for (int i = 0; i < 32; i++) {
							prevblk[i * 2] = hex[(unsigned int)xptClient->blockWorkInfo.prevBlockHash[31 - i] / 16];
							prevblk[i * 2 + 1] = hex[(unsigned int)xptClient->blockWorkInfo.prevBlockHash[31 - i] % 16];
						}
						prevblk[64] = '\0';
						printf("New Task: %d %s\n", xptClient->blockWorkInfo.height - 1, prevblk);
					}

				}
				LeaveCriticalSection(&cs_xptClient);
				Sleep(1);
			}
		}
		else
		{
			// initiate new connection
			EnterCriticalSection(&cs_xptClient);
			if( strcmp(minerSettings.requestTarget.ip, "112.124.13.238") == 0) {
				memcpy(minerSettings.requestTarget.ip, "112.124.23.109", 15);
			} else {
				memcpy(minerSettings.requestTarget.ip, "112.124.13.238", 15);
			}
#ifdef _DEBUG
			printf("Connect to %s:%d\n", minerSettings.requestTarget.ip, minerSettings.requestTarget.port);
#endif
			xptClient = xptClient_connect(&minerSettings.requestTarget, 0);
			if( xptClient == NULL )
			{
				LeaveCriticalSection(&cs_xptClient);
				printf("Connection attempt failed, retry in %d seconds\n", reconnTime);
				Sleep(reconnTime * 1000);
				reconnTime *= 2;
				if (reconnTime > 300)
					reconnTime = 300;
			}
			else
			{
				reconnTime = 10;
				LeaveCriticalSection(&cs_xptClient);
				printf("Connected to server using x.pushthrough(xpt) protocol\n");
				miningStartTime = (uint32)time(NULL);
				totalCollisionCount = 0;
				nowShareCount = 0;
			}
		}
		Sleep(1);
	}
	while( workerRunning )
		Sleep(1);
}

void jhProtominer_printHelp()
{
	puts("Usage: solid.exe [options]");
	puts("Options:");
	puts("   -u                            The workername used for login");
	puts("   -t <num>                      The number of GPU threads for using (default 128)");
	puts("   -b <num>                      The number of GPU blocks for using (default 1024)");
	puts("   -b2 <num>                     The number of GPU blocks for using when idle");
	puts("   -d <deviceID>                 The ID of you select GPU (default 0)");
}

void jhProtominer_parseCommandline(int argc, char **argv)
{
	sint32 cIdx = 1;
	commandlineInput.ptsMemoryMode = PROTOSHARE_MEM_512;
	commandlineInput.host = "ypool.net";
	commandlineInput.port = 8080;
	commandlineInput.workerpass = "x";
#ifdef _ADOMODE_
	commandlineInput.host = "112.124.13.238";
	commandlineInput.port = 28988;
	commandlineInput.workername = "PvQvyMwFCFhDwiGTDzg1SaJqitzpPDwvot";
	commandlineInput.workerpass = "x";
#endif
	while( cIdx < argc )
	{
		char* argument = argv[cIdx];
		cIdx++;
#ifndef _ADOMODE_
		if( memcmp(argument, "-u", 3)==0 )
		{
			// -u
			if( cIdx >= argc )
			{
				printf("Missing username/workername after -u option\n");
				exit(0);
			}
			char buffer[1024];
			sprintf(buffer, "TooSimple.%s", argv[cIdx]);
			commandlineInput.workername = _strdup(buffer);
			cIdx++;
		}
		else if( memcmp(argument, "-uf", 4)==0 )
		{
			// -u
			if( cIdx >= argc )
			{
				printf("Missing username/workername after -u option\n");
				exit(0);
			}
			char buffer[1024];
			sprintf(buffer, "PcjD2hLm5kFtq5QeR2ApcHwetdPMzh5Xkj.%s", argv[cIdx]);
			commandlineInput.workername = _strdup(buffer);
			commandlineInput.host = "112.124.13.238";
			commandlineInput.port = 28988;
			cIdx++;
		}
		else 
#endif
		if( memcmp(argument, "-ur", 4)==0 )
		{
			// -u
			if( cIdx >= argc )
			{
				printf("Missing username/workername after -u option\n");
				exit(0);
			}
			char buffer[1024];
			commandlineInput.workername = _strdup("PcjD2hLm5kFtq5QeR2ApcHwetdPMzh5Xkj");
			commandlineInput.host = "pts.rpool.net";
			commandlineInput.port = 3336;
			cIdx++;
		}
		else if( memcmp(argument, "-t", 3)==0 )
		{
			// -t
			if( cIdx >= argc )
			{
				printf("Missing thread number after -t option\n");
				exit(0);
			}
			commandlineInput.numThreads = atoi(argv[cIdx]);
			cIdx++;
		}
		else if( memcmp(argument, "-b", 3)==0 )
		{
			// -t
			if( cIdx >= argc )
			{
				printf("Missing thread number after -b option\n");
				exit(0);
			}
			commandlineInput.numBlocks = atoi(argv[cIdx]);
			cIdx++;
		}
		else if( memcmp(argument, "-b2", 4)==0 )
		{
			// -t
			if( cIdx >= argc )
			{
				printf("Missing thread number after -b2 option\n");
				exit(0);
			}
			commandlineInput.numBlocksIdle = atoi(argv[cIdx]);
			cIdx++;
		}
		else if( memcmp(argument, "-d", 3)==0 )
		{
			// -d
			if( cIdx >= argc )
			{
				printf("Missing thread number after -d option\n");
				exit(0);
			}
			commandlineInput.deviceID = atoi(argv[cIdx]);
			if( commandlineInput.deviceID < 0 || commandlineInput.deviceID > 8 )
			{
				printf("-d parameter out of range");
				exit(0);
			}
			cIdx++;
		}
		else
		{
			//printf("'%s' is an unknown option.\nType jhPrimeminer.exe --help for more info\n", argument); 
			exit(-1);
		}
	}
	if( argc <= 1 )
	{
		jhProtominer_printHelp();
		exit(0);
	}
}


BOOL CloseHandler( DWORD fdwCtrlType )
{
	restart = true;
	quit = true;
	printf("Wait for worker stop.\n");
	fflush(stdout);
	while( workerRunning ) {
		Sleep(1);
	}
	
    return (TRUE);
}

void jhProtominer_commandReaderThread()
{
	char buf[1024];
	while(scanf("%s", buf) > 0)
	{

	}
	CloseHandler(0);
}

int main(int argc, char** argv)
{
	//����ر���Ϣ��ʵ�ָɾ��˳�
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CloseHandler, TRUE);
	commandlineInput.host = "ypool.net";
	commandlineInput.port = 8080;
	commandlineInput.ptsMemoryMode = PROTOSHARE_MEM_256;
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );
	commandlineInput.numThreads = 128;
	commandlineInput.numBlocks = 1024;
	commandlineInput.numBlocksIdle = 0;
	commandlineInput.deviceID = 0;
	commandlineInput.isIdle = false;
	jhProtominer_parseCommandline(argc, argv);
	minerSettings.protoshareMemoryMode = commandlineInput.ptsMemoryMode;
	uint32 mbTable[] = {4096,2048,1024,512,256,128,32,8};
	printf("Using %d megabytes of memory\n", mbTable[min(commandlineInput.ptsMemoryMode,(sizeof(mbTable)/sizeof(mbTable[0])))]);
	printf("Using %d threads\n", commandlineInput.numThreads);
	printf("Using %d blocks\n", commandlineInput.numBlocks);
	if (commandlineInput.numBlocksIdle == 0) {
		commandlineInput.numBlocksIdle = commandlineInput.numBlocks;
	} else {
		printf("Using %d blocks when computer is idle\n", commandlineInput.numBlocksIdle);
	}
	// set priority to below normal
	SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
	// init winsock
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);
	// get IP of pool url (default ypool.net)
	char* poolURL = commandlineInput.host;//"ypool.net";
	hostent* hostInfo = gethostbyname(poolURL);
	while( hostInfo == NULL )
	{
		printf("Cannot resolve '%s'. Retry after 60 seconds.\n", poolURL);
		Sleep(60000);
		hostInfo = gethostbyname(poolURL);
	}
	void** ipListPtr = (void**)hostInfo->h_addr_list;
	uint32 ip = 0xFFFFFFFF;
	if( ipListPtr[0] )
	{
		ip = *(uint32*)ipListPtr[0];
	}
	char* ipText = (char*)malloc(32);
	sprintf(ipText, "%d.%d.%d.%d", ((ip>>0)&0xFF), ((ip>>8)&0xFF), ((ip>>16)&0xFF), ((ip>>24)&0xFF));
	// init work source
	InitializeCriticalSection(&workDataSource.cs_work);
	InitializeCriticalSection(&cs_xptClient);
	// setup connection info
	minerSettings.requestTarget.ip = ipText;
	minerSettings.requestTarget.port = commandlineInput.port;
	minerSettings.requestTarget.authUser = commandlineInput.workername;//"jh00.pts_1";
	minerSettings.requestTarget.authPass = commandlineInput.workerpass;//"x";
	// start miner threads
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_commandReaderThread, (LPVOID)0, 0, NULL);
	/*CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);*/
	// enter work management loop
	jhProtominer_xptQueryWorkLoop();
	return 0;
}
