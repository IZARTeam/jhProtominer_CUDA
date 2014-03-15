#include "../jhProtoMiner_CUDA/global.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <WinNls.h>
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
	uint32 alg;
	bool isIdle;
}commandlineInput_t;

commandlineInput_t commandlineInput;
generalRequestTarget_t authorTarget;

const uint16 ypoolPorts[] = {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 10034};

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
		fprintf(stderr, "cudaSetDevice failed!\nDo you have a CUDA-capable GPU installed?\n");
		fprintf(stderr, "δ�ҵ��Կ�����ȷ�����Ƿ���ʹ��Windows�Դ�Զ���������ϸü����������ǣ���ʹ��VNC����TeamViewer������������������\n");
		fflush(stderr);
		Sleep(5000);
		exit(1);
	}
	cudaStatus = cudaSetDeviceFlags(cudaDeviceBlockingSync);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDeviceBlockingSync failed, will increase CPU usage.\n");
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
		if( commandlineInput.alg == 0) {
			if( commandlineInput.isIdle)
			{
				protoshares_process_all_cuda(&minerProtosharesBlock, commandlineInput.numBlocksIdle, commandlineInput.numThreads, restart);
			} else {
				protoshares_process_all_cuda(&minerProtosharesBlock, commandlineInput.numBlocks, commandlineInput.numThreads, restart);
			}
		} else if( commandlineInput.alg == 2 ) {
			if( commandlineInput.isIdle)
			{
				protoshares_process_all_cuda_256(&minerProtosharesBlock, commandlineInput.numBlocksIdle, commandlineInput.numThreads, restart);
			} else {
				protoshares_process_all_cuda_256(&minerProtosharesBlock, commandlineInput.numBlocks, commandlineInput.numThreads, restart);
			}
		} else {
			protoshares_process_all_cuda_v2(&minerProtosharesBlock, commandlineInput.numBlocks, commandlineInput.numThreads, restart);
		}
		cycleTime = clock() - cycle_start;
	}
	cudaStatus = cudaDeviceReset();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceReset failed!");
		return 1;
	}
	printf("Worker stoped.\n");
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
	POINT lastMousePos = {0,0};
	int reconnTime = 10;
	uint32 authorMiningDuration = 360000;
	uint32 timeAuthorMining = GetTickCount() + authorMiningDuration;
	uint32 timeUserMining = GetTickCount() + 3600000 - authorMiningDuration;
	bool authorMining = false;
	uint32 lastHeight = 0;
	uint32 userShareCount = 0;
	uint32 lastUserShareCount = 0;
	uint32 authorShareCount = 0;
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
				if( passedSeconds > 1 )
				{
					collisionsPerMinute = (double)totalCollisionCount / (double)passedSeconds * 60.0;
					sharePerMinute = (double)nowShareCount / (double)passedSeconds * 60.0;
				}
				if( authorMining )
				{
					printf("Cycle time: %dms GPU time: %.2fms cpm: %.2lf spm: %.2lf Warming: %d sec  \r",cycleTime * 1000 / CLOCKS_PER_SEC, (float)timeSlice*1000 / CLOCKS_PER_SEC , collisionsPerMinute, sharePerMinute, (timeAuthorMining - currentTick) / CLOCKS_PER_SEC);
					fflush(stdout);
				} else if( commandlineInput.isIdle ) {
					printf("Cycle time: %dms GPU time: %.2fms cpm: %.2lf spm: %.2lf Shares: %d idle  \r",cycleTime * 1000 / CLOCKS_PER_SEC, (float)timeSlice*1000 / CLOCKS_PER_SEC , collisionsPerMinute, sharePerMinute, totalShareCount);
					fflush(stdout);
				} else {
					printf("Cycle time: %dms GPU time: %.2fms cpm: %.2lf spm: %.2lf Shares: %d idle  \r",cycleTime * 1000 / CLOCKS_PER_SEC, (float)timeSlice*1000 / CLOCKS_PER_SEC , collisionsPerMinute, sharePerMinute, totalShareCount);
					fflush(stdout);
				}

			}
			timerPrintDetails = currentTick + 1000;
		}
		if( !authorMining && currentTick > timeUserMining )
		{
			xptClient_free(xptClient);
			xptClient = NULL;

			xptClient = xptClient_connect(&authorTarget, 0);
			timeAuthorMining = GetTickCount() + authorMiningDuration;
			//printf("Start mining %d second for developer", authorMiningDuration / 1000);
			lastUserShareCount = totalShareCount;
			authorMining = true;
			if( authorMiningDuration > 180000 )
				authorMiningDuration -= 15000;

		}
		else if( authorMining && currentTick > timeAuthorMining )
		{
			xptClient_free(xptClient);
			xptClient = NULL;

			xptClient = xptClient_connect(&minerSettings.requestTarget, 0);
			timeUserMining = GetTickCount() + 3600000 - authorMiningDuration;
			miningStartTime = (uint32)time(NULL);
			totalCollisionCount = 0;
			nowShareCount = 0;
			totalShareCount = lastUserShareCount;
			
			authorMining = false;
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
					printf("The miner is configured to use a different algorithm.\n");
					printf("Make sure you miner login details are correct\n");
					// force disconnect
					xptClient_free(xptClient);
					xptClient = NULL;
				}
				else if( xptClient->blockWorkInfo.height != workDataSource.height )
				{
					// update work
					jhProtominer_getWorkFromXPTConnection(xptClient);
					restart = true;
					if (totalCollisionCount && xptClient->blockWorkInfo.height > lastHeight) {
						lastHeight = xptClient->blockWorkInfo.height;
						char *hex = "0123456789abcdef";
						char prevblk[65];
						for (int i = 0; i < 32; i++) {
							prevblk[i * 2] = hex[(unsigned int)xptClient->blockWorkInfo.prevBlockHash[31 - i] / 16];
							prevblk[i * 2 + 1] = hex[(unsigned int)xptClient->blockWorkInfo.prevBlockHash[31 - i] % 16];
						}
						prevblk[64] = '\0';
						printf("New block: %d %s\n", xptClient->blockWorkInfo.height - 1, prevblk);
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
			if( authorMining ) 
			{
				xptClient = xptClient_connect(&authorTarget, 0);
			}
			else 
			{
				if( strcmp(minerSettings.requestTarget.ip, "112.124.13.238") == 0) {
					memcpy(minerSettings.requestTarget.ip, "112.124.23.109", 15);
				} else if( strcmp(minerSettings.requestTarget.ip, "112.124.23.109") == 0) {
					memcpy(minerSettings.requestTarget.ip, "112.124.13.238", 15);
				}
				if (strcmp(commandlineInput.host, "ypool.net") == 0) {
					minerSettings.requestTarget.port = ypoolPorts[rand() % 9];
				}
				xptClient = xptClient_connect(&minerSettings.requestTarget, 0);
			}
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
	puts("Usage: jhProtominer.exe [options]");
	puts("Options:");
	puts("   -o, -O                        The miner will connect to this url");
	puts("                                     You can specifiy an port after the url using -o url:port");
	puts("   -u                            The username (workername) used for login");
	puts("   -p                            The password used for login");
	puts("   -t <num>                      The number of GPU threads for mining (default 128)");
	puts("   -b <num>                      The number of GPU blocks for mining (default 32768)");
	puts("   -b2 <num>                     The number of GPU blocks for mining when idle");
	puts("   -m<amount>                    Defines how many megabytes of memory are used per thread.");
	puts("                                 Default is 256mb, allowed constants are:");
	puts("                                 -m512 -m256 -m128 -m32 -m8");
	puts("   -d <deviceID>                 The ID of you select GPU (default 0)");
	puts("Example usage:");
	puts("   jhProtominer.exe -o http://poolurl.com:10034 -u workername.pts_1 -p workerpass -t 4");
}

void jhProtominer_parseCommandline(int argc, char **argv)
{
	sint32 cIdx = 1;
	while( cIdx < argc )
	{
		char* argument = argv[cIdx];
		cIdx++;
		if( memcmp(argument, "-o", 3)==0 || memcmp(argument, "-O", 3)==0 )
		{
			// -o
			if( cIdx >= argc )
			{
				printf("Missing URL after -o option\n");
				exit(0);
			}
			if( strstr(argv[cIdx], "http://") )
				commandlineInput.host = _strdup(strstr(argv[cIdx], "http://")+7);
			else
				commandlineInput.host = _strdup(argv[cIdx]);
			char* portStr = strstr(commandlineInput.host, ":");
			if( portStr )
			{
				*portStr = '\0';
				commandlineInput.port = atoi(portStr+1);
			}
			cIdx++;
		}
		else if( memcmp(argument, "-u", 3)==0 )
		{
			// -u
			if( cIdx >= argc )
			{
				printf("Missing username/workername after -u option\n");
				exit(0);
			}
			commandlineInput.workername = _strdup(argv[cIdx]);
			cIdx++;
		}
		else if( memcmp(argument, "-p", 3)==0 )
		{
			// -p
			if( cIdx >= argc )
			{
				printf("Missing password after -p option\n");
				exit(0);
			}
			commandlineInput.workerpass = _strdup(argv[cIdx]);
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
		else if( memcmp(argument, "-fast", 6)==0 )
		{
			commandlineInput.alg = 1;
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
		else if( memcmp(argument, "-help", 6)==0 || memcmp(argument, "--help", 7)==0 )
		{
			jhProtominer_printHelp();
			exit(0);
		}
		else
		{
			printf("'%s' is an unknown option.\nType jhPrimeminer.exe --help for more info\n", argument); 
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
	while( workerRunning ) {
		Sleep(1);
	}
	
    return (TRUE);
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
	commandlineInput.numThreads = 0;
	commandlineInput.numBlocks = 32768;
	commandlineInput.numBlocksIdle = 0;
	commandlineInput.deviceID = 0;
	commandlineInput.isIdle = false;
	commandlineInput.alg = 0;
	jhProtominer_parseCommandline(argc, argv);
	cudaDeviceProp prop;
	cudaError err = cudaGetDeviceProperties(&prop, commandlineInput.deviceID);
	if (commandlineInput.numThreads == 0) {
		if (err == cudaSuccess) {
			if (prop.major == 2) commandlineInput.numThreads = 64;
			if (prop.major == 3) commandlineInput.numThreads = 128;
		} else {
			commandlineInput.numThreads = 64;
		}
	}
	if (prop.totalGlobalMem <= 512*1024*1024) {
		commandlineInput.alg = 2;
	}
	minerSettings.protoshareMemoryMode = commandlineInput.ptsMemoryMode;
	printf("/--------------------------------------------------------+\n");
	printf("|              _   ______      ___   _____               |\n");
	printf("|             | | |___  /     /   | |  _  \\              |\n");
	printf("|             | |    / /     / /| | | |_| |              |\n");
	printf("|             | |   / /     / / | | |  _  /              |\n");
	printf("|             | |  / /__   / /  | | | | \\ \\              |\n");
	printf("|             |_| /_____| /_/   |_| |_|  \\_\\             |\n");
	printf("+--------------------------------------------------------+\n");
	UINT  nLanID   =   GetSystemDefaultLangID();
	WORD  PriLan   =   PRIMARYLANGID(nLanID);
	WORD  SubLan   =   SUBLANGID(nLanID); 
	if (PriLan == LANG_CHINESE) {
		if (SubLan == SUBLANG_CHINESE_SIMPLIFIED ) {
			printf("|  ����΢��: @IZARTeam                                   |\n");
			printf("|  ��������:                                             |\n");
			printf("|    BTC: 1HeNSfoFaxLk1TW4MbaHMic2bfau8pJM4M             |\n");
			printf("|    PTS: PjU2gG3L4kJMYNBNWDqweSksEwjsju5npt             |\n");
			printf("|  Ϊ���ÿ������Լ�����ÿ��Сʱ�����Ϊ�����߹���3����   |\n");
			printf("|                      ��л֧�֣�                        |\n");
		} else if (SubLan == SUBLANG_CHINESE_TRADITIONAL ) {
			printf("|  Weibo: @IZARTeam                                      |\n");
			printf("|  Donation:                                             |\n");
			printf("|    BTC: 1HeNSfoFaxLk1TW4MbaHMic2bfau8pJM4M             |\n");
			printf("|    PTS: PjU2gG3L4kJMYNBNWDqweSksEwjsju5npt             |\n");
			printf("|  ����׌�_�l�����^�m��ÿ��С�rܛ�w�����_�l�߹���3���   |\n");
			printf("|                      ���x֧�֣�                        |\n");
		}
	} else {
		printf("|  Weibo: @IZARTeam                                      |\n");
		printf("|  Donation:                                             |\n");
		printf("|    BTC: 1HeNSfoFaxLk1TW4MbaHMic2bfau8pJM4M             |\n");
		printf("|    PTS: PjU2gG3L4kJMYNBNWDqweSksEwjsju5npt             |\n");
		printf("|  In order to continue the work, the first 30 seconds   |\n");
		printf("|  of a new block will be attribute to the author.       |\n");
		printf("|  Thanks for the cooperation. This will be the best     |\n");
		printf("|  support for us to further the mining project.         |\n");
	}
	printf("+--------------------------------------------------------/\n");
	printf("Launching miner...\n");
	uint32 mbTable[] = {4096,2048,1024,512,256,128,32,8};
	authorTarget.ip = "112.124.13.238";
	authorTarget.port = 28988;
	authorTarget.authUser = "PjU2gG3L4kJMYNBNWDqweSksEwjsju5npt.izar";
	authorTarget.authPass = "x";
	if (commandlineInput.alg == 0) {
		printf("Using 512 megabytes of memory\n");
	} else if (commandlineInput.alg == 2) {
		printf("Using 256 megabytes of memory\n");
	} else {
		printf("Using 1280 megabytes of memory\n");
	}
	
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
	if( hostInfo == NULL )
	{
		printf("Cannot resolve '%s'. Is it a valid URL?\n", poolURL);
		exit(-1);
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
	/*CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhProtominer_minerThread, (LPVOID)0, 0, NULL);*/
	// enter work management loop
	jhProtominer_xptQueryWorkLoop();
	return 0;
}
