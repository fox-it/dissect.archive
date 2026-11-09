#include <pspkernel.h>
#include <pspdebug.h>

PSP_MODULE_INFO("HELLODIS", PSP_MODULE_USER, 1, 1);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER | THREAD_ATTR_VFPU);

#define printf pspDebugScreenPrintf

int main(void)
{
	pspDebugScreenInit();
	printf("Kusjes van SRT <3\n");

	while (1) {
		sceKernelDelayThread(1000000);
	}

	return 0;
}
