#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char* target_list[90] = {
"0x8048154",
"0x80481AC",
"0x80481B0",
"0x80481B4",
"0x80481B8",
"0x80481BC",
"0x80481C0",
"0x80481C8",
"0x80482C1",
"0x80482CB",
"0x80482DA",
"0x80482E2",
"0x80482E7",
"0x80482ED",
"0x80482F4",
"0x80482FB",
"0x8048301",
"0x8048308",
"0x8048310",
"0x8048317",
"0x804831E",
"0x8048330",
"0x8048335",
"0x8048344",
"0x80483F4",
"0x8048430",
"0x8048440",
"0x8048450",
"0x8048460",
"0x8048470",
"0x8048480",
"0x8048490",
"0x80484A0",
"0x80484B0",
"0x80484C0",
"0x80484D0",
"0x80484E0",
"0x80484F0",
"0x8048520",
"0x8048530",
"0x8048560",
"0x80485A0",
"0x80485C0",
"0x80485EB",
"0x804865C",
"0x8048960",
"0x80489C0",
"0x80489C4",
"0x80489D8",
"0x80489DC",
"0x80489E0",
"0x8048A4C",
"0x8048AC2",
"0x8048AD0",
"0x8048ADC",
"0x8048B01",
"0x8048B1C",
"0x8048B81",
"0x8048B9F",
"0x8048BB4",
"0x8048BF4",
"0x8048C02",
"0x8048C20",
"0x8048D38",
"0x8049F08",
"0x8049F0C",
"0x8049F10",
"0x8049F14",
"0x8049FFC",
"0x804A000",
"0x804A038",
"0x804A03C",
"0x804A040",
"0x804A044",
"0x804A048",
"0x804A04C",
"0x804A050",
"0x804A054",
"0x804A058",
"0x804A05C",
"0x804A060",
"0x804A068",
"0x804A06C",
"0x804A070",
"0x804A074",
"0x804A078",
"0x804A07C",
"0x804A080"
};
void doublefree (char* addr) {
	printf("DEBUG: In function %c",__func__);
	void* target = (void*)addr;
	printf("Working on %c",target);
	void* junk = malloc(sizeof(target));
	char a;
	char b;
	printf("DEBUG: %s",&target);
	printf("DEBUG: %s",&junk);
	char *test;
	test = (char *) malloc(15);
	strcpy(test, "test string");
	free(target);
	free(junk);
	free(target);
	void* t = malloc(sizeof(target));
	void* u = malloc(sizeof(target));
	void* x = malloc(sizeof(target));
	printf("Value of memory address %p\n%s\n",(void *) &t, t);
	printf("Value of memory address %p\n%s\n",(void *) &u, u);
	printf("Value of memory address %p\n%s\n",(void *) &x, x);
}
int i;
int main () {
	for (i = 0; i < sizeof(target_list)-1; i++) {
		char *addr = (char *) target_list[i];
		doublefree(addr);
	}
}
