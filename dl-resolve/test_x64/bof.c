/* bof.c */
#include <unistd.h>

int main()
{
	    char buf[100];
		    int size;
			    /* pop rdi; ret; pop rsi; ret; pop rdx; ret; */
			    char cheat[] = "\x5f\xc3\x5e\xc3\x5a\xc3";
				    read(0, &size, 8);
					    read(0, buf, size);
						    write(1, buf, size);
							    return 0;
}
