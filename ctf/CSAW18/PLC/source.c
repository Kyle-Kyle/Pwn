nclude <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//
// our spies could not exfiltratee the plc's header file
// so you'll have to reverse the remaining functionality...
//

#include "plc.h"
#include "sandbox.h" // disable_system()

bool g_debug= 0;		//0x202499
char code[0x100] = 0;	//0x2024a0
//0x30383231aa615746    0x4132523255323133
//0x4d32553249324e32    0x5832453248322032
//0x55324c3246324132    0x4432493252324f32
//0x3737373700324532    0x3737373737373737
//0x3737373737373737    0x3737373737373737
//0x3737373737373737    0x3737373737373737
//0x3737373737373737    0x3737373737373737
//0x0000000039373737    0x0000000000000000

// symbols 
//0x555555554000
//puts:					0x202018
//fread:				0x202020
//__stack_chk_fail:		0x202028
//printf:				0x202030
//memset:				0x202038
//__libc_start_main:	0x202040
//fgets:				0x202048
//setvbuf:				0x202050
//exit:					0x202058
//
//abort:				0x201fc0
//
//mprotect:				0x201fe0
//
//system:				0x201fd0
//__gmon_start__:		0x201fd8
//
//__cxa_finalize:		0x201ff8
//
//
//DEBUG:				0x202499
//code:					0x2024a0
//
//g1:					0x2028a0//int
//enrich:				0x2028a4// some string 0x40
//override:				0x2028e4//bool
//g3:					0x2028e8// alert pointer
//abort_func:			0x2028f0// abort pointer
//stdin:				0x202490

void plc_main()
{
    char cmd[128] = {};
    
    printf(" - - - - - - - - - - - - - - - - - - - - \n");
    printf(" - PLC Remote Management Protocol v0.5 - \n");
    printf(" - - - - - - - - - - - - - - - - - - - - \n");

    while(1)
    {
        if(!fgets(cmd, sizeof(cmd), stdin))
            break;
        
        if(g_debug)
            printf("[DEBUG] PLC CMD 0x%02X\n", cmd[0]);

        // update PLC firmware
        if(cmd[0] == 'U')
            update_firmware(); 

        // execute PLC fw
        else if(cmd[0] == 'E')
            execute_firmware();
        
        // print PLC status
        else if(cmd[0] == 'S')
            print_plc_status();
        
        // reset PLC
        else if(cmd[0] == 'R')
            reset_plc();

        // Quit / disconnect from this session
        else if(cmd[0] == 'Q')
			break;
    }
}

int validate_checksum(char* code_buf)
{
	// some validate algorithm
	if(g_debug){
		printf("[DEBUG] REPORTED FW CHECKSUM: %04X\n", &code_buf[2]);
		printf("[DEBUG]   ACTUAL FW CHECKSUM: %04X\n", real_checksum);
	}
}

void print_plc_status()
{
	if(g_debug)puts("[DEBUG] PRINTING PLC STATUS");
	// some puts
	printf("  * FW VERSION: v%c.%c\n", code[4], code[5]);
	printf("  * FW CHECKSUM: %04X\n", code[2]);
	printf("  * CENTRIFUGE RPM: %d RPM\n", g1);
	printf("  * ENRICHMENT MATERIAL: %s\n", enrich);
	printf("");
	if(override){
		puts("  * OVERRIDE: ACTIVE");
	}
	else{
		puts("  * OVERRIDE: DISABLED");
	}
}

void update_firmware()
{
	long canary;//rbp-8
	char buf[0x400];//rbp-0x410
	unsigned int status = 0;
	if(g_debug)puts("[DEBUG] UPDATING FIRMWARE");

	memset(buf, 0, 0x400);
	fread(buf, 1, 0x400, stdin);

	if(buf[0] == 'F' || buf[0] == 'W'){
		if(!validate_checksum(buf))//success
		{
			if(code[4]>0x39 || code[5] >0x39){
				status = 3;
			}
			else{
				reset_plc();
				memcpy(code, buf, 0x400);
				status = 0
			}
		}
		else{
			status = 2;
		}
	}
	else{
		status = 1;
	}

	if(status)puts("FIRMWARE UPDATE FAILED!");
	else puts("FIRMWARE UPDATE SUCCESSFUL!");

	if(g_debug)puts("[DEBUG] UPDATE RESULT CODE %u", status);
}

void boot_plc()
{
	puts("BOOTING PLC...");
    init_firmware();
    execute_firmware();
	plc_main();
}

void main()
{
    // disable buffering on stdout (ignore this)
    setvbuf(stdout, NULL, _IONBF, 0);

	// disable libc system() for better device security
    disable_system();

	// start the PLC
	boot_plc();
}

void bad_system()
{
	puts("!!!!! SECURITY BREACH - SYSTEM CALLED !!!!!");
	abort();
}

void disable_system()
{
	mprotect(system&0xfffffffffffff000, 0x1000, PROT_READ|PROT_WRITE);
	substitute_system_by_bad_system();
	mprotect(system&0xfffffffffffff000, 0x1000, PROT_READ|PROT_EXEC);
}

void init_firmware()
{
	if(g_debug)puts("[DEBUG] INITIALIZING DEFAULT FIRMWARE...");
	init_code();// copy code in data section to global variables, maybe writable
}

void reset_plc()
{
	if(g_debug)puts("[DEBUG] RESETTING PLC RUNTIME STATE...");
	g1 = 0;
	override = 0;
	g3 = rmp_alert;
	abort_func = abort;
	memset(enrich, 0, 0x40);
	strcpy(enrich, "<none>\x00\x00");
}
void rpm_alert()
{
	// sequence of stupid puts and this:
	printf("[WARNING]   CURRENT RPM: %d\n", g1);
}
void execute_firmware()
{
	char op = 0;//rbp-9
	unsigned addr = 6;//rbp-8
	int v3 = 0;//rbp-4

	reset_plc();
	if(g_debug)puts("[DEBUG] BEGIN EXECUTION");

	if(addr <= 0x3fe){
		op = code[addr];
		if(g_debug)printf("[DEBUG] 0x%03X: OP %02X\n", addr, op);
		
		switch op:
		case '0':
			g1 = 0;
			addr += 1;
			break;
		case '1':
			if(v3 == 0){
				addr += 1;
				break;
			}
			v3 -= 1;
			enrich[v3] = 0;
			addr += 1;
			break;
		case '2':
			enrich[v3] = code[addr+1];
			v3 += 1;
			addr += 2;
			break;
		case '3':
			code[addr+1];
			if(code[addr+1] == 0x31)first_byte_of(override) = 0;
			else first_byte_of(override) = code[addr+1];
			addr += 2;
			break;
		case '6':
			if(g1 > 999){
				g1 -= 1000;
			}
			else{
				g1 = 0;
			}
			addr += 1;
			break;
		case '7':
			g1 += 1000;
			addr += 1;
			break;
		case '8':
			if(code[addr+1] == 0x31)g_debug = 0;
			else g_debug = code[addr+1];
			addr += 2;
			break;
		case '9':
			break;
		default:
			printf("[ERROR] INVALID INSTRUCTION %02X\n", op);
			exit(1)
	}

	if(g1 <= 68000){
		puts("ENRICHMENT PROCEDURE IS RUNNING");
		return;
	}
	if(override != 0){
		g3();
		return;
	}
	puts("[FAILSAFE]");
	puts("[FAILSAFE] EXCEEDED SAFE RPM LIMITS! COMMENCING EMERGENCY SHUTDOWN")
	puts("[FAILSAFE]");
	abort_func();
	return;
}
