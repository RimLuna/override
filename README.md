# override
road to getting kicked out continues

**here we fucking go, pwn?**

The issue with this shit is that it's too fucking fun and tempting.
##level 00
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







