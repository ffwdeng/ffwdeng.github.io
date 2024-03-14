+++author = "Fabrizio Curcio"
title = "Honggfuzz!"
date = "2022-01-17"
description = "Hongfuzz!"
tags = [
  "linux",
  "security",
  "applications",
  "fuzzing",
]
categories = [
  "security",
  "linux",
  "fuzzing",
]
+++

First things first! What is Fuzzing?

Well, from 10000 feet we can say: fuzzing is a way to continuously feed random input to a program to catch bugs.
We have a program A and a starting input I, which in jargon is called corpus. We now continuously mutate I while feeding it into A. If some piece of code in A is unable to properly handle this input I, it will likely trigger some bug and make A crash.

<!--more-->

But, before moving further into fuzzing, let’s start from the beginning and explain in more detail, why I think fuzzing is a cool and necessary thing.

Every time I write code, no matter which language I use (mostly Go, C and Rust), I always want to be sure enough, that my code is not affected by subtle bugs.

What I do first, is writing tests. So, I can check if my code’s behavior is the one expected. But of course, this is not enough. I don’t think simple hand-crafted tests (even if supported by coverage) are enough to spot problems.

So, another thing I add to my secure coding checklist is static code analysis. Of course, static code analyzers are not enough either, because they’re able to spot common erroneous/dangerous patterns in source code, but this procedure is completely “offline“, since this code will be “read” and not executed. Therefore, after these two steps, here comes my favorite: fuzzing!

## An example target program to fuzz

An example program to fuzz:
check the following simple and buggy program, which suffers from an obvious stack buffer overflow in the **vuln()** function:

```c
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// stack buffer @buf is 48 bytes and @src
// can be arbitrary size
void vuln(void *src) {
    // buf is just 48 bytes
    char buf[48];

    // here stack buffer overflow happens
    // because src can be of an arbitrary
    // size supplied from user
    strcpy(buf, src);
}

int main(int argc, char *argv[]) {
    int fd;
    struct stat sb;
    void *buf;

    // open the file
    fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    // check its stats
    if (fstat(fd, &sb) == -1) {
        close(fd);
        return -1;
    }

    // allocate a buffer to hold
    the entire file content
    buf = malloc(sb.st_size);
    if (!buf) {
        close(fd);
        return -1;
    }

    // read the whole file supplied
    // as an input
    read(fd, buf, sb.st_size);

    // vuln called with an arbitrary length
    // buffer
    vuln(buf);

    // free the buffer
    free(buf);
    
    return 0;
}
```

## A bit more about fuzzers

Every programming language has more than one fuzzing tool in its ecosystem. It would surely take more than a book to list these tools and explain the techniques they use to fuzz software. In my list of fuzzers, one of **my favorite fuzzing tools** for C/C++ is **honggfuzz**.

**What is honggfuzz?** Honggfuzz is a **coverage guided fuzzer**.

What does that mean?
It allows one program to be compiled with some “instrumentation code” inside, which keeps track of which locations of the code get accessed during the fuzzing process. Honggfuzz creates dynamically input to be fed to the program and based on the knowledge it has of the actual program coverage. Here an example:

```c
void some_function(int a) {
    if (a > 20) {
        do_something();
    } else {
        do_something_else();
    }
}
```

Given a function like the one above, honggfuzz is able to create values for the a variable to both: take the **a > 20 branch** and execute **do_something()** and the else branch which invokes do_something_else().

## Running Honggfuzz

A Honggfuzz Example: To compile the simple vulnerable program to fuzz, we invoke the following commands from the shell

```bash
# create directory from which honggfuzz will get its input and outputs
mkdir in out

# create an initial corpus which honggfuzz will use as a first input
# for the program
echo -n A > in/initial_corpus

# then we compile and instrument our code
hfuzz-cc -o test test.c
```

Start fuzzing:

```bash
# --max_file_size 100 tells honggfuzz that the maximum file to feed the program will be 100 bytes
# --input is the directory from which get corpus that the fuzzer will mutate at each iteration
# --output is the directory where honggfuzz will put current program coverage
# --only-printable tells to use just printable characters for data that will be feed to the fuzzed program
# --exit_upon_crash tells to stop fuzzing after the first crash
# -- ./test __FILE__ tells honggfuzz to use the current mutated file corpus to the fuzzed program
honggfuzz --max_file_size 100 --input in/ --output out/ --only_printable --exit_upon_crash -- ./test ___FILE___
```

honggfuzz tells us, that it saved a file, which, if feed to our program, will crash it. If we try to feed it to our program, we have information of the address, where the fault happened, and so we can start debugging the issue

```bash
./test 'SIGSEGV.PC.436495.STACK.0.CODE.1.ADDR.a4220201f70.INSTR.mov____-0xb0(%rbp),%rdi.2022-06-26.17:05:33.1934768.fuzz'
UndefinedBehaviorSanitizer:DEADLYSIGNAL
==1935170==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x0a4220201f70 (pc 0x000000436495 bp 0x0a4220202020 sp 0x7ffe9f7d4ec0 T1935170)
==1935170==The signal is caused by a READ memory access.
UndefinedBehaviorSanitizer:DEADLYSIGNAL
UndefinedBehaviorSanitizer: nested bug in the same thread, aborting.
```

Do you like fuzzing? What is your favorite fuzzing tool?
