// #include <stdio.h>
// int main(int argc, char **argv)
// {
//     char text[32];
//     static int some_value = -72;

//     strcpy(text, argv[1]); /* ignore the buffer overflow here */

//     printf("This is how you print correctly:\n");
//     printf("%s", text);
//     printf("This is how not to print:\n");
//     printf(text);

//     printf("some_value @ 0x%08x = %d [0x%08x]", &some_value, some_value, some_value);
//     return(0);
// }

// #include <libcgc.h>
// #include "libc.h"
#include <stdio.h>

unsigned int get_length( )
{
    unsigned int length;

    //if ( recvdata( 0, (char*)&length, sizeof(unsigned int)) != 0 ) {
        //sendstring( 0, "recvdata fail\n");
    if(1){
        printf("recvdata fail\n");
        length = 0;
    }

    return length;
}


int recvuntil( void *dest, unsigned int size, char delim)
{
    unsigned int len = 0;
    char c = 0;
    int ret = 0;
    while ( len < size ) {
        c = getchar();
        if(len == 0) ret = c;
        if ( c == delim ) {
            return len;
        }
        printf("%c %d\n",c,len);
        ((char*)dest)[len] = c;

        len++;
    }

    return ret;
}

void memcpy( void *dest, void *src, unsigned int l)
{
    int i = 0;

    for ( i = 0; i < l; i++) {
        ((char*)dest)[i] = ((char*)src)[i];
    }

    return;
}

void memset( void *dest, char val, unsigned int l)
{
    int i = 0;

    for ( i = 0; i < l; i++) {
        ((char*)dest)[i] = val;
    }

    return;
}

void readname( char *name )
{
#ifdef PATCHED_1
    #define MAX     64
#else
    #define MAX     32
#endif

    unsigned char data[MAX];
    register int i = 0;
    register int l =0;

    memset( data, 0, MAX);

    printf("Enter Name: ");

    l = recvuntil( data, 48, '\n' );

    if ( l<= 0 ) {
        return;
    }

    memcpy( name, data, l);

    return;
}

int main(void) {
    char data[10];
    char name[100];

    int i = 0;

    while ( 1 ) {
        printf("1) Gimme Name\n");
        printf("2) Print Name\n");
        printf("3) Exit\n");
        printf(": ");

        for ( i = 0; i < 10; i++) {
            data[i] = 0;
        }

        recvuntil( data, 2, '\n');

        switch ( data[0]-0x30) {
            case 1:
                readname( name );
                break;
            case 2:
                printf("%s\n", name);
                break;
            case 3:
                printf("Exit\n");
                return 0;
                break;
            default:
                printf("Invalid\n");
                break;
        };
    }

    return 0;
}



/*
  StackOverrun.c
  This program shows an example of how a stack-based 
  buffer overrun can be used to execute arbitrary code.  Its 
  objective is to find an input string that executes the function bar.
*/



// #pragma check_stack(off)

// #include <string.h>
// #include <stdio.h> 

// void cpy( void *dest, void *src)
// {
//     int i = 0;
//     int l = strlen(src);
//     for ( i = 0; i < l; i++) {
//         ((char*)dest)[i] = ((char*)src)[i];
//     }

//     return;
// }

// int foo(const char* input)
// {
//     char buf[10];

//     printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");

//     strcpy(buf, input);
//     printf("%s\n", buf);

//     printf("Now the stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
//     return buf[0];
// }

// void bar(void)
// {
//     printf("Augh! I've been hacked!\n");
// }

// int main(int argc, char* argv[])
// {
//     //Blatant cheating to make life easier on myself
//     printf("Address of foo = %p\n", foo);
//     printf("Address of bar = %p\n", bar);
//     if (argc != 2) 
//  {
//         printf("Please supply a string as an argument!\n");
//         return -1;
//     } 
// foo(argv[1]);
//     return 0;
// }
