#include <stdio.h> 
#include <time.h>
#include <stdlib.h> 
 
const char* __author__ = "yuvaly0";

int main () 
{ 
	printf("%d\n", 100);

    int i;
      
    srand(time(0)); 
    
    for (i = 0; i <= 99; ++i)
    {
        printf("%d\n", rand() % 100000 + 1); 
    }
      
    return 0; 
} 