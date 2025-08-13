#include <stdio.h>
#include <stdint.h>

void enable_cyclecounter(void);
void disable_cyclecounter(void);
uint64_t get_cyclecounter(void);

int main() {
    enable_cyclecounter();
    uint64_t start = get_cyclecounter();

    
    for (volatile int i = 0; i < 1000000; i++);

    uint64_t end = get_cyclecounter();
    disable_cyclecounter();

    printf("Cycle Count: %llu\n", (unsigned long long)(end - start));
    return 0;
}

// For linux
//run: gcc -DPMU_CYCLES hal.c main.c -o test
// ./test
