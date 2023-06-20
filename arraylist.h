#include <stdio.h>
#include <stdlib.h>
// data structure for a dynamic array
typedef struct array{ 
  u_int32_t *array;
  int used;
  int size;
} Array;

struct array* initArray(size_t initialSize);

int insertArray(struct array *a, u_int32_t element);

void freeArray(struct array *a);

//global array that can be accessed across c files by including the header file
extern Array *syn_addr;
