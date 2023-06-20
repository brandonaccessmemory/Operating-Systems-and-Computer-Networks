#include "arraylist.h"
#include <stdio.h>
#include <stdlib.h>

//initialises array with argument initialSize
struct array* initArray(size_t initialSize) {
  struct array *a =(struct array *)malloc(sizeof(struct array));
  a->array = malloc(initialSize * sizeof(u_int32_t));
  a->used  = 0;
  a->size  = initialSize;
  //returns a pointer to the array  
  return(a);
}

//performs an insert to the array 
int insertArray(struct array *a, u_int32_t element) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only after the array has been accessed.
  // Therefore a->used can go up to a->size 
  if (a->used == a->size) {
    a->size *= 2;
    //realloc memory with twice the previous size of the array
    a->array = realloc(a->array, a->size * sizeof(u_int32_t));
  }

  // specifications asked for unique addresses , checks the array if address to insert already exists
  for(int i = 0; i < a->used; i++) {
    if (a->array[i] == element) 
      //prevents insertion of array if true
      return 1;     
  }

    a->array[a->used++] = element;
    return 0;
}

// free the array to prevent any memory leaks
void freeArray(struct array *a) {
  free(a->array);
  a->array = NULL;
  a->used  = a->size = 0;
}
