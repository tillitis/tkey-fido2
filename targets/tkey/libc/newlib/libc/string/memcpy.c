/*
FUNCTION
        <<memcpy>>---copy memory regions

SYNOPSIS
        #include <string.h>
        void* memcpy(void *restrict <[out]>, const void *restrict <[in]>,
                     size_t <[n]>);

DESCRIPTION
        This function copies <[n]> bytes from the memory region
        pointed to by <[in]> to the memory region pointed to by
        <[out]>.

        If the regions overlap, the behavior is undefined.

RETURNS
        <<memcpy>> returns a pointer to the first byte of the <[out]>
        region.

PORTABILITY
<<memcpy>> is ANSI C.

<<memcpy>> requires no supporting OS subroutines.

QUICKREF
        memcpy ansi pure
	*/

#include <string.h>

void *
memcpy (void *__restrict dst0,
	const void *__restrict src0,
	size_t len0)
{
  char *dst = (char *) dst0;
  const char *src = (const char *) src0;

  void *save = dst0;

  while (len0--)
    {
      *dst++ = *src++;
    }

  return save;
}
