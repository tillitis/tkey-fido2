/*
FUNCTION
	<<memcmp>>---compare two memory areas

INDEX
	memcmp

SYNOPSIS
	#include <string.h>
	int memcmp(const void *<[s1]>, const void *<[s2]>, size_t <[n]>);

DESCRIPTION
	This function compares not more than <[n]> characters of the
	object pointed to by <[s1]> with the object pointed to by <[s2]>.


RETURNS
	The function returns an integer greater than, equal to or
	less than zero 	according to whether the object pointed to by
	<[s1]> is greater than, equal to or less than the object
	pointed to by <[s2]>.

PORTABILITY
<<memcmp>> is ANSI C.

<<memcmp>> requires no supporting OS subroutines.

QUICKREF
	memcmp ansi pure
*/

#include <string.h>


int
memcmp (const void *m1,
	const void *m2,
	size_t n)
{
  const unsigned char *s1 = (const unsigned char *) m1;
  const unsigned char *s2 = (const unsigned char *) m2;

  while (n--)
    {
      if (*s1 != *s2)
	{
	  return *s1 - *s2;
	}
      s1++;
      s2++;
    }
  return 0;
}

