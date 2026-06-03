/*
FUNCTION
	<<strcmp>>---character string compare
	
INDEX
	strcmp

SYNOPSIS
	#include <string.h>
	int strcmp(const char *<[a]>, const char *<[b]>);

DESCRIPTION
	<<strcmp>> compares the string at <[a]> to
	the string at <[b]>.

RETURNS
	If <<*<[a]>>> sorts lexicographically after <<*<[b]>>>,
	<<strcmp>> returns a number greater than zero.  If the two
	strings match, <<strcmp>> returns zero.  If <<*<[a]>>>
	sorts lexicographically before <<*<[b]>>>, <<strcmp>> returns a
	number less than zero.

PORTABILITY
<<strcmp>> is ANSI C.

<<strcmp>> requires no supporting OS subroutines.

QUICKREF
	strcmp ansi pure
*/

#include <string.h>

int
strcmp (const char *s1,
	const char *s2)
{ 
  while (*s1 != '\0' && *s1 == *s2)
    {
      s1++;
      s2++;
    }

  return (*(const unsigned char *) s1) - (*(const unsigned char *) s2);
}
