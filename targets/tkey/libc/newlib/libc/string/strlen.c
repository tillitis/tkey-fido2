/*
FUNCTION
	<<strlen>>---character string length

INDEX
	strlen

SYNOPSIS
	#include <string.h>
	size_t strlen(const char *<[str]>);

DESCRIPTION
	The <<strlen>> function works out the length of the string
	starting at <<*<[str]>>> by counting chararacters until it
	reaches a <<NULL>> character.

RETURNS
	<<strlen>> returns the character count.

PORTABILITY
<<strlen>> is ANSI C.

<<strlen>> requires no supporting OS subroutines.

QUICKREF
	strlen ansi pure
*/

#include <string.h>

size_t
strlen (const char *str)
{
  const char *start = str;

  while (*str)
    str++;
  return (size_t)(str - start);
}
