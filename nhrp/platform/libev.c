#include "libev.h"
/* The header declares extern symbols; their definitions need no extern. */
#undef EV_API_DECL
#define EV_API_DECL
#include "../../libev/ev.c"
#include <string.h>
