/* opennhrp.c - OpenNHRP main routines
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <ctype.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "nhrp_interface.h"
#include "nhrp_common.h"

int read_word(FILE *in, int *lineno, size_t len, char *word)
{
	int ch, i;

	ch = fgetc(in);
	while (isspace(ch)) {
		if (ch == EOF)
			return 0;
		if (ch == '\n')
			(*lineno)++;
		ch = fgetc(in);
	}

	for (i = 0; i < len-1 && !isspace(ch); i++) {
		word[i] = ch;
		ch = fgetc(in);
		if (ch == EOF)
			return 0;
		if (ch == '\n')
			(*lineno)++;
	}
	word[i] = 0;

	return 1;
}

int load_config(const char *config_file)
{
	struct nhrp_interface *iface = NULL;
	char word[256];
	FILE *in;
	int lineno = 1, rc = 0;

	in = fopen(config_file, "r");
	if (in == NULL) {
		nhrp_error("Unable to open configuration file '%s'.", config_file);
		return -1;
	}

	while (read_word(in, &lineno, sizeof(word), word)) {
		if (strcmp(word, "interface") == 0) {
			if (!read_word(in, &lineno, sizeof(word), word)) {
				rc = -2;
				break;
			}

			iface = nhrp_interface_get_by_name(word, TRUE);
		} else if (strcmp(word, "map") == 0) {
			read_word(in, &lineno, sizeof(word), word);
			read_word(in, &lineno, sizeof(word), word);
			read_word(in, &lineno, sizeof(word), word);
		} else if (strcmp(word, "cisco-authentication") == 0) {
			read_word(in, &lineno, sizeof(word), word);
		} else if (strcmp(word, "shortcut") == 0) {
		} else if (strcmp(word, "redirect") == 0) {
		} else if (strcmp(word, "non-caching") == 0) {
		} else {
			rc = -1;
			break;
		}
	}

	if (rc < 0)
		nhrp_error("Config error in %s:%d, near word '%s'",
			   config_file, lineno, word);
	fclose(in);
	return !rc;
}

int main(int argc, char **argv)
{
	if (!log_init())
		return 1;
	if (!load_config("../nhrp.conf"))
		return 2;
	if (!kernel_init())
		return 3;

	nhrp_task_run();

	return 0;
}
