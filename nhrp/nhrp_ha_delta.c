/* nhrp_ha_delta.c - Registration snapshot delta codec */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "nhrp_ha_control.h"
#include "nhrp_ha_delta.h"
#include "nhrp_ha_hub.h"

struct delta_line {
  char *text;
  char key[96];
};

static void lines_free(struct delta_line *lines, size_t count) {
  size_t i;

  for (i = 0; i < count; i++)
    free(lines[i].text);
  free(lines);
}

static int line_key(const char *line, char key[96]) {
  char protocol[64];
  unsigned int prefix;
  int length;

  if (sscanf(line, "entry %63s %u", protocol, &prefix) != 2 || prefix > 32)
    return 0;
  length = snprintf(key, 96, "%s/%u", protocol, prefix);
  return length > 0 && length < 96;
}

static int line_compare(const void *left, const void *right) {
  const struct delta_line *a = left;
  const struct delta_line *b = right;

  return strcmp(a->key, b->key);
}

static int snapshot_parse(const uint8_t *snapshot, size_t length,
                          struct delta_line **output, size_t *count) {
  struct delta_line *lines;
  char *copy;
  char *line;
  char *save = NULL;
  size_t used = 0;
  size_t i;

  *output = NULL;
  *count = 0;
  if (length > NHRP_HA_CONTROL_MAX_FRAME || (length != 0 && snapshot == NULL))
    return 0;
  copy = malloc(length + 1);
  lines = calloc(NHRP_HA_HUB_MAX_REGISTRATIONS, sizeof(*lines));
  if (copy == NULL || lines == NULL) {
    free(copy);
    free(lines);
    return 0;
  }
  memcpy(copy, snapshot, length);
  copy[length] = 0;
  for (line = strtok_r(copy, "\n", &save); line != NULL;
       line = strtok_r(NULL, "\n", &save)) {
    if (used >= NHRP_HA_HUB_MAX_REGISTRATIONS || strlen(line) >= 256 ||
        !line_key(line, lines[used].key))
      goto failed;
    lines[used].text = strdup(line);
    if (lines[used].text == NULL)
      goto failed;
    used++;
  }
  qsort(lines, used, sizeof(*lines), line_compare);
  for (i = 1; i < used; i++)
    if (strcmp(lines[i - 1].key, lines[i].key) == 0)
      goto failed;
  free(copy);
  *output = lines;
  *count = used;
  return 1;

failed:
  free(copy);
  lines_free(lines, used);
  return 0;
}

static int append(uint8_t **buffer, size_t *used, size_t *allocated,
                  const char *prefix, const char *line) {
  size_t prefix_length = strlen(prefix);
  size_t line_length = strlen(line);
  size_t wanted = *used + prefix_length + line_length + 1;

  if (wanted > NHRP_HA_CONTROL_MAX_FRAME)
    return 0;
  if (wanted + 1 > *allocated) {
    uint8_t *larger;
    size_t next = *allocated == 0 ? 4096 : *allocated;

    while (next < wanted + 1)
      next *= 2;
    larger = realloc(*buffer, next);
    if (larger == NULL)
      return 0;
    *buffer = larger;
    *allocated = next;
  }
  memcpy(*buffer + *used, prefix, prefix_length);
  *used += prefix_length;
  memcpy(*buffer + *used, line, line_length);
  *used += line_length;
  (*buffer)[(*used)++] = '\n';
  (*buffer)[*used] = 0;
  return 1;
}

int nhrp_ha_delta_build(const uint8_t *old_snapshot, size_t old_length,
                        const uint8_t *new_snapshot, size_t new_length,
                        uint8_t **delta, size_t *delta_length) {
  struct delta_line *old_lines = NULL;
  struct delta_line *new_lines = NULL;
  size_t old_count = 0;
  size_t new_count = 0;
  size_t old_index = 0;
  size_t new_index = 0;
  size_t allocated = 0;
  size_t used = 0;
  uint8_t *result = NULL;
  int ok = 0;

  *delta = NULL;
  *delta_length = 0;
  if (!snapshot_parse(old_snapshot, old_length, &old_lines, &old_count) ||
      !snapshot_parse(new_snapshot, new_length, &new_lines, &new_count))
    goto done;
  while (old_index < old_count || new_index < new_count) {
    int comparison =
        old_index == old_count ? 1
        : new_index == new_count
            ? -1
            : strcmp(old_lines[old_index].key, new_lines[new_index].key);

    if (comparison == 0) {
      if (strcmp(old_lines[old_index].text, new_lines[new_index].text) != 0 &&
          !append(&result, &used, &allocated, "+", new_lines[new_index].text))
        goto done;
      old_index++;
      new_index++;
    } else if (comparison < 0) {
      if (!append(&result, &used, &allocated, "-", old_lines[old_index].key))
        goto done;
      old_index++;
    } else {
      if (!append(&result, &used, &allocated, "+", new_lines[new_index].text))
        goto done;
      new_index++;
    }
  }
  if (result == NULL) {
    result = calloc(1, 1);
    if (result == NULL)
      goto done;
  }
  *delta = result;
  *delta_length = used;
  result = NULL;
  ok = 1;

done:
  free(result);
  lines_free(old_lines, old_count);
  lines_free(new_lines, new_count);
  return ok;
}

static ssize_t line_find(struct delta_line *lines, size_t count,
                         const char *key) {
  size_t i;

  for (i = 0; i < count; i++)
    if (strcmp(lines[i].key, key) == 0)
      return i;
  return -1;
}

int nhrp_ha_delta_apply(const uint8_t *old_snapshot, size_t old_length,
                        const uint8_t *delta, size_t delta_length,
                        uint8_t **new_snapshot, size_t *new_length) {
  struct delta_line *lines = NULL;
  size_t count = 0;
  char *copy = NULL;
  char *operation;
  char *save = NULL;
  uint8_t *result = NULL;
  size_t used = 0;
  size_t allocated = 0;
  size_t i;
  int ok = 0;

  *new_snapshot = NULL;
  *new_length = 0;
  if (!snapshot_parse(old_snapshot, old_length, &lines, &count) ||
      delta_length > NHRP_HA_CONTROL_MAX_FRAME ||
      (delta_length != 0 && delta == NULL))
    goto done;
  copy = malloc(delta_length + 1);
  if (copy == NULL)
    goto done;
  memcpy(copy, delta, delta_length);
  copy[delta_length] = 0;
  for (operation = strtok_r(copy, "\n", &save); operation != NULL;
       operation = strtok_r(NULL, "\n", &save)) {
    char key[96];
    ssize_t found;

    if (operation[0] == '+') {
      char *replacement;

      if (!line_key(operation + 1, key))
        goto done;
      found = line_find(lines, count, key);
      if (found < 0 && count >= NHRP_HA_HUB_MAX_REGISTRATIONS)
        goto done;
      replacement = strdup(operation + 1);
      if (replacement == NULL)
        goto done;
      if (found >= 0) {
        free(lines[found].text);
        lines[found].text = replacement;
      } else {
        lines[count].text = replacement;
        snprintf(lines[count].key, sizeof(lines[count].key), "%s", key);
        count++;
      }
    } else if (operation[0] == '-') {
      found = line_find(lines, count, operation + 1);
      if (found < 0)
        goto done;
      free(lines[found].text);
      memmove(&lines[found], &lines[found + 1],
              (count - (size_t)found - 1) * sizeof(*lines));
      count--;
      memset(&lines[count], 0, sizeof(*lines));
    } else {
      goto done;
    }
  }
  qsort(lines, count, sizeof(*lines), line_compare);
  for (i = 0; i < count; i++)
    if (!append(&result, &used, &allocated, "", lines[i].text))
      goto done;
  if (result == NULL) {
    result = calloc(1, 1);
    if (result == NULL)
      goto done;
  }
  *new_snapshot = result;
  *new_length = used;
  result = NULL;
  ok = 1;

done:
  free(copy);
  free(result);
  lines_free(lines, count);
  return ok;
}
