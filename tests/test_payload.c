#include <assert.h>
#include <stdio.h>

#include "nhrp_packet.h"

static unsigned int frees;

void nhrp_log(int level, const char *format, ...) {
  (void)level;
  (void)format;
  assert(!"unexpected payload error");
}

void __real_free(void *pointer);
void __wrap_free(void *pointer) {
  if (pointer != NULL)
    frees++;
  __real_free(pointer);
}

int main(void) {
  struct nhrp_payload payload = {0};
  struct nhrp_buffer *first, *second;
  struct nhrp_cie *cie;
  unsigned int i;

  /* Probe and authentication replies both replace an existing RAW payload. */
  for (i = 0; i < 100000; i++) {
    unsigned int before = frees;

    first = nhrp_buffer_alloc(55);
    second = nhrp_buffer_alloc(86);
    second->data[0] = 0xa5;
    nhrp_payload_set_raw(&payload, first);
    assert(frees == before);
    nhrp_payload_set_raw(&payload, first);
    assert(frees == before && payload.u.raw == first);
    assert(payload.u.raw->length == 55);
    nhrp_payload_set_raw(&payload, second);
    assert(frees == before + 1);
    assert(payload.payload_type == NHRP_PAYLOAD_TYPE_RAW);
    assert(payload.u.raw == second && payload.u.raw->length == 86);
    assert(payload.u.raw->data[0] == 0xa5);
    nhrp_payload_free(&payload);
    assert(frees == before + 2);
  }

  frees = 0;
  nhrp_payload_set_raw(&payload, nhrp_buffer_alloc(0));
  nhrp_payload_set_raw(&payload, NULL);
  assert(frees == 1 && payload.u.raw == NULL);
  nhrp_payload_set_raw(&payload, NULL);
  nhrp_payload_free(&payload);
  assert(frees == 1);

  nhrp_payload_set_type(&payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
  cie = nhrp_cie_alloc();
  assert(cie != NULL);
  nhrp_payload_add_cie(&payload, cie);
  first = nhrp_buffer_alloc(1);
  nhrp_payload_set_raw(&payload, first);
  assert(frees == 2 && payload.u.raw == first);
  nhrp_payload_set_type(&payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
  assert(frees == 3 && list_empty(&payload.u.cie_list));
  nhrp_payload_free(&payload);

  puts("payload ownership tests passed");
  return 0;
}
