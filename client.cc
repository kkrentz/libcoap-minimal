/* minimal CoAP client
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include "common.hh"

static int have_response = 0;

static const uint8_t master_secret[] = {
  0x0 , 0x1 , 0x2 , 0x3 , 0x4 , 0x5 , 0x6 , 0x7 ,
  0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF
};
static const coap_oscore_ng_keying_material_t keying_material = {
  { sizeof(master_secret), master_secret }, { 0, NULL}
};
static const uint8_t sender_id_bytes[] = { 0xA };
static const coap_bin_const_t sender_id = {
  sizeof(sender_id_bytes) , sender_id_bytes
};
static const uint8_t recipient_id_bytes[] = { 0x00 , 0x02 }; /* replace with something like { 0x53 , 0x29 }; when communicating with OpenMotes */
static const coap_bin_const_t recipient_id = {
  sizeof(recipient_id_bytes) , recipient_id_bytes
};
static const char proxy_scheme[] = "coap";
static const char uri_host[] = "fd00::ff:fe00:2"; /* replace with something like "fd00::ff:fe00:5329" when communicating with OpenMotes */
static const char uri_path[] = "hello";

static const coap_oscore_ng_keying_material_t *
get_keying_material(const coap_bin_const_t *ri)
{
  return coap_binary_equal(ri, &recipient_id) ? &keying_material : NULL;
}

int
main(void) {
  coap_context_t  *ctx = nullptr;
  coap_session_t *session = nullptr;
  coap_address_t dst;
  coap_pdu_t *pdu = nullptr;
  int result = EXIT_FAILURE;;

  coap_startup();

  /* Set logging level */
  coap_set_log_level(LOG_DEBUG);

  /* resolve destination address where server should be sent */
  if (resolve_address("fd00:abcd::2" /* address of CoAP proxy */, "5683", &dst) < 0) {
    coap_log(LOG_CRIT, "failed to resolve address\n");
    goto finish;
  }

  /* create CoAP context and a client session */
  if (!(ctx = coap_new_context(nullptr))) {
    coap_log(LOG_EMERG, "cannot create libcoap context\n");
    goto finish;
  }
  /* Support large responses */
  coap_context_set_block_mode(ctx,
                  COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

  if (!(session = coap_new_client_session(ctx, nullptr, &dst,
                                                  COAP_PROTO_UDP))) {
    coap_log(LOG_EMERG, "cannot create client session\n");
    goto finish;
  }

  /* coap_register_response_handler(ctx, response_handler); */
  coap_register_response_handler(ctx, [](auto, auto,
                                         const coap_pdu_t *received,
                                         auto) {
                                        have_response = 1;
                                        coap_show_pdu(LOG_WARNING, received);
                                        return COAP_RESPONSE_OK;
                                      });
  coap_register_nack_handler(ctx, [](auto, auto, auto, auto) {
                                        have_response = 1;
                                     });

  /* init OSCORE-NG */
  if(!coap_oscore_ng_init(ctx, get_keying_material, &sender_id)) {
    coap_log_err("coap_oscore_ng_init failed\n");
    goto finish;
  }
  if (!coap_oscore_ng_init_client_session(session, &recipient_id, 1)) {
    coap_log_err("coap_oscore_ng_init_client_session failed\n");
    goto finish;
  }

  while (1) {
    pdu = coap_pdu_init(COAP_MESSAGE_CON,
                        COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    coap_add_option(pdu, COAP_OPTION_URI_HOST,
        sizeof(uri_host) - 1,
        (const uint8_t *)uri_host);
    coap_add_option(pdu, COAP_OPTION_URI_PATH,
        sizeof(uri_path) - 1,
        (const uint8_t *)uri_path);
    coap_add_option(pdu, COAP_OPTION_PROXY_SCHEME,
        sizeof(proxy_scheme) - 1,
        (const uint8_t *)proxy_scheme);
    coap_send(session, pdu);

    have_response = 0;
    do {
      coap_io_process(ctx, COAP_IO_NO_WAIT);
    } while (!have_response);
    sleep(5);
  }

  result = EXIT_SUCCESS;
 finish:

  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();

  return result;
}
