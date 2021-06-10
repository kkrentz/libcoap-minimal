/* minimal CoAP client
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <coap3/oscore.h>
#include "common.hh"

static const oscore_keying_material_t oscore_keying_material = {
  0 , 0 , { 0x0 , 0x1 , 0x2 , 0x3 , 0x4 , 0x5 , 0x6 , 0x7 ,  0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF }
};
static const uint8_t sender_id[] = { 0xA };
static const uint8_t recipient_id[] = { 0x00 , 0x02 };
static const char proxy_scheme[] = "coap";
static const char uri_host[] = "fd00::ff:fe00:2";
static const char uri_path[] = "hello";

int
main(void) {
  coap_context_t  *ctx = nullptr;
  coap_session_t *session = nullptr;
  coap_address_t dst;
  coap_pdu_t *pdu = nullptr;
  int result = EXIT_FAILURE;;

  coap_startup();
  coap_set_log_level(LOG_DEBUG);

  /* resolve destination address where server should be sent */
  if (resolve_address("fd00:abcd::2" /* address of CoAP proxy */, "5683", &dst) < 0) {
    coap_log(LOG_CRIT, "failed to resolve address\n");
    goto finish;
  }

  /* create CoAP context and a client session */
  ctx = coap_new_context(nullptr);

  if (!ctx || !(session = coap_new_client_session(ctx, nullptr, &dst,
                                                  COAP_PROTO_UDP))) {
    coap_log(LOG_EMERG, "cannot create client session\n");
    goto finish;
  }

  if (!coap_oscore_init_client_session(session,
      &oscore_keying_material,
      sender_id, sizeof(sender_id),
      recipient_id, sizeof(recipient_id))) {
    coap_log(LOG_EMERG, "cannot initialize OSCORE session\n");
    goto finish;
  }

  /* coap_register_response_handler(ctx, response_handler); */
  coap_register_response_handler(ctx, [](auto, auto,
                                         const coap_pdu_t *received,
                                         auto) {
                                        coap_show_pdu(LOG_WARNING, received);
                                        return COAP_RESPONSE_OK;
                                      });
  /* construct CoAP message */
  pdu = coap_pdu_init(COAP_MESSAGE_CON,
                      COAP_REQUEST_CODE_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (!pdu) {
    coap_log( LOG_EMERG, "cannot create PDU\n" );
    goto finish;
  }

  /* add a Uri-Path and a Proxy-URI option */
  coap_add_option(pdu, COAP_OPTION_PROXY_SCHEME,
      sizeof(proxy_scheme) - 1,
      (const uint8_t *)proxy_scheme);
  coap_add_option(pdu, COAP_OPTION_URI_HOST,
      sizeof(uri_host) - 1,
      (const uint8_t *)uri_host);
  coap_add_option(pdu, COAP_OPTION_URI_PATH,
      sizeof(uri_path) - 1,
      (const uint8_t *)uri_path);

  coap_show_pdu(LOG_WARNING, pdu);
  /* and send the PDU */
  coap_send(session, pdu);

  coap_io_process(ctx, COAP_IO_WAIT);

  result = EXIT_SUCCESS;
 finish:

  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();

  return result;
}
