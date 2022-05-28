/* minimal CoAP client
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/stat.h>
#include "common.hh"

static const char oscore_conf_file[] = "oscore.conf";
static const char oscore_seq_save_file[] = "sequence-number.conf";
static const char proxy_uri[] = "coap://[fd00::ff:fe00:2]:5683/hello";
static coap_oscore_conf_t *oscore_conf;
static FILE *oscore_seq_num_fp;

static uint8_t *read_file_mem(const char* filename, size_t *length) {
  FILE *f;
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!filename || !(f = fopen(filename, "r")))
    return NULL;

  if (fstat(fileno(f), &statbuf) == -1) {
    fclose(f);
    return NULL;
  }

  buf = (uint8_t *)coap_malloc(statbuf.st_size+1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
    fclose(f);
    coap_free(buf);
    return NULL;
  }
  buf[statbuf.st_size] = '\000';
  *length = (size_t)(statbuf.st_size + 1);
  fclose(f);
  return buf;
}

static int
oscore_save_seq_num(uint64_t sender_seq_num, void *param COAP_UNUSED) {
  if (oscore_seq_num_fp) {
    rewind(oscore_seq_num_fp);
    fprintf(oscore_seq_num_fp, "%ju\n", sender_seq_num);
    fflush(oscore_seq_num_fp);
  }
  return 1;
}

static coap_oscore_conf_t *
get_oscore_conf(void) {
  uint8_t *buf;
  size_t length;
  coap_str_const_t file_mem;
  uint64_t start_seq_num = 0;

  buf = read_file_mem(oscore_conf_file, &length);
  if (buf == NULL) {
    fprintf(stderr, "OSCORE configuraton file error: %s\n", oscore_conf_file);
    return NULL;
  }
  file_mem.s = buf;
  file_mem.length = length;
  if (oscore_seq_save_file) {
    oscore_seq_num_fp = fopen(oscore_seq_save_file, "r+");
    if (oscore_seq_num_fp == NULL) {
      /* Try creating it */
      oscore_seq_num_fp = fopen(oscore_seq_save_file, "w+");
      if (oscore_seq_num_fp == NULL) {
        fprintf(stderr, "OSCORE save restart info file error: %s\n",
                oscore_seq_save_file);
        return NULL;
      }
    }
    if (fscanf(oscore_seq_num_fp, "%ju", &start_seq_num) == 0) {
      /* Must be empty */
      start_seq_num = 0;
    }
  }
  oscore_conf = coap_new_oscore_conf(file_mem,
                                     oscore_save_seq_num,
                                     NULL, start_seq_num);
  coap_free(buf);
  if (oscore_conf == NULL) {
    fprintf(stderr, "OSCORE configuraton file error: %s\n", oscore_conf_file);
    return NULL;
  }
  return oscore_conf;
}

int
main(void) {
  coap_context_t  *ctx = nullptr;
  coap_session_t *session = nullptr;
  coap_address_t dst;
  coap_pdu_t *pdu = nullptr;
  int result = EXIT_FAILURE;;

  coap_startup();

  if(!coap_oscore_is_supported()) {
    coap_log(LOG_CRIT, "OSCORE is not supported\n");
    goto finish;
  } else {
    coap_log(LOG_INFO, "OSCORE is supported\n");
  }
  if (!get_oscore_conf()) {
    coap_log(LOG_EMERG, "get_oscore_conf failed\n");
    goto finish;
  }

  /* resolve destination address where server should be sent */
  if (resolve_address("fd00:abcd::2" /* address of CoAP proxy */, "5683", &dst) < 0) {
    coap_log(LOG_CRIT, "failed to resolve address\n");
    goto finish;
  }

  /* create CoAP context and a client session */
  ctx = coap_new_context(nullptr);

  if (!ctx || !(session = coap_new_client_session_oscore(ctx, nullptr, &dst,
                                                  COAP_PROTO_UDP, oscore_conf))) {
    coap_log(LOG_EMERG, "cannot create client session\n");
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

  /* add a Proxy-URI option */
  coap_add_option(pdu, COAP_OPTION_PROXY_URI,
      sizeof(proxy_uri) - 1, (const uint8_t *)proxy_uri);

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
