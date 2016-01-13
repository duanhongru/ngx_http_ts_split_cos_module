#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_uint_t media_begin;
    ngx_uint_t media_len;
} ngx_http_ts_split_media_index_t;


typedef struct {
    ngx_flag_t media_index_result;
    ngx_int_t media_seq;
    ngx_uint_t media_begin;
    ngx_uint_t media_len;
    ngx_str_t media_url;
    ngx_http_status_t status;
} ngx_http_ts_split_cos_ctx_t;

typedef struct {
    ngx_flag_t                     enable;
    ngx_http_upstream_conf_t       upstream;
    ngx_str_t                      cos_addr;
} ngx_http_ts_split_cos_loc_conf_t;

static ngx_str_t  ngx_http_ts_split_cos_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static void *ngx_http_ts_split_cos_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ts_split_cos_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static void ngx_http_ts_split_cos_rpartition(const ngx_str_t *src, ngx_str_t *first,
        ngx_str_t *second, u_char delim);
static ngx_str_t ngx_http_ts_split_cos_get_media_name(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_cos_get_media_seq(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_cos_index_info(ngx_http_request_t *r,
        const u_char *index_start, const u_char *index_end);
static ngx_int_t ngx_ts_split_cos_subrequest_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc);
static void ngx_ts_split_cos_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_ts_split_cos_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_ts_split_cos_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_ts_split_cos_process_header(ngx_http_request_t *r);
static void ngx_ts_split_cos_upstream_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc);
static char *ngx_http_ts_split_cos_pass(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static ngx_int_t ngx_http_ts_split_cos_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ts_split_cos_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_ts_split_cos_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_subrange_rm_header(ngx_list_t *headers, ngx_str_t key);


static ngx_command_t  ngx_http_ts_split_cos_commands[] = {
    { ngx_string("ts_split_cos"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_split_cos_loc_conf_t, enable),
      NULL },

    { ngx_string("ts_split_cos_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_ts_split_cos_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

ngx_http_module_t  ngx_http_ts_split_cos_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ts_split_cos_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ts_split_cos_create_loc_conf, /* create location configuration */
    ngx_http_ts_split_cos_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_ts_split_cos_module = {
    NGX_MODULE_V1,
    &ngx_http_ts_split_cos_module_ctx,     /* module context */
    ngx_http_ts_split_cos_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_ts_split_cos_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ts_split_cos_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ts_split_cos_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->upstream.connect_timeout = 60000;
    conf->upstream.send_timeout = 60000;
    conf->upstream.read_timeout = 60000;
    conf->upstream.store_access = 0600;
    conf->upstream.buffering = 0;
    conf->upstream.bufs.num = 8;
    conf->upstream.bufs.size = ngx_pagesize;
    conf->upstream.buffer_size = ngx_pagesize;
    conf->upstream.busy_buffers_size = 2*ngx_pagesize;
    conf->upstream.temp_file_write_size = 2*ngx_pagesize;
    conf->upstream.max_temp_file_size = 1024*1024*1024;
    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_ts_split_cos_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_split_cos_loc_conf_t *prev = parent;
    ngx_http_ts_split_cos_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->cos_addr, prev->cos_addr, "");
    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream,
            ngx_http_ts_split_cos_hide_headers, &hash) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ts_split_cos_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_ts_split_cos_handler;

    ngx_http_ts_split_cos_loc_conf_t *tscf = conf;
    ngx_str_t *value = cf->args->elts;
    tscf->cos_addr = value[1];

    return NGX_CONF_OK;
}

static void
ngx_http_ts_split_cos_rpartition(const ngx_str_t *src, ngx_str_t *first,
        ngx_str_t *second, u_char delim)
{
    u_char  *p;

    for (p = src->data + src->len; p >= src->data; p--) {
        if (*p == delim) {
            first->data = src->data;
            first->len = p - first->data;
            second->data = p + 1;
            second->len = src->len - first->len - 1;
            break;

        }
    }
}

static ngx_str_t
ngx_http_ts_split_cos_get_media_name(const ngx_str_t *src)
{
    u_char *p;
    ngx_uint_t count;
    ngx_str_t media;

    count = 0;
    for (p = src->data + src->len; p != src->data; p--) {
        if (*p == '.') {
            count++;
        }

        if (count == 3) {
            break;
        }
    }

    media.data = src->data;
    media.len = p - src->data;

    return media;
}

static ngx_int_t
ngx_http_ts_split_cos_get_media_seq(const ngx_str_t *src)
{
    u_char *p, *begin, *end;
    ngx_uint_t count;
    ngx_str_t media_seq;

    ngx_str_null(&media_seq);
    count = 0;
    begin = NULL;
    end = NULL;
    for (p = src->data + src->len; p != src->data; p--) {
        if (*p == '.') {
            count++;
        }

        if (count == 2 && end == NULL) {
            end = p;
        }

        if (count == 3 && begin == NULL) {
            begin = p + 1;
        }

        if (begin != NULL && end != NULL) {
            break;
        }
    }


    if (begin != NULL && end != NULL) {
        media_seq.data = begin;
        media_seq.len = end - begin;

        return ngx_atoi(media_seq.data, media_seq.len);
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_ts_split_cos_index_info(ngx_http_request_t *r,
        const u_char *index_start, const u_char *index_end)
{
    ngx_http_ts_split_cos_ctx_t *req_ctx =
            ngx_http_get_module_ctx(r, ngx_http_ts_split_cos_module);

    if (index_start + req_ctx->media_seq/10 +
            sizeof(ngx_http_ts_split_media_index_t) > index_end) {
        return NGX_ERROR;
    }
    ngx_http_ts_split_media_index_t *media_index =
            (ngx_http_ts_split_media_index_t *)index_start + req_ctx->media_seq/10;
    req_ctx->media_begin = media_index->media_begin;
    req_ctx->media_len = media_index->media_len;

    return NGX_OK;

}

static ngx_int_t
ngx_http_ts_split_cos_handler(ngx_http_request_t *r)
{
    ngx_str_t                  index_url, media_url;
    ngx_str_t                  first, second, media_name;
    ngx_int_t                  rc, media_seq;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
          return NGX_HTTP_NOT_ALLOWED;
      }

    if (r->uri.data[r->uri.len - 1] == '/') {
      return NGX_DECLINED;
    }

    ngx_str_t range_key = ngx_string("Range");
    ngx_http_subrange_rm_header(&r->headers_in.headers, range_key);

    ngx_str_null(&media_name);
    ngx_str_null(&second);

    ngx_http_ts_split_cos_rpartition(&r->uri, &first, &second, '/');

    index_url.len = first.len + sizeof("index.m3u8");
    index_url.data = ngx_palloc(r->pool, index_url.len);

    ngx_snprintf(index_url.data, index_url.len, "%V/index.m3u8", &first);

    media_name = ngx_http_ts_split_cos_get_media_name(&second);
    media_url.len = first.len + 4 + media_name.len;
    media_url.data = ngx_palloc(r->pool, media_url.len);

    ngx_snprintf(media_url.data, media_url.len, "%V/%V.ts", &first, &media_name);

    media_seq = ngx_http_ts_split_cos_get_media_seq(&second);

    ngx_http_ts_split_cos_ctx_t *req_ctx =
            ngx_http_get_module_ctx(r, ngx_http_ts_split_cos_module);
    if (req_ctx == NULL) {
        req_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ts_split_cos_ctx_t));
        if (req_ctx == NULL) {
            return NGX_ERROR;
        }
    }
    ngx_http_set_ctx(r, req_ctx, ngx_http_ts_split_cos_module);
    req_ctx->media_seq = media_seq;
    req_ctx->media_url = media_url;

    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool,
            sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    psr->handler = ngx_ts_split_cos_subrequest_post_handler;
    psr->data = req_ctx;

    ngx_http_request_t *sr;
    rc = ngx_http_subrequest(r, &index_url, NULL, &sr,
            psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}

static ngx_int_t
ngx_ts_split_cos_subrequest_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc)
{
    ngx_http_request_t *pr = r->parent;
    ngx_http_ts_split_cos_ctx_t *req_ctx =
            ngx_http_get_module_ctx(pr, ngx_http_ts_split_cos_module);
    pr->headers_out.status = r->headers_out.status;
    if (r->headers_out.status == NGX_HTTP_OK) {
        ngx_buf_t *recv_buf = &r->upstream->buffer;
        u_char *index_start = (u_char *)ngx_strstr((char *)recv_buf->start,
                "\r\n\r\n");
        if (index_start == NULL) {
            return NGX_ERROR;

        } else {
            index_start = index_start + sizeof("\r\n\r\n") - 1;
        }
        u_char *index_end = recv_buf->last;

        if (ngx_http_ts_split_cos_index_info(pr, index_start, index_end) ==
                NGX_ERROR) {
            req_ctx->media_index_result = 0;

        } else {
            req_ctx->media_index_result = 1;

        }
    }

    pr->write_event_handler = ngx_ts_split_cos_post_handler;

    return NGX_OK;

}

static void
ngx_ts_split_cos_post_handler(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK) {
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }

    ngx_http_ts_split_cos_ctx_t *req_ctx = ngx_http_get_module_ctx(r,
            ngx_http_ts_split_cos_module);
    if (!req_ctx->media_index_result) {
        return;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
         return;
    }

    ngx_http_ts_split_cos_loc_conf_t * tscf = ngx_http_get_module_loc_conf(r,
            ngx_http_ts_split_cos_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &tscf->upstream;
    u->buffering = tscf->upstream.buffering;
    u->resolved = (ngx_http_upstream_resolved_t *)ngx_pcalloc(r->pool,
            sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_pcalloc resolved error .%s.", strerror(errno));
        return;
    }

    struct sockaddr_in *backend_addr = ngx_pcalloc(r->pool,
            sizeof(struct sockaddr_in));

    ngx_str_t addr, port;
    ngx_str_null(&addr);
    ngx_str_null(&port);
    ngx_http_ts_split_cos_rpartition(&tscf->cos_addr, &addr, &port, ':');
    backend_addr->sin_port = htons((uint16_t)ngx_atoi(port.data, port.len));
    backend_addr->sin_addr.s_addr = ngx_inet_addr(addr.data, addr.len);
    backend_addr->sin_family = AF_INET;

    u->resolved->sockaddr = (struct sockaddr *)backend_addr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;
    u->create_request = ngx_ts_split_cos_upstream_create_request;
    u->process_header = ngx_ts_split_cos_process_status_line;
    u->finalize_request = ngx_ts_split_cos_upstream_finalize_request;

    r->main->count++;
    ngx_http_upstream_init(r);

    return;
}

static ngx_int_t
ngx_ts_split_cos_upstream_create_request(ngx_http_request_t *r)
{
    ngx_http_ts_split_cos_ctx_t *req_ctx = ngx_http_get_module_ctx(r,
            ngx_http_ts_split_cos_module);

    static ngx_str_t cos_query_line =
            ngx_string("GET %V HTTP/1.1\r\nHOST: %V\r\nRange: bytes=%ul-%ul\r\n\r\n");
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024);
    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_http_ts_split_cos_loc_conf_t * tscf = ngx_http_get_module_loc_conf(r,
            ngx_http_ts_split_cos_module);
    b->last = ngx_snprintf(b->last, 1024, (char *)cos_query_line.data,
            &req_ctx->media_url, &tscf->cos_addr, req_ctx->media_begin,
            (req_ctx->media_begin + req_ctx->media_len));
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }
    r->upstream->request_bufs->buf=b;
    r->upstream->request_bufs->next=NULL;
    r->upstream->request_sent=0;
    r->upstream->header_sent=0;
    r->header_hash=1;

    return NGX_OK;
}

static ngx_int_t
ngx_ts_split_cos_process_status_line(ngx_http_request_t *r)
{
    size_t                 len;
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;

    ngx_http_ts_split_cos_ctx_t *ctx = ngx_http_get_module_ctx(r,
            ngx_http_ts_split_cos_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NGX_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;


    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < NGX_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = ngx_ts_split_cos_process_header;

    return ngx_ts_split_cos_process_header(r);
}


static ngx_int_t
ngx_ts_split_cos_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void
ngx_ts_split_cos_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_ts_split_cos_upstream_finalize_request");
}



static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_subrange_rm_header(ngx_list_t *headers, ngx_str_t key)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i,j;

    part = &headers->part;
    h = part->elts;
    for(i = 0;/* void */; ++i){
        if(i >= part->nelts){
            if(part->next == NULL){
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if(ngx_strncasecmp(key.data, h[i].lowcase_key, h[i].key.len) == 0){
            if(part->nelts == 1){ //just skip if we have one header in the part
                part->nelts = 0;
                break;
            }
            j = i + 1;
            while(j <= part->nelts){
                h[i++] = h[j++];
            }
            part->nelts -= 1;
            break;
        }
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_ts_split_cos_header_filter(ngx_http_request_t *r)
{

    ngx_http_ts_split_cos_loc_conf_t * tscf = ngx_http_get_module_loc_conf(r,
            ngx_http_ts_split_cos_module);
    if (!tscf->enable) {
        return ngx_http_next_header_filter(r);
    }
    ngx_str_t content_range_key = ngx_string("Content-Range");
    ngx_str_t range_key = ngx_string("Range");
    ngx_str_t status_line = ngx_string("200 OK");


    r->headers_out.status = NGX_HTTP_OK; //Change 206 to 200
    r->headers_out.status_line = status_line;
    r->headers_out.content_range = NULL;
    r->headers_in.range = NULL;
    ngx_http_subrange_rm_header(&r->headers_in.headers, range_key);
    ngx_http_subrange_rm_header(&r->headers_out.headers, content_range_key);

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_ts_split_cos_init(ngx_conf_t *cf)
{

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ts_split_cos_header_filter;

    return NGX_OK;
}
