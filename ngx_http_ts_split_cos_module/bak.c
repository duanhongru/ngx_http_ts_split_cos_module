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
    u_char *media_mem_start;
    u_char *media_mem_end;
    ngx_http_status_t status;
} ngx_http_ts_split_cos_ctx_t;


static void ngx_http_ts_split_cos_rpartition(const ngx_str_t *src, ngx_str_t *first,
        ngx_str_t *second, u_char delim);
static ngx_str_t ngx_http_ts_split_cos_get_media_name(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_cos_get_media_seq(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_cos_index_info(ngx_http_request_t *r,
        const u_char *index_start, const u_char *index_end);
static ngx_int_t ngx_ts_split_cos_subrequest_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc);
static void ngx_ts_split_cos_post_handler(ngx_http_request_t *r);

static char *ngx_http_ts_split_cos(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static ngx_int_t ngx_http_ts_split_cos_handler(ngx_http_request_t *r);
static void ngx_ts_split_cos_second_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_ts_split_cos_second_subrequest_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc);


static ngx_str_t  ngx_http_ts_split_cos_media_begin =
        ngx_string("ts_split_cos_media_begin");
static ngx_str_t  ngx_http_ts_split_cos_media_end =
        ngx_string("ts_split_cos_media_end");




static ngx_command_t  ngx_http_ts_split_cos_commands[] = {

    { ngx_string("ts_split_cos"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_http_ts_split_cos,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

ngx_http_module_t  ngx_http_ts_split_cos_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
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

static char *
ngx_http_ts_split_cos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_ts_split_cos_handler;

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
        req_ctx = ngx_palloc(r->pool, sizeof(ngx_http_ts_split_cos_ctx_t));
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
ngx_ts_split_cos_second_post_handler(ngx_http_request_t *r)
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

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return;
    }

    b->pos = req_ctx->media_mem_start;
    b->last = req_ctx->media_mem_end;
    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    ngx_str_t type = ngx_string("video/mp2t");
    r->headers_out.content_type = type;
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;

    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);

    ngx_http_finalize_request(r, ret);
}

static ngx_int_t
ngx_ts_split_cos_second_subrequest_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc)
{
    ngx_http_request_t *pr = r->parent;
    ngx_http_ts_split_cos_ctx_t *req_ctx =
            ngx_http_get_module_ctx(pr, ngx_http_ts_split_cos_module);
    pr->headers_out.status = r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT ?
            NGX_HTTP_OK : r->headers_out.status;
    if (r->headers_out.status == NGX_HTTP_OK) {
        ngx_buf_t *recv_buf = &r->upstream->buffer;
        u_char *media_start = (u_char *)ngx_strstr((char *)recv_buf->start,
                "\r\n\r\n");
        if (media_start == NULL) {
            return NGX_ERROR;

        } else {
            media_start = media_start + sizeof("\r\n\r\n") - 1;
        }
        u_char *media_end = recv_buf->last;

        req_ctx->media_mem_start = media_start;
        req_ctx->media_mem_end = media_end;
    }

    pr->write_event_handler = ngx_ts_split_cos_second_post_handler;

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

    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool,
            sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return;
    }
    psr->handler = ngx_ts_split_cos_second_subrequest_post_handler;
    psr->data = req_ctx;

    ngx_http_request_t *sr;
    ngx_int_t rc = ngx_http_subrequest(r, &(req_ctx->media_url), NULL, &sr,
            psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return;
    }

    return;
}
