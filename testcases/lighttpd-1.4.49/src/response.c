#include "first.h"

#include "response.h"
#include "fdevent.h"
#include "keyvalue.h"
#include "log.h"
#include "stat_cache.h"
#include "chunk.h"

#include "configfile.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int http_response_write_header(server *srv, connection *con) {
	buffer *b;
	size_t i;
	int have_date = 0;
	int have_server = 0;

	b = buffer_init();

	if (con->request.http_version == HTTP_VERSION_1_1) {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
	} else {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.0 "));
	}
	buffer_append_int(b, con->http_status);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	buffer_append_string(b, get_http_status_name(con->http_status));

	/* disable keep-alive if requested */
	if (con->request_count > con->conf.max_keep_alive_requests || 0 == con->conf.max_keep_alive_idle) {
		con->keep_alive = 0;
	} else {
		con->keep_alive_idle = con->conf.max_keep_alive_idle;
	}

	if ((con->parsed_response & HTTP_UPGRADE) && con->request.http_version == HTTP_VERSION_1_1) {
		response_header_overwrite(srv, con, CONST_STR_LEN("Connection"), CONST_STR_LEN("upgrade"));
	} else if (0 == con->keep_alive) {
		response_header_overwrite(srv, con, CONST_STR_LEN("Connection"), CONST_STR_LEN("close"));
	} else if (con->request.http_version == HTTP_VERSION_1_0) {/*(&& con->keep_alive != 0)*/
		response_header_overwrite(srv, con, CONST_STR_LEN("Connection"), CONST_STR_LEN("keep-alive"));
	}

	/* add all headers */
	for (i = 0; i < con->response.headers->used; i++) {
		data_string *ds;

		ds = (data_string *)con->response.headers->data[i];

		if (buffer_string_is_empty(ds->value) || buffer_string_is_empty(ds->key)) continue;
		if (0 == strncasecmp(ds->key->ptr, CONST_STR_LEN("X-Sendfile"))) continue;
		if (0 == strncasecmp(ds->key->ptr, CONST_STR_LEN("X-LIGHTTPD-"))) {
			if (0 == strncasecmp(ds->key->ptr+sizeof("X-LIGHTTPD-")-1, CONST_STR_LEN("KBytes-per-second"))) {
				/* "X-LIGHTTPD-KBytes-per-second" */
				long limit = strtol(ds->value->ptr, NULL, 10);
				if (limit > 0
				    && (limit < con->conf.kbytes_per_second
				        || 0 == con->conf.kbytes_per_second)) {
					if (limit > USHRT_MAX) limit= USHRT_MAX;
					con->conf.kbytes_per_second = limit;
				}
			}
			continue;
		} else {
			if (0 == strcasecmp(ds->key->ptr, "Date")) have_date = 1;
			if (0 == strcasecmp(ds->key->ptr, "Server")) have_server = 1;
			if (0 == strcasecmp(ds->key->ptr, "Content-Encoding") && 304 == con->http_status) continue;

			buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
			buffer_append_string_buffer(b, ds->key);
			buffer_append_string_len(b, CONST_STR_LEN(": "));
#if 0
			/** 
			 * the value might contain newlines, encode them with at least one white-space
			 */
			buffer_append_string_encoded(b, CONST_BUF_LEN(ds->value), ENCODING_HTTP_HEADER);
#else
			buffer_append_string_buffer(b, ds->value);
#endif
		}
	}

	if (!have_date) {
		/* HTTP/1.1 requires a Date: header */
		buffer_append_string_len(b, CONST_STR_LEN("\r\nDate: "));

		/* cache the generated timestamp */
		if (srv->cur_ts != srv->last_generated_date_ts) {
			buffer_string_prepare_copy(srv->ts_date_str, 255);

			buffer_append_strftime(srv->ts_date_str, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(srv->cur_ts)));

			srv->last_generated_date_ts = srv->cur_ts;
		}

		buffer_append_string_buffer(b, srv->ts_date_str);
	}

	if (!have_server) {
		if (!buffer_string_is_empty(con->conf.server_tag)) {
			buffer_append_string_len(b, CONST_STR_LEN("\r\nServer: "));
			buffer_append_string_encoded(b, CONST_BUF_LEN(con->conf.server_tag), ENCODING_HTTP_HEADER);
		}
	}

	buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

	con->bytes_header = buffer_string_length(b);

	if (con->conf.log_response_header) {
		log_error_write(srv, __FILE__, __LINE__, "sSb", "Response-Header:", "\n", b);
	}

	chunkqueue_prepend_buffer(con->write_queue, b);
	buffer_free(b);

	return 0;
}

static handler_t http_response_physical_path_check(server *srv, connection *con) {
	stat_cache_entry *sce = NULL;

	if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		/* file exists */
	} else {
		char *pathinfo = NULL;
		switch (errno) {
		case EACCES:
			con->http_status = 403;

			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			}

			buffer_reset(con->physical.path);
			return HANDLER_FINISHED;
		case ENAMETOOLONG:
			/* file name to be read was too long. return 404 */
		case ENOENT:
			con->http_status = 404;

			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- file not found");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			}

			buffer_reset(con->physical.path);
			return HANDLER_FINISHED;
		case ENOTDIR:
			/* PATH_INFO ! :) */
			break;
		default:
			/* we have no idea what happend. let's tell the user so. */
			con->http_status = 500;
			buffer_reset(con->physical.path);

			log_error_write(srv, __FILE__, __LINE__, "ssbsb",
					"file not found ... or so: ", strerror(errno),
					con->uri.path,
					"->", con->physical.path);

			return HANDLER_FINISHED;
		}

		/* not found, perhaps PATHINFO */

		{
			/*(might check at startup that s->document_root does not end in '/')*/
			size_t len = buffer_string_length(con->physical.basedir);
			if (len > 0 && '/' == con->physical.basedir->ptr[len-1]) --len;
			pathinfo = con->physical.path->ptr + len;
			if ('/' != *pathinfo) pathinfo = NULL;
		}

		for (char *pprev = pathinfo; pathinfo; pprev = pathinfo, pathinfo = strchr(pathinfo+1, '/')) {
			stat_cache_entry *nsce = NULL;
			buffer_copy_string_len(srv->tmp_buf, con->physical.path->ptr, pathinfo - con->physical.path->ptr);
			if (HANDLER_ERROR == stat_cache_get_entry(srv, con, srv->tmp_buf, &nsce)) {
				pathinfo = pathinfo != pprev ? pprev : NULL;
				break;
			}
			sce = nsce;
			if (!S_ISDIR(sce->st.st_mode)) break;
		}

		if (NULL == pathinfo || !S_ISREG(sce->st.st_mode)) {
			/* no it really doesn't exists */
			con->http_status = 404;

			if (con->conf.log_file_not_found) {
				log_error_write(srv, __FILE__, __LINE__, "sbsb",
						"file not found:", con->uri.path,
						"->", con->physical.path);
			}

			buffer_reset(con->physical.path);

			return HANDLER_FINISHED;
		}

		/* we have a PATHINFO */
		if (pathinfo) {
			size_t len = strlen(pathinfo), reqlen;
			if (con->conf.force_lowercase_filenames
			    && len <= (reqlen = buffer_string_length(con->request.uri))
			    && 0 == strncasecmp(con->request.uri->ptr + reqlen - len, pathinfo, len)) {
				/* attempt to preserve case-insensitive PATH_INFO
				 * (works in common case where mod_alias, mod_magnet, and other modules
				 *  have not modified the PATH_INFO portion of request URI, or did so
				 *  with exactly the PATH_INFO desired) */
				buffer_copy_string_len(con->request.pathinfo, con->request.uri->ptr + reqlen - len, len);
			} else {
				buffer_copy_string_len(con->request.pathinfo, pathinfo, len);
			}

			/*
			 * shorten uri.path
			 */

			buffer_string_set_length(con->uri.path, buffer_string_length(con->uri.path) - len);
			buffer_string_set_length(con->physical.path, (size_t)(pathinfo - con->physical.path->ptr));
		}
	}

#ifdef HAVE_LSTAT
	if ((sce->is_symlink != 0) && !con->conf.follow_symlink) {
		con->http_status = 403;

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied due symlink restriction");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}

		buffer_reset(con->physical.path);
		return HANDLER_FINISHED;
	};
#endif
	if (S_ISDIR(sce->st.st_mode)) {
		if (con->uri.path->ptr[buffer_string_length(con->uri.path) - 1] != '/') {
			/* redirect to .../ */

			http_response_redirect_to_directory(srv, con);

			return HANDLER_FINISHED;
		}
#ifdef HAVE_LSTAT
	} else if (!S_ISREG(sce->st.st_mode) && !sce->is_symlink) {
#else
	} else if (!S_ISREG(sce->st.st_mode)) {
#endif
		/* any special handling of non-reg files ?*/
	}

	return HANDLER_GO_ON;
}

handler_t http_response_prepare(server *srv, connection *con) {
	handler_t r;

	/* looks like someone has already done a decision */
	if (con->mode == DIRECT &&
	    (con->http_status != 0 && con->http_status != 200)) {
		/* remove a packets in the queue */
		if (con->file_finished == 0) {
			chunkqueue_reset(con->write_queue);
		}

		return HANDLER_FINISHED;
	}

	/* no decision yet, build conf->filename */
	if (con->mode == DIRECT && buffer_is_empty(con->physical.path)) {


	    if (!con->async_callback) {


		char *qstr;

		/* we only come here when we have the parse the full request again
		 *
		 * a HANDLER_COMEBACK from mod_rewrite and mod_fastcgi might be a
		 * problem here as mod_setenv might get called multiple times
		 *
		 * fastcgi-auth might lead to a COMEBACK too
		 * fastcgi again dead server too
		 *
		 * mod_compress might add headers twice too
		 *
		 *  */

		config_cond_cache_reset(srv, con);
		config_setup_connection(srv, con); /* Perhaps this could be removed at other places. */

		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "run condition");
		}

		/**
		 * prepare strings
		 *
		 * - uri.path_raw
		 * - uri.path (secure)
		 * - uri.query
		 *
		 */

		/**
		 * Name according to RFC 2396
		 *
		 * - scheme
		 * - authority
		 * - path
		 * - query
		 *
		 * (scheme)://(authority)(path)?(query)#fragment
		 *
		 *
		 */

		/* take initial scheme value from connection-level state
		 * (request con->uri.scheme can be overwritten for later,
		 *  for example by mod_extforward or mod_magnet) */
		buffer_copy_buffer(con->uri.scheme, con->proto);
		buffer_copy_buffer(con->uri.authority, con->request.http_host);
		buffer_to_lower(con->uri.authority);

		/** their might be a fragment which has to be cut away */
		if (NULL != (qstr = strchr(con->request.uri->ptr, '#'))) {
			buffer_string_set_length(con->request.uri, qstr - con->request.uri->ptr);
		}

		/** extract query string from request.uri */
		if (NULL != (qstr = strchr(con->request.uri->ptr, '?'))) {
			buffer_copy_string    (con->uri.query, qstr + 1);
			buffer_copy_string_len(con->uri.path_raw, con->request.uri->ptr, qstr - con->request.uri->ptr);
		} else {
			buffer_reset     (con->uri.query);
			buffer_copy_buffer(con->uri.path_raw, con->request.uri);
		}

		/* decode url to path
		 *
		 * - decode url-encodings  (e.g. %20 -> ' ')
		 * - remove path-modifiers (e.g. /../)
		 */

		if (con->request.http_method == HTTP_METHOD_OPTIONS &&
		    con->uri.path_raw->ptr[0] == '*' && con->uri.path_raw->ptr[1] == '\0') {
			/* OPTIONS * ... */
			buffer_copy_buffer(con->uri.path, con->uri.path_raw);
		} else if (con->request.http_method == HTTP_METHOD_CONNECT) {
			buffer_copy_buffer(con->uri.path, con->uri.path_raw);
		} else {
			buffer_copy_buffer(srv->tmp_buf, con->uri.path_raw);
			buffer_urldecode_path(srv->tmp_buf);
			buffer_path_simplify(con->uri.path, srv->tmp_buf);
		}

		con->conditional_is_valid[COMP_SERVER_SOCKET] = 1;       /* SERVERsocket */
		con->conditional_is_valid[COMP_HTTP_SCHEME] = 1;         /* Scheme:      */
		con->conditional_is_valid[COMP_HTTP_HOST] = 1;           /* Host:        */
		con->conditional_is_valid[COMP_HTTP_REMOTE_IP] = 1;      /* Client-IP */
		con->conditional_is_valid[COMP_HTTP_REQUEST_METHOD] = 1; /* REQUEST_METHOD */
		con->conditional_is_valid[COMP_HTTP_URL] = 1;            /* HTTPurl */
		con->conditional_is_valid[COMP_HTTP_QUERY_STRING] = 1;   /* HTTPqs */
		con->conditional_is_valid[COMP_HTTP_REQUEST_HEADER] = 1; /* HTTP request header */
		config_patch_connection(srv, con);

		/* do we have to downgrade to 1.0 ? */
		if (!con->conf.allow_http11) {
			con->request.http_version = HTTP_VERSION_1_0;
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- splitting Request-URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Request-URI     : ", con->request.uri);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-scheme      : ", con->uri.scheme);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-authority   : ", con->uri.authority);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path (raw)  : ", con->uri.path_raw);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path (clean): ", con->uri.path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-query       : ", con->uri.query);
		}

		/* con->conf.max_request_size is in kBytes */
		if (0 != con->conf.max_request_size &&
		    (off_t)con->request.content_length > ((off_t)con->conf.max_request_size << 10)) {
			log_error_write(srv, __FILE__, __LINE__, "sos",
					"request-size too long:", (off_t) con->request.content_length, "-> 413");
			con->keep_alive = 0;
			con->http_status = 413;
			con->file_finished = 1;

			return HANDLER_FINISHED;
		}


	    }
	    con->async_callback = 0; /* reset */


		/**
		 *
		 * call plugins
		 *
		 * - based on the raw URL
		 *
		 */

		switch(r = plugins_call_handle_uri_raw(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", "handle_uri_raw: unknown return value", r);
			break;
		}

		/**
		 *
		 * call plugins
		 *
		 * - based on the clean URL
		 *
		 */

		switch(r = plugins_call_handle_uri_clean(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}

		if (con->request.http_method == HTTP_METHOD_OPTIONS &&
		    con->uri.path->ptr[0] == '*' && con->uri.path_raw->ptr[1] == '\0') {
			/* option requests are handled directly without checking of the path */

			response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));

			con->http_status = 200;
			con->file_finished = 1;

			return HANDLER_FINISHED;
		}

		/***
		 *
		 * border
		 *
		 * logical filename (URI) becomes a physical filename here
		 *
		 *
		 *
		 */




		/* 1. stat()
		 * ... ISREG() -> ok, go on
		 * ... ISDIR() -> index-file -> redirect
		 *
		 * 2. pathinfo()
		 * ... ISREG()
		 *
		 * 3. -> 404
		 *
		 */

		/*
		 * SEARCH DOCUMENT ROOT
		 */

		/* set a default */

		buffer_copy_buffer(con->physical.doc_root, con->conf.document_root);
		buffer_copy_buffer(con->physical.rel_path, con->uri.path);

#if defined(__WIN32) || defined(__CYGWIN__)
		/* strip dots from the end and spaces
		 *
		 * windows/dos handle those filenames as the same file
		 *
		 * foo == foo. == foo..... == "foo...   " == "foo..  ./"
		 *
		 * This will affect in some cases PATHINFO
		 *
		 * on native windows we could prepend the filename with \\?\ to circumvent
		 * this behaviour. I have no idea how to push this through cygwin
		 *
		 * */

		if (con->physical.rel_path->used > 1) {
			buffer *b = con->physical.rel_path;
			size_t len = buffer_string_length(b);

			/* strip trailing " /" or "./" once */
			if (len > 1 &&
			    b->ptr[len - 1] == '/' &&
			    (b->ptr[len - 2] == ' ' || b->ptr[len - 2] == '.')) {
				len -= 2;
			}
			/* strip all trailing " " and "." */
			while (len > 0 &&  ( ' ' == b->ptr[len-1] || '.' == b->ptr[len-1] ) ) --len;
			buffer_string_set_length(b, len);
		}
#endif

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- before doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
		/* the docroot plugin should set the doc_root and might also set the physical.path
		 * for us (all vhost-plugins are supposed to set the doc_root)
		 * */
		switch(r = plugins_call_handle_docroot(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}

		/* MacOS X and Windows can't distiguish between upper and lower-case
		 *
		 * convert to lower-case
		 */
		if (con->conf.force_lowercase_filenames) {
			buffer_to_lower(con->physical.rel_path);
		}

		/* the docroot plugins might set the servername, if they don't we take http-host */
		if (buffer_string_is_empty(con->server_name)) {
			buffer_copy_buffer(con->server_name, con->uri.authority);
		}

		/**
		 * create physical filename
		 * -> physical.path = docroot + rel_path
		 *
		 */

		buffer_copy_buffer(con->physical.basedir, con->physical.doc_root);
		buffer_copy_buffer(con->physical.path, con->physical.doc_root);
		buffer_append_slash(con->physical.path);
		if (!buffer_string_is_empty(con->physical.rel_path) &&
		    con->physical.rel_path->ptr[0] == '/') {
		      #ifdef __COVERITY__
			if (buffer_string_length(con->physical.rel_path) < 1) return HANDLER_ERROR;
		      #endif
			/* coverity[overflow_sink : FALSE] */
			buffer_append_string_len(con->physical.path, con->physical.rel_path->ptr + 1, buffer_string_length(con->physical.rel_path) - 1);
		} else {
			buffer_append_string_buffer(con->physical.path, con->physical.rel_path);
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}

		switch(r = plugins_call_handle_physical(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- logical -> physical");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Basedir      :", con->physical.basedir);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
	}

	/*
	 * Noone catched away the file from normal path of execution yet (like mod_access)
	 *
	 * Go on and check of the file exists at all
	 */

	if (con->mode == DIRECT) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling physical path");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}

		r = http_response_physical_path_check(srv, con);
		if (HANDLER_GO_ON != r) return r;

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling subrequest");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI          :", con->uri.path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Pathinfo     :", con->request.pathinfo);
		}

		/* call the handlers */
		r = plugins_call_handle_subrequest_start(srv, con);
		if (HANDLER_GO_ON != r) {
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- subrequest finished");
			}
			return r;
		}

		/* if we are still here, no one wanted the file, status 403 is ok I think */
		if (con->mode == DIRECT && con->http_status == 0) {
			con->http_status = (con->request.http_method != HTTP_METHOD_OPTIONS) ? 403 : 200;
			return HANDLER_FINISHED;
		}

	}

	r = plugins_call_handle_subrequest(srv, con);
	if (HANDLER_GO_ON == r) r = HANDLER_FINISHED; /* request was not handled, looks like we are done */
	return r;
}
