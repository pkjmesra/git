#include "cache.h"
#include "remote.h"
#include "checkout.h"
#include "config.h"

struct tracking_name_data {
	/* const */ char *src_ref;
	char *dst_ref;
	struct object_id *dst_oid;
	int unique;
	const char *implicit_remote;
	char *implicit_dst_ref;
};

static int check_tracking_name(struct remote *remote, void *cb_data)
{
	struct tracking_name_data *cb = cb_data;
	struct refspec query;
	memset(&query, 0, sizeof(struct refspec));
	query.src = cb->src_ref;
	if (remote_find_tracking(remote, &query) ||
	    get_oid(query.dst, cb->dst_oid)) {
		free(query.dst);
		return 0;
	}
	if (cb->implicit_remote && !strcmp(remote->name, cb->implicit_remote))
		cb->implicit_dst_ref = xstrdup(query.dst);
	if (cb->dst_ref) {
		free(query.dst);
		cb->unique = 0;
		return 0;
	}
	cb->dst_ref = query.dst;
	return 0;
}

const char *unique_tracking_name(const char *name, struct object_id *oid)
{
	const char *implicit_remote = NULL;
	struct tracking_name_data cb_data = { NULL, NULL, NULL, 1, NULL, NULL };
	if (!git_config_get_string_const("checkout.implicitremote", &implicit_remote))
		cb_data.implicit_remote = implicit_remote;
	cb_data.src_ref = xstrfmt("refs/heads/%s", name);
	cb_data.dst_oid = oid;
	for_each_remote(check_tracking_name, &cb_data);
	free(cb_data.src_ref);
	free((char *)implicit_remote);
	if (cb_data.unique) {
		free(cb_data.implicit_dst_ref);
		return cb_data.dst_ref;
	}
	free(cb_data.dst_ref);
	if (cb_data.implicit_dst_ref)
		return cb_data.implicit_dst_ref;
	return NULL;
}
