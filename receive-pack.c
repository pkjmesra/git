#include "cache.h"
#include "pack.h"
#include "refs.h"
#include "pkt-line.h"
#include "run-command.h"
#include "commit.h"
#include "object.h"

static const char receive_pack_usage[] = "git-receive-pack <git-dir>";

static int deny_non_fast_forwards = 0;
static int unpack_limit = 5000;
static int report_status;

static char capabilities[] = "report-status";
static int capabilities_sent;

static int receive_pack_config(const char *var, const char *value)
{
	git_default_config(var, value);

	if (strcmp(var, "receive.denynonfastforwards") == 0)
	{
		deny_non_fast_forwards = git_config_bool(var, value);
		return 0;
	}

	if (strcmp(var, "receive.unpacklimit") == 0)
	{
		unpack_limit = git_config_int(var, value);
		return 0;
	}

	return 0;
}

static int show_ref(const char *path, const unsigned char *sha1, int flag, void *cb_data)
{
	if (capabilities_sent)
		packet_write(1, "%s %s\n", sha1_to_hex(sha1), path);
	else
		packet_write(1, "%s %s%c%s\n",
			     sha1_to_hex(sha1), path, 0, capabilities);
	capabilities_sent = 1;
	return 0;
}

static void write_head_info(void)
{
	for_each_ref(show_ref, NULL);
	if (!capabilities_sent)
		show_ref("capabilities^{}", null_sha1, 0, NULL);

}

struct command {
	struct command *next;
	const char *error_string;
	unsigned char old_sha1[20];
	unsigned char new_sha1[20];
	char ref_name[FLEX_ARRAY]; /* more */
};

static struct command *commands;

static char update_hook[] = "hooks/update";

static int run_update_hook(const char *refname,
			   char *old_hex, char *new_hex)
{
	int code;

	if (access(update_hook, X_OK) < 0)
		return 0;
	code = run_command(update_hook, refname, old_hex, new_hex, NULL);
	switch (code) {
	case 0:
		return 0;
	case -ERR_RUN_COMMAND_FORK:
		return error("hook fork failed");
	case -ERR_RUN_COMMAND_EXEC:
		return error("hook execute failed");
	case -ERR_RUN_COMMAND_WAITPID:
		return error("waitpid failed");
	case -ERR_RUN_COMMAND_WAITPID_WRONG_PID:
		return error("waitpid is confused");
	case -ERR_RUN_COMMAND_WAITPID_SIGNAL:
		return error("%s died of signal", update_hook);
	case -ERR_RUN_COMMAND_WAITPID_NOEXIT:
		return error("%s died strangely", update_hook);
	default:
		error("%s exited with error code %d", update_hook, -code);
		return -code;
	}
}

static int update(struct command *cmd)
{
	const char *name = cmd->ref_name;
	unsigned char *old_sha1 = cmd->old_sha1;
	unsigned char *new_sha1 = cmd->new_sha1;
	char new_hex[41], old_hex[41];
	struct ref_lock *lock;

	cmd->error_string = NULL;
	if (!strncmp(name, "refs/", 5) && check_ref_format(name + 5)) {
		cmd->error_string = "funny refname";
		return error("refusing to create funny ref '%s' locally",
			     name);
	}

	strcpy(new_hex, sha1_to_hex(new_sha1));
	strcpy(old_hex, sha1_to_hex(old_sha1));
	if (!has_sha1_file(new_sha1)) {
		cmd->error_string = "bad pack";
		return error("unpack should have generated %s, "
			     "but I can't find it!", new_hex);
	}
	if (deny_non_fast_forwards && !is_null_sha1(old_sha1)) {
		struct commit *old_commit, *new_commit;
		struct commit_list *bases, *ent;

		old_commit = (struct commit *)parse_object(old_sha1);
		new_commit = (struct commit *)parse_object(new_sha1);
		bases = get_merge_bases(old_commit, new_commit, 1);
		for (ent = bases; ent; ent = ent->next)
			if (!hashcmp(old_sha1, ent->item->object.sha1))
				break;
		free_commit_list(bases);
		if (!ent)
			return error("denying non-fast forward;"
				     " you should pull first");
	}
	if (run_update_hook(name, old_hex, new_hex)) {
		cmd->error_string = "hook declined";
		return error("hook declined to update %s", name);
	}

	lock = lock_any_ref_for_update(name, old_sha1);
	if (!lock) {
		cmd->error_string = "failed to lock";
		return error("failed to lock %s", name);
	}
	write_ref_sha1(lock, new_sha1, "push");

	fprintf(stderr, "%s: %s -> %s\n", name, old_hex, new_hex);
	return 0;
}

static char update_post_hook[] = "hooks/post-update";

static void run_update_post_hook(struct command *cmd)
{
	struct command *cmd_p;
	int argc;
	const char **argv;

	if (access(update_post_hook, X_OK) < 0)
		return;
	for (argc = 1, cmd_p = cmd; cmd_p; cmd_p = cmd_p->next) {
		if (cmd_p->error_string)
			continue;
		argc++;
	}
	argv = xmalloc(sizeof(*argv) * (1 + argc));
	argv[0] = update_post_hook;

	for (argc = 1, cmd_p = cmd; cmd_p; cmd_p = cmd_p->next) {
		char *p;
		if (cmd_p->error_string)
			continue;
		p = xmalloc(strlen(cmd_p->ref_name) + 1);
		strcpy(p, cmd_p->ref_name);
		argv[argc] = p;
		argc++;
	}
	argv[argc] = NULL;
	run_command_v_opt(argc, argv, RUN_COMMAND_NO_STDIO);
}

/*
 * This gets called after(if) we've successfully
 * unpacked the data payload.
 */
static void execute_commands(void)
{
	struct command *cmd = commands;

	while (cmd) {
		update(cmd);
		cmd = cmd->next;
	}
	run_update_post_hook(commands);
}

static void read_head_info(void)
{
	struct command **p = &commands;
	for (;;) {
		static char line[1000];
		unsigned char old_sha1[20], new_sha1[20];
		struct command *cmd;
		char *refname;
		int len, reflen;

		len = packet_read_line(0, line, sizeof(line));
		if (!len)
			break;
		if (line[len-1] == '\n')
			line[--len] = 0;
		if (len < 83 ||
		    line[40] != ' ' ||
		    line[81] != ' ' ||
		    get_sha1_hex(line, old_sha1) ||
		    get_sha1_hex(line + 41, new_sha1))
			die("protocol error: expected old/new/ref, got '%s'",
			    line);

		refname = line + 82;
		reflen = strlen(refname);
		if (reflen + 82 < len) {
			if (strstr(refname + reflen + 1, "report-status"))
				report_status = 1;
		}
		cmd = xmalloc(sizeof(struct command) + len - 80);
		hashcpy(cmd->old_sha1, old_sha1);
		hashcpy(cmd->new_sha1, new_sha1);
		memcpy(cmd->ref_name, line + 82, len - 81);
		cmd->error_string = "n/a (unpacker error)";
		cmd->next = NULL;
		*p = cmd;
		p = &cmd->next;
	}
}

static const char *parse_pack_header(struct pack_header *hdr)
{
	char *c = (char*)hdr;
	ssize_t remaining = sizeof(struct pack_header);
	do {
		ssize_t r = xread(0, c, remaining);
		if (r <= 0)
			return "eof before pack header was fully read";
		remaining -= r;
		c += r;
	} while (remaining > 0);
	if (hdr->hdr_signature != htonl(PACK_SIGNATURE))
		return "protocol error (pack signature mismatch detected)";
	if (!pack_version_ok(hdr->hdr_version))
		return "protocol error (pack version unsupported)";
	return NULL;
}

static const char *unpack(void)
{
	struct pack_header hdr;
	const char *hdr_err;
	char hdr_arg[38];
	int code;

	hdr_err = parse_pack_header(&hdr);
	if (hdr_err)
		return hdr_err;
	snprintf(hdr_arg, sizeof(hdr_arg), "--pack_header=%u,%u",
			ntohl(hdr.hdr_version), ntohl(hdr.hdr_entries));

	if (ntohl(hdr.hdr_entries) < unpack_limit) {
		const char *unpacker[3];
		unpacker[0] = "unpack-objects";
		unpacker[1] = hdr_arg;
		unpacker[2] = NULL;
		code = run_command_v_opt(1, unpacker, RUN_GIT_CMD);
	} else {
		const char *keeper[6];
		char my_host[255], keep_arg[128 + 255];

		if (gethostname(my_host, sizeof(my_host)))
			strcpy(my_host, "localhost");
		snprintf(keep_arg, sizeof(keep_arg),
				"--keep=receive-pack %i on %s",
				getpid(), my_host);

		keeper[0] = "index-pack";
		keeper[1] = "--stdin";
		keeper[2] = "--fix-thin";
		keeper[3] = hdr_arg;
		keeper[4] = keep_arg;
		keeper[5] = NULL;
		code = run_command_v_opt(1, keeper, RUN_GIT_CMD);
		if (!code)
			reprepare_packed_git();
	}

	switch (code) {
		case 0:
			return NULL;
		case -ERR_RUN_COMMAND_FORK:
			return "unpack fork failed";
		case -ERR_RUN_COMMAND_EXEC:
			return "unpack execute failed";
		case -ERR_RUN_COMMAND_WAITPID:
			return "waitpid failed";
		case -ERR_RUN_COMMAND_WAITPID_WRONG_PID:
			return "waitpid is confused";
		case -ERR_RUN_COMMAND_WAITPID_SIGNAL:
			return "unpacker died of signal";
		case -ERR_RUN_COMMAND_WAITPID_NOEXIT:
			return "unpacker died strangely";
		default:
			return "unpacker exited with error code";
	}
}

static void report(const char *unpack_status)
{
	struct command *cmd;
	packet_write(1, "unpack %s\n",
		     unpack_status ? unpack_status : "ok");
	for (cmd = commands; cmd; cmd = cmd->next) {
		if (!cmd->error_string)
			packet_write(1, "ok %s\n",
				     cmd->ref_name);
		else
			packet_write(1, "ng %s %s\n",
				     cmd->ref_name, cmd->error_string);
	}
	packet_flush(1);
}

int main(int argc, char **argv)
{
	int i;
	char *dir = NULL;

	argv++;
	for (i = 1; i < argc; i++) {
		char *arg = *argv++;

		if (*arg == '-') {
			/* Do flag handling here */
			usage(receive_pack_usage);
		}
		if (dir)
			usage(receive_pack_usage);
		dir = arg;
	}
	if (!dir)
		usage(receive_pack_usage);

	if (!enter_repo(dir, 0))
		die("'%s': unable to chdir or not a git archive", dir);

	setup_ident();
	git_config(receive_pack_config);

	write_head_info();

	/* EOF */
	packet_flush(1);

	read_head_info();
	if (commands) {
		const char *unpack_status = unpack();
		if (!unpack_status)
			execute_commands();
		if (report_status)
			report(unpack_status);
	}
	return 0;
}
