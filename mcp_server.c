/*
 * mcp_server.c - MCP server for crash utility
 *
 */

#include "defs.h"

#ifdef MCP

#include "mcp.h"
#include "cJSON.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

static int mcp_call_count;
static int mcp_client_fd = -1;
static int mcp_use_socket = 0;

static const char *mcp_blocked_commands[] = {
	"q", "quit", "exit", NULL
};

static int
mcp_is_blocked_command(const char *name)
{
	int i;
	for (i = 0; mcp_blocked_commands[i]; i++) {
		if (strcmp(name, mcp_blocked_commands[i]) == 0)
			return 1;
	}
	return 0;
}

static const char *
mcp_tool_desc(const char *name)
{
	static const struct {
		const char *name;
		const char *desc;
	} descs[] = {
		{"*",         "Shortcut for struct/union member access"},
		{"alias",     "Display and manage command aliases"},
		{"ascii",     "Translate hexadecimal values to ASCII"},
		{"bpf",       "Display loaded eBPF programs and maps"},
		{"bt",        "Display kernel stack backtrace"},
		{"btop",      "Translate address to page frame number"},
		{"dev",       "Display character and block device data"},
		{"dis",       "Disassemble memory at given address"},
		{"eval",      "Evaluate expression or numeric value"},
		{"extend",    "Load or unload extension shared objects"},
		{"files",     "Display open files of a task"},
		{"foreach",   "Run a command across multiple tasks"},
		{"fuser",     "Display tasks using a file or socket"},
		{"gdb",       "Pass arguments directly to gdb"},
		{"help",      "Display help for a command"},
		{"ipcs",      "Display System V IPC facilities"},
		{"irq",       "Display IRQ descriptor and action data"},
		{"kmem",      "Display kernel memory/slab/subsystem info"},
		{"list",      "Dump contents of a linked list"},
		{"log",       "Dump kernel log buffer"},
		{"mach",      "Display machine-specific data"},
		{"mod",       "Display and load kernel module info"},
		{"mount",     "Display mounted filesystem data"},
		{"net",       "Display network devices and socket data"},
		{"p",         "Evaluate expression via gdb print"},
		{"ps",        "Display process status information"},
		{"pte",       "Translate page table entry contents"},
		{"ptob",      "Translate page frame number to bytes"},
		{"ptov",      "Translate physical address to kernel virtual"},
		{"rd",        "Read and display memory contents"},
		{"repeat",    "Repeat a command at intervals"},
		{"runq",      "Display run queue tasks per CPU"},
		{"sbitmapq",  "Dump sbitmap_queue structure contents"},
		{"search",    "Search memory for a value or string"},
		{"set",       "Set process context or crash variable"},
		{"sig",       "Display signal-handling data of tasks"},
		{"struct",    "Display structure definition or contents"},
		{"swap",      "Display swap device information"},
		{"sym",       "Translate symbol to address or vice-versa"},
		{"sys",       "Display kernel panic and system data"},
		{"task",      "Display task_struct and thread_info contents"},
		{"timer",     "Display timer queue entries"},
		{"tree",      "Dump radix tree, XArray, or rbtree"},
		{"union",     "Display union definition or contents"},
		{"vm",        "Display virtual memory mappings"},
		{"vtop",      "Translate virtual to physical address"},
		{"waitq",     "List tasks queued on a wait queue"},
		{"whatis",    "Search symbol table for type definitions"},
		{"wr",        "Write value to memory"},
		{"rustfilt",  "Demangle Rust symbol to human-readable"},
		{NULL, NULL}
	};
	int i;
	for (i = 0; descs[i].name; i++) {
		if (strcmp(name, descs[i].name) == 0)
			return descs[i].desc;
	}
	return NULL;
}

static FILE *mcp_saved_fp;
static int mcp_saved_stderr_fd;
static jmp_buf mcp_saved_env;
static int mcp_out_fd = -1;
static int mcp_err_fd = -1;
static char mcp_outfile[64];
static char mcp_errfile[64];
static int mcp_capturing;
static char *mcp_output_buf;
static size_t mcp_output_len;

struct mcp_buf {
	char *data;
	size_t len;
	size_t cap;
};

static void
mcp_buf_init(struct mcp_buf *b)
{
	b->cap = 4096;
	b->data = malloc(b->cap);
	b->len = 0;
	if (b->data)
		b->data[0] = '\0';
}

static void
mcp_buf_append(struct mcp_buf *b, const char *src, size_t slen)
{
	if (!b->data || slen == 0)
		return;

	while (b->len + slen + 1 > b->cap) {
		size_t newcap = b->cap * 2;
		char *newdata = realloc(b->data, newcap);
		if (!newdata) {
			b->data = NULL;
			return;
		}
		b->data = newdata;
		b->cap = newcap;
	}

	memcpy(b->data + b->len, src, slen);
	b->len += slen;
	b->data[b->len] = '\0';
}

static char *
mcp_buf_detach(struct mcp_buf *b)
{
	char *ret = b->data;
	if (!ret)
		ret = strdup("");
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
	return ret;
}

static char *
mcp_drain_pipe(int fd, const char *prefix)
{
	char buf[4096];
	ssize_t n;
	struct mcp_buf b;

	mcp_buf_init(&b);
	if (!b.data) {
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			;
		close(fd);
		return strdup(prefix ? prefix : "");
	}

	if (prefix)
		mcp_buf_append(&b, prefix, strlen(prefix));

	while ((n = read(fd, buf, sizeof(buf))) > 0)
		mcp_buf_append(&b, buf, (size_t)n);
	close(fd);

	return mcp_buf_detach(&b);
}

static char *
mcp_read_file(const char *path)
{
	struct stat st;
	char *buf;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	if (st.st_size == 0) {
		close(fd);
		return strdup("");
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}

	n = read(fd, buf, st.st_size);
	close(fd);

	if (n < 0) {
		free(buf);
		return NULL;
	}

	buf[n] = '\0';
	return buf;
}

int
mcp_capture_start(char **output, size_t *output_len)
{
	int out_fd, err_fd;

	if (mcp_capturing)
		return -1;

	snprintf(mcp_outfile, sizeof(mcp_outfile),
		"/tmp/crash_mcp_out.XXXXXX");
	snprintf(mcp_errfile, sizeof(mcp_errfile),
		"/tmp/crash_mcp_err.XXXXXX");

	out_fd = mkstemp(mcp_outfile);
	if (out_fd < 0)
		return -1;

	err_fd = mkstemp(mcp_errfile);
	if (err_fd < 0) {
		close(out_fd);
		unlink(mcp_outfile);
		return -1;
	}

	mcp_saved_fp = fp;
	fp = fdopen(out_fd, "w");
	if (!fp) {
		close(out_fd);
		close(err_fd);
		unlink(mcp_outfile);
		unlink(mcp_errfile);
		fp = mcp_saved_fp;
		return -1;
	}

	mcp_out_fd = out_fd;
	mcp_err_fd = err_fd;

	mcp_saved_stderr_fd = dup(STDERR_FILENO);
	dup2(err_fd, STDERR_FILENO);

	memcpy(&mcp_saved_env, &pc->main_loop_env, sizeof(jmp_buf));
	mcp_output_buf = NULL;
	mcp_output_len = 0;

	mcp_capturing = 1;
	return 0;
}

static void
mcp_capture_restore(void)
{
	fflush(fp);
	fclose(fp);
	fp = mcp_saved_fp;
	mcp_out_fd = -1;

	fflush(stderr);
	dup2(mcp_saved_stderr_fd, STDERR_FILENO);
	close(mcp_saved_stderr_fd);
	close(mcp_err_fd);
	mcp_err_fd = -1;

	mcp_capturing = 0;
}

void
mcp_capture_stop(char **output, size_t *output_len)
{
	char *stdout_data, *stderr_data;

	if (!mcp_capturing) {
		*output = NULL;
		*output_len = 0;
		return;
	}

	mcp_capture_restore();

	stdout_data = mcp_read_file(mcp_outfile);
	stderr_data = mcp_read_file(mcp_errfile);

	unlink(mcp_outfile);
	unlink(mcp_errfile);

	if (stdout_data && stderr_data && stderr_data[0]) {
		size_t slen = strlen(stdout_data);
		size_t elen = strlen(stderr_data);
		mcp_output_buf = malloc(slen + elen + 2);
		if (mcp_output_buf) {
			memcpy(mcp_output_buf, stdout_data, slen);
			mcp_output_buf[slen] = '\n';
			memcpy(mcp_output_buf + slen + 1, stderr_data, elen);
			mcp_output_buf[slen + elen + 1] = '\0';
			mcp_output_len = slen + elen + 1;
		} else {
			mcp_output_buf = stdout_data;
			stdout_data = NULL;
			mcp_output_len = strlen(mcp_output_buf);
		}
	} else {
		mcp_output_buf = stdout_data;
		stdout_data = NULL;
		mcp_output_len = mcp_output_buf ? strlen(mcp_output_buf) : 0;
	}

	free(stderr_data);
	free(stdout_data);

	memcpy(&pc->main_loop_env, &mcp_saved_env, sizeof(jmp_buf));
}

void
mcp_capture_transfer(char **output, size_t *output_len)
{
	if (output)
		*output = mcp_output_buf;
	if (output_len)
		*output_len = mcp_output_len;
	mcp_output_buf = NULL;
	mcp_output_len = 0;
}

void
mcp_capture_cleanup(void)
{
	char *stdout_data, *stderr_data;

	if (!mcp_capturing)
		return;

	mcp_capture_restore();

	stdout_data = mcp_read_file(mcp_outfile);
	stderr_data = mcp_read_file(mcp_errfile);

	unlink(mcp_outfile);
	unlink(mcp_errfile);

	if (stdout_data && stderr_data && stderr_data[0]) {
		size_t slen = strlen(stdout_data);
		size_t elen = strlen(stderr_data);
		mcp_output_buf = malloc(slen + elen + 2);
		if (mcp_output_buf) {
			memcpy(mcp_output_buf, stdout_data, slen);
			mcp_output_buf[slen] = '\n';
			memcpy(mcp_output_buf + slen + 1, stderr_data, elen);
			mcp_output_buf[slen + elen + 1] = '\0';
			mcp_output_len = slen + elen + 1;
		} else {
			mcp_output_buf = stdout_data;
			stdout_data = NULL;
			mcp_output_len = strlen(mcp_output_buf);
		}
	} else {
		mcp_output_buf = stdout_data;
		stdout_data = NULL;
		mcp_output_len = mcp_output_buf ? strlen(mcp_output_buf) : 0;
	}

	free(stderr_data);
	free(stdout_data);

	memcpy(&pc->main_loop_env, &mcp_saved_env, sizeof(jmp_buf));
}

/*
 * Persistent buffer for mcp_read_request() to handle the case where
 * a single read() returns data containing multiple JSON-RPC messages
 * separated by newlines.  Without this, the second (and subsequent)
 * messages are silently dropped.
 */
static char mcp_rx_buf[MCP_MAX_INPUT_SIZE + 1];
static size_t mcp_rx_len; /* number of bytes in mcp_rx_buf */

int
mcp_read_request(char *buf, size_t maxlen)
{
	size_t i;
	ssize_t n;

	/*
	 * First, check for a complete line already in the persistent
	 * buffer from a previous read() that returned multiple lines.
	 */
	for (i = 0; i < mcp_rx_len; i++) {
		if (mcp_rx_buf[i] == '\n') {
			if (i >= maxlen - 1)
				i = maxlen - 2;
			memcpy(buf, mcp_rx_buf, i);
			buf[i] = '\0';
			/* Shift remaining data to front of persistent buf */
			mcp_rx_len -= i + 1;
			memmove(mcp_rx_buf, mcp_rx_buf + i + 1, mcp_rx_len);
			return i;
		}
	}

	/*
	 * No complete line yet — read more data from stdin, appending
	 * to whatever is already in the persistent buffer.
	 */
	while (mcp_rx_len < MCP_MAX_INPUT_SIZE) {
		size_t space = MCP_MAX_INPUT_SIZE - mcp_rx_len;
		int fd = mcp_use_socket ? mcp_client_fd : STDIN_FILENO;
		n = read(fd, mcp_rx_buf + mcp_rx_len, space);
		if (n <= 0) {
			if (errno == EINTR)
				continue;
			if (mcp_rx_len > 0) {
				/* EOF with leftover data — return it */
				if (mcp_rx_len >= maxlen)
					mcp_rx_len = maxlen - 1;
				memcpy(buf, mcp_rx_buf, mcp_rx_len);
				buf[mcp_rx_len] = '\0';
				mcp_rx_len = 0;
				return mcp_rx_len;
			}
			return -1;
		}
		mcp_rx_len += n;

		/* Check if we now have a complete line */
		for (i = 0; i < mcp_rx_len; i++) {
			if (mcp_rx_buf[i] == '\n') {
				if (i >= maxlen - 1)
					i = maxlen - 2;
				memcpy(buf, mcp_rx_buf, i);
				buf[i] = '\0';
				mcp_rx_len -= i + 1;
				memmove(mcp_rx_buf, mcp_rx_buf + i + 1, mcp_rx_len);
				return i;
			}
		}
	}

	/* Buffer full without a newline — return what we have */
	if (mcp_rx_len >= maxlen)
		mcp_rx_len = maxlen - 1;
	memcpy(buf, mcp_rx_buf, mcp_rx_len);
	buf[mcp_rx_len] = '\0';
	mcp_rx_len = 0;
	return mcp_rx_len;
}

void
mcp_send_response(const char *json_str)
{
	size_t len = strlen(json_str);
	size_t written = 0;
	int fd = mcp_use_socket ? mcp_client_fd : STDOUT_FILENO;

	while (written < len) {
		ssize_t n = write(fd, json_str + written,
				 len - written);
		if (n <= 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		written += (size_t)n;
	}

	write(fd, "\n", 1);
}

void
mcp_send_error(int id, int code, const char *message)
{
	cJSON *resp = cJSON_CreateObject();
	cJSON *err = cJSON_CreateObject();

	cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
	cJSON_AddNumberToObject(resp, "id", id);
	cJSON_AddNumberToObject(err, "code", code);
	cJSON_AddStringToObject(err, "message", message);
	cJSON_AddItemToObject(resp, "error", err);

	{
		char *out = cJSON_PrintUnformatted(resp);
		mcp_send_response(out);
		free(out);
	}
	cJSON_Delete(resp);
}

static void
mcp_send_result(int id, cJSON *result)
{
	cJSON *resp = cJSON_CreateObject();
	cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
	cJSON_AddNumberToObject(resp, "id", id);
	cJSON_AddItemToObject(resp, "result", result);

	{
		char *out = cJSON_PrintUnformatted(resp);
		mcp_send_response(out);
		free(out);
	}
	cJSON_Delete(resp);
}

static void
mcp_build_instructions(char *buf, size_t size)
{
	char panic_msg[BUFSIZE] = "N/A";
	char mem_size[BUFSIZE];
	char session_info[4096];
	const char *mode;

	if (pc->dumpfile)
		mode = "vmcore";
	else if (pc->live_memsrc)
		mode = "live";
	else if (pc->flags & MINIMAL_MODE)
		mode = "minimal";
	else
		mode = "unknown";

	if (STREQ(mode, "vmcore") && DUMPFILE()) {
		char *panic = get_panicmsg(panic_msg);
		if (panic && strlen(panic) > 0) {
			strip_linefeeds(panic);
			strncpy(panic_msg, panic, sizeof(panic_msg) - 1);
			panic_msg[sizeof(panic_msg) - 1] = '\0';
		}
	}

	get_memory_size(mem_size);

	char intro[1024];
	if (STREQ(mode, "live")) {
		snprintf(intro, sizeof(intro),
			"You are analyzing a LIVE running kernel via the crash utility through MCP. "
			"The kernel is active and its memory is accessible in real-time (see Session Context below). "
			"You do NOT need to load any dump file. "
			"Start analysis immediately by calling the tools below. "
			"NOTE: Some commands (like 'bt' without args) may reflect the current running state, not a crash snapshot.\n");
	} else if (STREQ(mode, "vmcore")) {
		snprintf(intro, sizeof(intro),
			"You are analyzing a kernel crash dump (vmcore) loaded into the crash utility through MCP. "
			"The dump file is ALREADY loaded (see Session Context below). "
			"You do NOT need to check files or directories. "
			"Start analysis immediately by calling the tools below.\n");
	} else {
		snprintf(intro, sizeof(intro),
			"You are connected to the crash utility through MCP. "
			"The current session context is shown below. "
			"Start analysis by calling the tools below.\n");
	}

	snprintf(session_info, sizeof(session_info),
		"Session Context:\n"
		"- Mode: %s\n"
		"- Kernel: %s\n"
		"- Architecture: %s\n"
		"- Hostname: %s\n"
		"- Memory: %s\n",
		mode,
		kt->utsname.release,
		kt->utsname.machine,
		kt->utsname.nodename,
		mem_size);

	if (STREQ(mode, "vmcore")) {
		char vmcore_info[2048];
		snprintf(vmcore_info, sizeof(vmcore_info),
			"- Dumpfile: %s\n"
			"- Panic Message: %s\n"
			"- Crash Date: %s\n",
			pc->dumpfile ? pc->dumpfile : "N/A",
			panic_msg,
			ctime_tz(&kt->date.tv_sec));
		strncat(session_info, vmcore_info,
			sizeof(session_info) - strlen(session_info) - 1);
	} else if (STREQ(mode, "live")) {
		char live_info[1024];
		snprintf(live_info, sizeof(live_info),
			"- Memory Source: %s\n"
			"- WARNING: Operating on LIVE kernel memory. "
			"Write operations will affect the running system.\n",
			pc->live_memsrc ? pc->live_memsrc : "N/A");
		strncat(session_info, live_info,
			sizeof(session_info) - strlen(session_info) - 1);
	}

		snprintf(buf, size,
		"%s\n\n"
		"%s\n"
		"AVAILABLE METHODS:\n"
		"  - tools/list                  : List all available crash commands\n"
		"  - tools/call (name, args)     : Execute a crash command\n"
		"  - resources/list              : List help resources\n"
		"  - resources/read (uri)        : Read help for a specific command\n"
		"  - shutdown                    : End the session\n\n"
		"HOW TO GET HELP:\n"
		"  Use resources/read with resource://crash/help/<command>\n"
		"  Example: resource://crash/help/bt\n\n"
		"DIAGNOSTIC WORKFLOWS:\n\n"
		"[Kernel Panic Analysis]\n"
		"  1. tools/call sys        → Identify panic type and CPU\n"
		"  2. tools/call bt         → Backtrace of panicking task\n"
		"  3. tools/call log -d     → dmesg messages (smaller than full log)\n"
		"  4. If NULL pointer: tools/call task <pid>; tools/call vm <pid>\n"
		"  5. If Oops: tools/call dis <pc> → Disassemble faulting instruction\n\n"
		"[Hung Task / Deadlock Detection]\n"
		"  1. tools/call ps -k      → List kernel threads\n"
		"  2. tools/call ps -s D    → Find tasks in D (uninterruptible) state\n"
		"  3. tools/call task <pid> → Examine task_struct of hung task\n"
		"  4. tools/call bt <pid>   → Stack trace to identify wait location\n"
		"  5. tools/call waitq      → Check if task is on a wait queue\n\n"
		"[Memory Leak / Corruption]\n"
		"  1. tools/call kmem -i    → Overall memory statistics\n"
		"  2. tools/call kmem -s    → Slab allocator details\n"
		"  3. tools/call kmem -S <name> → Specific slab cache info\n"
		"  4. tools/call search -s <pattern> → Search for suspicious strings\n"
		"  5. tools/call rd <addr>  → Inspect memory at specific address\n\n"
		"[Module / Driver Issues]\n"
		"  1. tools/call mod        → List loaded modules\n"
		"  2. tools/call mod <name> → Details of specific module\n"
		"  3. tools/call sym <addr> → Resolve symbol at fault address\n"
		"  4. tools/call dis <symbol> → Disassemble module code\n"
		"  5. tools/call struct module <addr> → Inspect module structure\n\n"
		"[Multi-CPU Analysis]\n"
		"  1. tools/call bt -a      → Backtraces of all CPUs\n"
		"  2. tools/call foreach 'task -R comm,state' → Task states across CPUs\n"
		"  3. tools/call runq       → Run queue status per CPU\n\n"
		"[Advanced: GDB Pass-through]\n"
		"  Use when crash built-in commands are insufficient:\n"
		"  tools/call gdb 'p <expression>'\n"
		"  tools/call gdb 'x/10i <address>'\n"
		"  tools/call gdb 'info registers'\n\n"
		"IMPORTANT CONSTRAINTS:\n"
		"  - Shell pipes (|, grep, tail, head) are NOT supported in args.\n"
		"    Only pass crash command flags, e.g. args='-d' not args='-d | tail'.\n"
		"  - Use crash's built-in flags to limit output:\n"
		"      log -d         → dmesg only (much smaller than full log)\n"
		"      ps -k          → kernel threads only\n"
		"      ps -s <state>  → tasks in specific state\n"
		"      bt -c <cpu>    → backtrace for one CPU\n"
		"      task -R <field>→ print specific task_struct field only\n"
		"  - For large vmcores, prefer targeted commands over full scans.\n\n",
		intro, session_info);
}

void
mcp_handle_initialize(int id)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *caps = cJSON_CreateObject();
	cJSON *tools_cap = cJSON_CreateObject();
	cJSON *server_info = cJSON_CreateObject();
	cJSON *session = cJSON_CreateObject();
	char buf[BUFSIZE];
	char instructions[8192];
	const char *mode;

	cJSON_AddStringToObject(result, "protocolVersion", MCP_PROTOCOL_VERSION);
	cJSON_AddItemToObject(tools_cap, "tools", cJSON_CreateObject());
	cJSON_AddItemToObject(caps, "tools", tools_cap);
	cJSON_AddItemToObject(caps, "resources", cJSON_CreateObject());
	cJSON_AddItemToObject(result, "capabilities", caps);

	if (pc->dumpfile)
		mode = "vmcore";
	else if (pc->live_memsrc)
		mode = "live";
	else if (pc->flags & MINIMAL_MODE)
		mode = "minimal";
	else
		mode = "unknown";

	cJSON_AddStringToObject(server_info, "name", "crash");
	cJSON_AddStringToObject(server_info, "version",
		pc->program_version ? pc->program_version : "unknown");

	cJSON_AddStringToObject(session, "mode", mode);
	cJSON_AddStringToObject(session, "kernel", kt->utsname.release);
	cJSON_AddStringToObject(session, "hostname", kt->utsname.nodename);
	cJSON_AddStringToObject(session, "machine", kt->utsname.machine);
	cJSON_AddStringToObject(session, "memory", get_memory_size(buf));

	if (STREQ(mode, "vmcore")) {
		cJSON_AddStringToObject(session, "dumpfile", pc->dumpfile);
		if (pc->namelist_orig)
			cJSON_AddStringToObject(session, "namelist", pc->namelist_orig);
		else if (pc->namelist)
			cJSON_AddStringToObject(session, "namelist", pc->namelist);

		if (DUMPFILE()) {
			char *panic = get_panicmsg(buf);
			if (panic && strlen(panic) > 0) {
				strip_linefeeds(panic);
				cJSON_AddStringToObject(session, "panic", panic);
			}
		}

		cJSON_AddStringToObject(session, "date", ctime_tz(&kt->date.tv_sec));
	} else if (STREQ(mode, "live")) {
		cJSON_AddStringToObject(session, "memory_source", pc->live_memsrc);
		cJSON_AddStringToObject(session, "warning",
			"Operating on LIVE kernel memory. "
			"Write operations (wr command) will affect the running system.");
	}

	cJSON_AddItemToObject(server_info, "session", session);
	cJSON_AddItemToObject(result, "serverInfo", server_info);

	mcp_build_instructions(instructions, sizeof(instructions));
	cJSON_AddStringToObject(result, "instructions", instructions);

	mcp_send_result(id, result);
}

static void
mcp_add_tool_to_array(cJSON *tools, struct command_table_entry *ct)
{
	cJSON *tool = cJSON_CreateObject();
	cJSON *schema = cJSON_CreateObject();
	cJSON *props = cJSON_CreateObject();
	cJSON *args_prop = cJSON_CreateObject();
	const char *desc;

	cJSON_AddStringToObject(tool, "name", ct->name);

	desc = mcp_tool_desc(ct->name);
	if (desc) {
		char full_desc[512];
		snprintf(full_desc, sizeof(full_desc), "%s. "
			"Use resource://crash/help/%s for detailed usage.",
			desc, ct->name);
		cJSON_AddStringToObject(tool, "description", full_desc);
	} else {
		cJSON_AddStringToObject(tool, "description", ct->name);
	}

	cJSON_AddStringToObject(schema, "type", "object");
	cJSON_AddStringToObject(args_prop, "type", "string");
	cJSON_AddStringToObject(args_prop, "description", "Command arguments");
	cJSON_AddItemToObject(props, "args", args_prop);
	cJSON_AddItemToObject(schema, "properties", props);
	cJSON_AddItemToObject(tool, "inputSchema", schema);

	cJSON_AddItemToArray(tools, tool);
}

void
mcp_handle_tools_list(int id)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *tools = cJSON_CreateArray();
	struct command_table_entry *ct;

	for (ct = pc->cmd_table; ct->name; ct++) {
		if (ct->flags & HIDDEN_COMMAND)
			continue;
		if (mcp_is_blocked_command(ct->name))
			continue;
		mcp_add_tool_to_array(tools, ct);
	}

	cJSON_AddItemToObject(result, "tools", tools);
	mcp_send_result(id, result);
}

void
mcp_handle_tools_call(int id, const char *tool_name, const char *tool_args)
{
	char *output;
	size_t output_len;
	int capture_ret;
	cJSON *result;
	cJSON *content;
	char cmd_buf[BUFSIZE];

	mcp_call_count++;
	if (mcp_call_count > MCP_MAX_TOOL_CALLS) {
		mcp_send_error(id, MCP_ERR_INTERNAL_ERROR,
			"Tool call limit exceeded");
		return;
	}

	if (mcp_is_blocked_command(tool_name)) {
		mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
			"Command not available in MCP mode. "
			"Use shutdown method to end session.");
		return;
	}

	if (strcmp(tool_name, "gdb") == 0 &&
	    (!tool_args || strlen(tool_args) == 0)) {
		mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
			"Interactive GDB mode not supported in MCP. "
			"Pass GDB commands as arguments, e.g. gdb bt");
		return;
	}

	if (tool_args && strlen(tool_args) > 0)
		snprintf(cmd_buf, sizeof(cmd_buf), "%s %s", tool_name, tool_args);
	else
		snprintf(cmd_buf, sizeof(cmd_buf), "%s", tool_name);

	BZERO(args, sizeof(args));
	argcnt = parse_line(cmd_buf, args);

	if (argcnt == 0 || !args[0]) {
		mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
			"Failed to parse command");
		return;
	}

	capture_ret = mcp_capture_start(NULL, NULL);

	if (capture_ret == 0) {
		exec_command();
		mcp_capture_stop(NULL, NULL);
	}

	mcp_capture_transfer(&output, &output_len);

	if (!output) {
		output = strdup("");
		output_len = 0;
	}

	if (output_len > MCP_MAX_OUTPUT_SIZE) {
		size_t trunc_len = MCP_MAX_OUTPUT_SIZE;
		char *truncated = malloc(trunc_len + 128);
		if (truncated) {
			memcpy(truncated, output, trunc_len);
			truncated[trunc_len] = '\0';
			strcat(truncated,
				"\n... [output truncated at 1MB]");
			free(output);
			output = truncated;
			output_len = strlen(output);
		}
	}

	result = cJSON_CreateObject();
	content = cJSON_CreateArray();
	{
		cJSON *text_item = cJSON_CreateObject();
		cJSON_AddStringToObject(text_item, "type", "text");
		cJSON_AddStringToObject(text_item, "text", output);
		cJSON_AddItemToArray(content, text_item);
	}
	cJSON_AddItemToObject(result, "content", content);
	cJSON_AddBoolToObject(result, "isError", capture_ret != 0);

	mcp_send_result(id, result);

	free(output);
}

void
mcp_handle_shutdown(int id)
{
	cJSON *result = cJSON_CreateObject();
	mcp_send_result(id, result);
	fflush(stdout);
	clean_exit(0);
}

static const char MCP_RESOURCE_PREFIX[] = "resource://crash/help/";

static struct command_table_entry *
mcp_find_cmd(const char *name)
{
	struct command_table_entry *ct;
	for (ct = pc->cmd_table; ct->name; ct++) {
		if (strcmp(name, ct->name) == 0)
			return ct;
	}
	return NULL;
}

void
mcp_handle_resources_list(int id)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *resources = cJSON_CreateArray();
	struct command_table_entry *ct;

	for (ct = pc->cmd_table; ct->name; ct++) {
		cJSON *res = cJSON_CreateObject();
		char uri[128];
		snprintf(uri, sizeof(uri), "%s%s",
			MCP_RESOURCE_PREFIX, ct->name);
		cJSON_AddStringToObject(res, "uri", uri);

		const char *desc = mcp_tool_desc(ct->name);
		if (desc)
			cJSON_AddStringToObject(res, "name", desc);
		else
			cJSON_AddStringToObject(res, "name", ct->name);

		cJSON_AddStringToObject(res, "mimeType", "text/plain");
		cJSON_AddItemToArray(resources, res);
	}

	cJSON_AddItemToObject(result, "resources", resources);
	mcp_send_result(id, result);
}

void
mcp_handle_resources_read(int id, const char *uri)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *contents = cJSON_CreateArray();
	const char *prefix = MCP_RESOURCE_PREFIX;
	size_t prefix_len = strlen(prefix);

	if (strncmp(uri, prefix, prefix_len) != 0) {
		mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
			"Unknown resource URI");
		return;
	}

	const char *cmd_name = uri + prefix_len;
	struct command_table_entry *ct = mcp_find_cmd(cmd_name);

	if (!ct || !ct->help_data || !ct->help_data[0]) {
		mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
			"Command not found or has no help data");
		return;
	}

	int i;
	size_t help_len = 0;
	char *help_text;

	for (i = 0; ct->help_data[i]; i++)
		help_len += strlen(ct->help_data[i]) + 1;

	help_text = malloc(help_len + 1);
	if (help_text) {
		help_text[0] = '\0';
		for (i = 0; ct->help_data[i]; i++) {
			strcat(help_text, ct->help_data[i]);
			strcat(help_text, "\n");
		}
	} else {
		help_text = strdup("");
	}

	cJSON *item = cJSON_CreateObject();
	cJSON_AddStringToObject(item, "uri", uri);
	cJSON_AddStringToObject(item, "mimeType", "text/plain");
	cJSON_AddStringToObject(item, "text", help_text);
	cJSON_AddItemToArray(contents, item);

	cJSON_AddItemToObject(result, "contents", contents);
	mcp_send_result(id, result);
	free(help_text);
}

static void
mcp_dispatch(int id, const char *method, cJSON *params)
{
	if (strcmp(method, "initialize") == 0) {
		mcp_handle_initialize(id);
		return;
	}

	if (strcmp(method, "tools/list") == 0) {
		mcp_handle_tools_list(id);
		return;
	}

	if (strcmp(method, "tools/call") == 0) {
		cJSON *name_obj, *args_obj;
		const char *name = NULL;
		const char *args_str = "";

		if (params) {
			name_obj = cJSON_GetObjectItem(params, "name");
			if (name_obj && cJSON_IsString(name_obj))
				name = name_obj->valuestring;

			args_obj = cJSON_GetObjectItem(params, "arguments");
			if (args_obj) {
				if (cJSON_IsString(args_obj)) {
					args_str = args_obj->valuestring;
				} else if (cJSON_IsObject(args_obj)) {
					cJSON *args_field =
						cJSON_GetObjectItem(args_obj, "args");
					if (args_field && cJSON_IsString(args_field))
						args_str =
							args_field->valuestring;
				} else if (cJSON_IsArray(args_obj)) {
					int i, last = 0;
					size_t len = 0;
					cJSON *item;
					cJSON_ArrayForEach(item, args_obj) {
						if (cJSON_IsString(item))
							len += strlen(item->valuestring)
								+ 1;
					}
					if (len > 0) {
						static char args_buf[BUFSIZE];
						args_buf[0] = '\0';
						cJSON_ArrayForEach(
							item, args_obj) {
							if (cJSON_IsString(item)) {
								if (last)
									strcat(args_buf,
										" ");
								strcat(args_buf,
									item->valuestring);
								last = 1;
							}
						}
						args_str = args_buf;
					}
				}
			}
		}

		if (!name) {
			mcp_send_error(id, MCP_ERR_INVALID_PARAMS,
				"Missing tool name");
			return;
		}

		mcp_handle_tools_call(id, name, args_str);
		return;
	}

	if (strcmp(method, "shutdown") == 0) {
		mcp_handle_shutdown(id);
		clean_exit(0);
		return;
	}

	if (strcmp(method, "resources/list") == 0) {
		mcp_handle_resources_list(id);
		return;
	}

	if (strcmp(method, "resources/read") == 0) {
		const char *uri = "";
		if (params) {
			cJSON *uri_obj = cJSON_GetObjectItem(params, "uri");
			if (uri_obj && cJSON_IsString(uri_obj))
				uri = uri_obj->valuestring;
		}
		mcp_handle_resources_read(id, uri);
		return;
	}

	mcp_send_error(id, MCP_ERR_METHOD_NOT_FOUND, "Method not found");
}

static int
mcp_create_socket(const char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "MCP: socket() failed: %s\n", strerror(errno));
		return -1;
	}

	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "MCP: bind(%s) failed: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}

	chmod(path, 0600);

	if (listen(fd, 1) < 0) {
		fprintf(stderr, "MCP: listen() failed: %s\n", strerror(errno));
		close(fd);
		unlink(path);
		return -1;
	}

	return fd;
}

static volatile sig_atomic_t mcp_interrupted;
static const char *mcp_active_sock_path;

static void
mcp_cleanup(void)
{
	if (mcp_active_sock_path)
		unlink(mcp_active_sock_path);
}

static void
mcp_sigint_handler(int sig)
{
	mcp_interrupted = 1;
}

static void
mcp_set_sigint_default(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(SIGINT, &sa, NULL);
}

static void
mcp_set_sigint_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = mcp_sigint_handler;
	mcp_interrupted = 0;
	sigaction(SIGINT, &sa, NULL);
}

static int
mcp_accept_client(int listen_fd, const char *sock_path)
{
	while (1) {
		mcp_client_fd = accept(listen_fd, NULL, NULL);
		if (mcp_client_fd >= 0)
			return 0;
		if (errno == EINTR) {
			if (mcp_interrupted) {
				fprintf(stderr, "\nMCP: interrupted.\n");
				return -1;
			}
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		fprintf(stderr, "MCP: accept() failed: %s\n",
			strerror(errno));
		return -1;
	}
}

void
mcp_server_loop(void)
{
	char *buf;
	const char *sock_path;
	int listen_fd = -1;
	int force_socket = 0;

	sock_path = getenv("CRASH_MCP_SOCKET");
	if (sock_path) {
		force_socket = 1;
	} else {
		sock_path = "/tmp/crash.sock";
	}

	if (force_socket || isatty(STDOUT_FILENO)) {
		listen_fd = mcp_create_socket(sock_path);
		if (listen_fd >= 0) {
			mcp_use_socket = 1;
			mcp_active_sock_path = sock_path;
			atexit(mcp_cleanup);
			fprintf(stderr,
				"crash MCP server ready.\n"
				"  socket: %s\n"
				"  waiting for client... (Ctrl+C to exit)\n",
				sock_path);
			fflush(stderr);
			mcp_set_sigint_handler();
			if (mcp_accept_client(listen_fd, sock_path) < 0) {
				close(listen_fd);
				mcp_cleanup();
				clean_exit(1);
			}
			close(listen_fd);
			fprintf(stderr, "MCP: client connected.\n");
			fflush(stderr);
		}
	}

	buf = malloc(MCP_MAX_INPUT_SIZE + 1);
	if (!buf) {
		fprintf(stderr, "MCP: failed to allocate input buffer\n");
		mcp_cleanup();
		clean_exit(1);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_DFL);
	mcp_set_sigint_default();

	pc->flags &= ~READLINE;
	pc->scroll_command = SCROLL_NONE;

	mcp_call_count = 0;

	for (;;) {
		if (mcp_use_socket && mcp_client_fd < 0) {
			/*
			 * Listen fd is already closed after first accept.
			 * Re-create socket for subsequent clients.
			 */
			listen_fd = mcp_create_socket(sock_path);
			if (listen_fd < 0) {
				mcp_cleanup();
				clean_exit(1);
			}
			fprintf(stderr,
				"MCP: waiting for client... (Ctrl+C to exit)\n");
			fflush(stderr);
			mcp_set_sigint_handler();
			if (mcp_accept_client(listen_fd, sock_path) < 0) {
				close(listen_fd);
				mcp_cleanup();
				clean_exit(1);
			}
			close(listen_fd);
			fprintf(stderr, "MCP: client connected.\n");
			fflush(stderr);
		}

		while (1) {
			int n;
			cJSON *root;
			cJSON *method_obj, *id_obj, *params_obj;
			const char *method;
			int req_id = 0;

			if (setjmp(pc->main_loop_env)) {
				char *output;
				size_t output_len;
				cJSON *result, *content, *text_item;

				mcp_capture_cleanup();
				mcp_capture_transfer(&output, &output_len);
				if (!output)
					output = strdup(
						"Command restarted unexpectedly");

				result = cJSON_CreateObject();
				content = cJSON_CreateArray();
				text_item = cJSON_CreateObject();
				cJSON_AddStringToObject(text_item,
					"type", "text");
				cJSON_AddStringToObject(text_item,
					"text", output);
				cJSON_AddItemToArray(content, text_item);
				cJSON_AddItemToObject(result,
					"content", content);
				cJSON_AddBoolToObject(result, "isError", 1);

				mcp_send_result(req_id, result);
				free(output);
				continue;
			}

			n = mcp_read_request(buf, MCP_MAX_INPUT_SIZE + 1);
			if (n <= 0) {
				if (mcp_use_socket) {
					close(mcp_client_fd);
					mcp_client_fd = -1;
				}
				break;
			}

			if (strlen(buf) == 0)
				continue;

			if (strlen(buf) > MCP_MAX_INPUT_SIZE) {
				mcp_send_error(0, MCP_ERR_PARSE_ERROR,
					"Request too large");
				continue;
			}

			root = cJSON_Parse(buf);
			if (!root) {
				mcp_send_error(0, MCP_ERR_PARSE_ERROR,
					"Invalid JSON");
				continue;
			}

			method_obj = cJSON_GetObjectItem(root, "method");
			id_obj = cJSON_GetObjectItem(root, "id");
			params_obj = cJSON_GetObjectItem(root, "params");

			if (!method_obj || !cJSON_IsString(method_obj)) {
				if (!id_obj) {
					cJSON_Delete(root);
					continue;
				}
				mcp_send_error(id_obj->valueint,
					MCP_ERR_INVALID_REQUEST,
					"Missing or invalid method");
				cJSON_Delete(root);
				continue;
			}

			method = method_obj->valuestring;
			if (id_obj && cJSON_IsNumber(id_obj))
				req_id = id_obj->valueint;

			if (!id_obj &&
			    strncmp(method, "notifications/", 14) == 0) {
				cJSON_Delete(root);
				continue;
			}

			mcp_dispatch(req_id, method, params_obj);
			cJSON_Delete(root);
		}

		if (!mcp_use_socket)
			break;
	}

	free(buf);
	if (mcp_use_socket && sock_path)
		unlink(sock_path);
	clean_exit(0);
}

#endif /* MCP */
