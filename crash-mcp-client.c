/*
 * crash-mcp-client - MCP client bridge for crash utility
 *
 * Usage: crash-mcp-client [SOCKET_PATH]
 *
 * Connects to a crash MCP server via Unix domain socket,
 * then bridges stdio to the socket for JSON-RPC communication.
 *
 * Default socket: /tmp/crash.sock
 * Override with: CRASH_MCP_SOCKET environment variable
 *                or first command-line argument
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <poll.h>

#define BUF_SIZE (1024 * 1024)

static int
connect_socket(const char *path)
{
	int fd;
	struct sockaddr_un addr;
	int retries = 30;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "crash-mcp-client: socket() failed: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	while (retries-- > 0) {
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
			return fd;

		if (errno != ECONNREFUSED && errno != ENOENT) {
			fprintf(stderr,
				"crash-mcp-client: connect(%s) failed: %s\n",
				path, strerror(errno));
			close(fd);
			return -1;
		}

		usleep(100000);
	}

	fprintf(stderr,
		"crash-mcp-client: connect(%s) failed after retries: %s\n",
		path, strerror(errno));
	close(fd);
	return -1;
}

static int
bridge(int sock_fd)
{
	char *buf;
	struct pollfd fds[2];
	int nfds = 2;

	buf = malloc(BUF_SIZE);
	if (!buf) {
		fprintf(stderr, "crash-mcp-client: out of memory\n");
		return 1;
	}

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[1].fd = sock_fd;
	fds[1].events = POLLIN;

	while (1) {
		int ret = poll(fds, nfds, 5000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		if (ret == 0) {
			if (nfds == 1)
				break;
			continue;
		}

		if (fds[0].revents & POLLIN) {
			ssize_t n = read(STDIN_FILENO, buf, BUF_SIZE);
			if (n <= 0)
				break;
			ssize_t written = 0;
			while (written < n) {
				ssize_t w = write(sock_fd, buf + written, n - written);
				if (w < 0) {
					if (errno == EINTR)
						continue;
					goto out;
				}
				written += w;
			}
		}

		if (fds[0].revents & (POLLHUP | POLLERR)) {
			/*
			 * stdin EOF — stop polling it, but keep draining
			 * socket responses until the server closes.
			 */
			fds[0].fd = -1;
			nfds = 1;
		}

		if (fds[1].revents & POLLIN) {
			ssize_t n = read(sock_fd, buf, BUF_SIZE);
			if (n <= 0)
				break;
			ssize_t written = 0;
			while (written < n) {
				ssize_t w = write(STDOUT_FILENO, buf + written, n - written);
				if (w < 0) {
					if (errno == EINTR)
						continue;
					goto out;
				}
				written += w;
			}
		}

		if (fds[1].revents & (POLLHUP | POLLERR))
			break;
	}

out:
	free(buf);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *sock_path;
	int sock_fd;

	sock_path = getenv("CRASH_MCP_SOCKET");
	if (!sock_path) {
		if (argc > 1)
			sock_path = argv[1];
		else
			sock_path = "/tmp/crash.sock";
	}

	sock_fd = connect_socket(sock_path);
	if (sock_fd < 0)
		return 1;

	return bridge(sock_fd);
}
