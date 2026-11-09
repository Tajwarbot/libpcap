/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The rpcapd interface-list reply packs rpcap_sockaddr structures right
 * after variable-length interface names and descriptions, so the output
 * address is not always suitably aligned for an rpcap_sockaddr.  Exercise
 * daemon_seraddr() with a deliberately unaligned destination and check the
 * resulting bytes.
 */

#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "rpcapd/daemon.c"

void
rpcapd_log(log_priority priority _U_, const char *message _U_, ...)
{
}

static int
check_ipv4(void)
{
	char buf[256];
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)&ss;
	struct rpcap_sockaddr_in out;
	int i;

	memset(buf, 0xAA, sizeof(buf));
	memset(&ss, 0, sizeof(ss));
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(0x7f000001);

	daemon_seraddr(&ss, &buf[1]);

	memcpy(&out, &buf[1], sizeof(out));
	if (out.family != htons(RPCAP_AF_INET) ||
	    out.port != 0 ||
	    out.addr != htonl(0x7f000001)) {
		fprintf(stderr, "IPv4 address serialized incorrectly\n");
		return -1;
	}
	if ((unsigned char)buf[0] != 0xAA) {
		fprintf(stderr, "write before the output buffer\n");
		return -1;
	}
	for (i = 1 + (int)sizeof(out); i < 1 + (int)sizeof(struct rpcap_sockaddr); i++) {
		if (buf[i] != 0) {
			fprintf(stderr, "IPv4 address padding not zeroed\n");
			return -1;
		}
	}
	if ((unsigned char)buf[1 + sizeof(struct rpcap_sockaddr)] != 0xAA) {
		fprintf(stderr, "write past the output buffer\n");
		return -1;
	}
	return 0;
}

#ifndef _WIN32
static int
check_ipv6(void)
{
	char buf[256];
	struct sockaddr_storage ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)&ss;
	struct rpcap_sockaddr_in6 out;
	int i;

	memset(buf, 0xAA, sizeof(buf));
	memset(&ss, 0, sizeof(ss));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	sin6->sin6_flowinfo = 7;
	sin6->sin6_scope_id = 9;
	for (i = 0; i < 16; i++)
		sin6->sin6_addr.s6_addr[i] = (unsigned char)i;

	daemon_seraddr(&ss, &buf[1]);

	memcpy(&out, &buf[1], sizeof(out));
	if (out.family != htons(RPCAP_AF_INET6) ||
	    out.port != 0 ||
	    out.flowinfo != htonl(7) ||
	    out.scope_id != htonl(9)) {
		fprintf(stderr, "IPv6 address serialized incorrectly\n");
		return -1;
	}
	for (i = 0; i < 16; i++) {
		if (out.addr[i] != (unsigned char)i) {
			fprintf(stderr, "IPv6 address serialized incorrectly\n");
			return -1;
		}
	}
	return 0;
}
#endif

int
main(void)
{
	if (check_ipv4() == -1)
		return 1;
#ifndef _WIN32
	if (check_ipv6() == -1)
		return 1;
#endif
	printf("daemon_seraddr unaligned output is OK\n");
	return 0;
}
