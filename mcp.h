/*
 * mcp.h - MCP (Model Context Protocol) support for crash utility
 *
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef MCP_H
#define MCP_H

#ifdef MCP

/* JSON-RPC 2.0 error codes */
#define MCP_ERR_PARSE_ERROR         (-32700)
#define MCP_ERR_INVALID_REQUEST     (-32600)
#define MCP_ERR_METHOD_NOT_FOUND    (-32601)
#define MCP_ERR_INVALID_PARAMS      (-32602)
#define MCP_ERR_INTERNAL_ERROR      (-32603)

/* Security configuration */
#define MCP_MAX_INPUT_SIZE          (1024 * 1024)   /* 1MB request limit */
#define MCP_MAX_OUTPUT_SIZE         (1024 * 1024)   /* 1MB output limit */
#define MCP_MAX_TOOL_CALLS          10000           /* max tool calls per session */

/* MCP protocol version */
#define MCP_PROTOCOL_VERSION        "2024-11-05"

/*
 * MCP request structure (parsed from JSON-RPC)
 */
struct mcp_request {
	int id;
	char *method;
	char *tool_name;       /* for tools/call */
	char *tool_args;       /* for tools/call: arguments.args value */
};

/*
 * MCP public API
 */
void mcp_server_loop(void);

/*
 * MCP internal functions (used within mcp_server.c)
 */
int  mcp_read_request(char *buf, unsigned long maxlen);
void mcp_send_response(const char *json_str);
void mcp_send_error(int id, int code, const char *message);

void mcp_handle_initialize(int id);
void mcp_handle_tools_list(int id);
void mcp_handle_tools_call(int id, const char *tool_name, const char *tool_args);
void mcp_handle_shutdown(int id);

#endif /* MCP */
#endif /* MCP_H */
