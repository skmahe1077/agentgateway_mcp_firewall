"""
MCP Tool Firewall Proxy

An aiohttp-based proxy that sits between agents and MCP servers,
intercepting tools/list responses and scanning for poisoning attacks.
Designed to work behind agentgateway as the content security layer
in a defense-in-depth architecture.

Features:
- Inbound: scans tools/list responses, blocks poisoned tool descriptions
- Outbound: scans tools/call responses for secrets, PII, data leaks
- Policy engine: YAML-driven allowlists, blocklists, server trust levels
- agentgateway integration: reads forwarded identity headers, enforces gateway-only access
- Kill switch: emergency deny-all mode
- Metrics: Prometheus-compatible /metrics endpoint
- Admin API: /admin/status, /admin/kill-switch
"""

import argparse
import json
import logging
import os
import time
import uuid
from ipaddress import ip_address, ip_network
from typing import List, Optional

import yaml
from aiohttp import web, ClientSession

from .scanner import ToolScanner
from .reporter import AuditReporter
from .response_scanner import ResponseScanner
from .metrics import MetricsCollector
from .policy import PolicyEngine

logger = logging.getLogger("mcp-firewall")

# Headers forwarded by agentgateway to identify the calling agent/user
AGENTGATEWAY_HEADERS = {
    "user": "X-Agentgateway-User",
    "role": "X-Agentgateway-Role",
    "request_id": "X-Agentgateway-Request-Id",
    "target": "X-Agentgateway-Target",
}


class MCPToolFirewall:
    def __init__(
        self,
        upstream_host: str = "localhost",
        upstream_port: int = 9999,
        block_threshold: int = 51,
        warn_threshold: int = 26,
        log_dir: str = "logs",
        kill_switch: bool = False,
        config_path: Optional[str] = None,
        trusted_gateways: Optional[List[str]] = None,
        enable_semantic: bool = True,
        semantic_api_key: Optional[str] = None,
        semantic_model: str = "claude-haiku-4-5-20251001",
    ):
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        self.scanner = ToolScanner(
            block_threshold=block_threshold,
            warn_threshold=warn_threshold,
            enable_semantic=enable_semantic,
            semantic_api_key=semantic_api_key,
            semantic_model=semantic_model,
        )
        self.reporter = AuditReporter(log_dir=log_dir)
        self.response_scanner = ResponseScanner()
        self.metrics = MetricsCollector()
        self.kill_switch = kill_switch
        self.pending_requests: dict = {}

        # Load policy engine from config file
        self.policy = PolicyEngine()
        if config_path and os.path.exists(config_path):
            self.policy = PolicyEngine.from_yaml_file(config_path)
            logger.info(f"Loaded policy engine from {config_path}")

        # Trusted gateway IPs/CIDRs — only accept traffic from agentgateway
        self.trusted_gateways: List[str] = trusted_gateways or []
        if self.trusted_gateways:
            logger.info(f"Gateway lockdown enabled — trusted sources: {self.trusted_gateways}")

        self.metrics.record_kill_switch(kill_switch)

        # Session management for Streamable HTTP
        self.sessions: dict = {}

        self.app = web.Application()
        self.app.router.add_post("/mcp", self.handle_jsonrpc)
        self.app.router.add_get("/mcp", self.handle_sse_get)
        self.app.router.add_delete("/mcp", self.handle_session_delete)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/metrics", self.handle_metrics)
        self.app.router.add_get("/admin/status", self.handle_admin_status)
        self.app.router.add_post("/admin/kill-switch", self.handle_kill_switch)

    def _extract_gateway_identity(self, request: web.Request) -> dict:
        """Extract agentgateway-forwarded identity headers from the request."""
        identity = {}
        for key, header in AGENTGATEWAY_HEADERS.items():
            value = request.headers.get(header)
            if value:
                identity[key] = value
        return identity

    def _is_trusted_source(self, request: web.Request) -> bool:
        """Check if the request originates from a trusted agentgateway instance."""
        if not self.trusted_gateways:
            return True  # No lockdown configured

        peername = request.transport.get_extra_info("peername")
        if not peername:
            return False
        client_ip = peername[0]

        for trusted in self.trusted_gateways:
            try:
                if "/" in trusted:
                    if ip_address(client_ip) in ip_network(trusted, strict=False):
                        return True
                elif client_ip == trusted:
                    return True
            except ValueError:
                continue
        return False

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "kill_switch": self.kill_switch,
            "gateway_lockdown": len(self.trusted_gateways) > 0,
            "policy_engine": {
                "blocklist_rules": len(self.policy.blocklist),
                "allowlist_rules": len(self.policy.allowlist),
                "server_trust_rules": len(self.policy.server_trust),
            },
        })

    async def handle_metrics(self, request: web.Request) -> web.Response:
        return web.Response(
            text=self.metrics.generate_metrics(),
            content_type="text/plain",
            charset="utf-8",
        )

    async def handle_admin_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "kill_switch": self.kill_switch,
            "upstream": self.upstream_url,
            "stats": self.reporter.get_stats(),
            "response_scanner_stats": self.response_scanner.get_stats(),
        })

    async def handle_kill_switch(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            enabled = body.get("enabled", False)
            self.kill_switch = bool(enabled)
            self.metrics.record_kill_switch(self.kill_switch)
            logger.warning(f"Kill switch {'ENABLED' if self.kill_switch else 'DISABLED'}")
            return web.json_response({
                "kill_switch": self.kill_switch,
                "message": f"Kill switch {'enabled — all tools blocked' if self.kill_switch else 'disabled — normal operation resumed'}",
            })
        except Exception as e:
            return web.json_response(
                {"error": str(e)}, status=400
            )

    def _wants_sse(self, request: web.Request) -> bool:
        """Check if client accepts SSE (Streamable HTTP MCP)."""
        accept = request.headers.get("Accept", "")
        return "text/event-stream" in accept

    def _sse_response(self, data: dict, session_id: str = None) -> web.Response:
        """Return a Server-Sent Events formatted response."""
        body = f"data: {json.dumps(data)}\n\n"
        headers = {"Content-Type": "text/event-stream", "Cache-Control": "no-cache"}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return web.Response(text=body, headers=headers)

    def _json_or_sse(self, data: dict, request: web.Request, session_id: str = None) -> web.Response:
        """Return SSE if client accepts it, otherwise plain JSON."""
        if self._wants_sse(request):
            return self._sse_response(data, session_id)
        resp = web.json_response(data)
        if session_id:
            resp.headers["Mcp-Session-Id"] = session_id
        return resp

    async def handle_sse_get(self, request: web.Request) -> web.Response:
        """Handle GET /mcp for SSE stream establishment."""
        session_id = request.headers.get("Mcp-Session-Id")
        if not session_id or session_id not in self.sessions:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32001, "message": "Invalid or missing session"}, "id": None},
                status=400,
            )
        return web.Response(
            text="data: {}\n\n",
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Mcp-Session-Id": session_id},
        )

    async def handle_session_delete(self, request: web.Request) -> web.Response:
        """Handle DELETE /mcp to close a session."""
        session_id = request.headers.get("Mcp-Session-Id")
        if session_id and session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Session closed: {session_id}")
        return web.Response(status=204)

    async def handle_jsonrpc(self, request: web.Request) -> web.Response:
        try:
            # Enforce gateway lockdown — reject traffic not from agentgateway
            if not self._is_trusted_source(request):
                logger.warning(
                    f"Rejected request from untrusted source: "
                    f"{request.transport.get_extra_info('peername')}"
                )
                return self._json_or_sse(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32001,
                            "message": "Forbidden: traffic must route through agentgateway",
                        },
                        "id": None,
                    },
                    request,
                )

            # Extract agentgateway-forwarded identity
            gateway_identity = self._extract_gateway_identity(request)
            if gateway_identity:
                logger.info(
                    f"Request from agentgateway — user={gateway_identity.get('user', 'unknown')}, "
                    f"role={gateway_identity.get('role', 'unknown')}, "
                    f"request_id={gateway_identity.get('request_id', 'none')}"
                )

            body = await request.read()
            req_data = json.loads(body)

            req_id = req_data.get("id")
            method = req_data.get("method", "")

            # Session management for Streamable HTTP
            session_id = request.headers.get("Mcp-Session-Id")

            if method == "initialize":
                session_id = str(uuid.uuid4())
                self.sessions[session_id] = {"created": time.time()}
                logger.info(f"New MCP session: {session_id}")
            elif session_id and session_id not in self.sessions:
                return self._json_or_sse(
                    {"jsonrpc": "2.0", "error": {"code": -32001, "message": "Unknown session"}, "id": req_id},
                    request,
                )

            if req_id is not None:
                self.pending_requests[req_id] = method

            async with ClientSession() as session:
                async with session.post(
                    f"{self.upstream_url}/mcp",
                    data=body,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    resp_body = await resp.read()
                    resp_data = json.loads(resp_body)

            inspected = self._inspect_message(
                req_id, method, resp_data, gateway_identity
            )

            if req_id is not None:
                self.pending_requests.pop(req_id, None)

            return self._json_or_sse(inspected, request, session_id)

        except json.JSONDecodeError:
            return self._json_or_sse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                request,
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return self._json_or_sse(
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": None},
                request,
            )

    def _inspect_message(
        self, req_id, method: str, resp_data: dict, gateway_identity: dict = None
    ) -> dict:
        stored_method = self.pending_requests.get(req_id, method)

        # Handle tools/list — inbound scanning
        if stored_method == "tools/list":
            return self._inspect_tools_list(resp_data, gateway_identity or {})

        # Handle tools/call — outbound response scanning
        if stored_method == "tools/call":
            return self._inspect_tool_response(resp_data)

        return resp_data

    def _inspect_tools_list(
        self, resp_data: dict, gateway_identity: dict = None
    ) -> dict:
        result = resp_data.get("result", {})
        tools = result.get("tools", None)

        if tools is None:
            return resp_data

        # Kill switch: block everything
        if self.kill_switch:
            resp_data["result"]["tools"] = []
            resp_data["result"]["_firewall"] = {
                "kill_switch": True,
                "tools_blocked": len(tools),
                "message": "Kill switch active — all tools blocked",
            }
            return resp_data

        start = time.time()
        server_name = (
            (gateway_identity or {}).get("target")
            or f"upstream-{self.upstream_url}"
        )

        # Apply policy engine BEFORE scanning
        policy_blocked = []
        policy_allowed = []
        tools_to_scan = []

        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            decision = self.policy.evaluate(
                tool_name=name,
                server_name=server_name,
                description=desc,
            )
            if decision.action == "block":
                policy_blocked.append({"tool": name, "reason": decision.reason})
                self.metrics.record_policy_override()
                logger.info(f"Policy BLOCKED tool '{name}': {decision.reason}")
            elif decision.action == "allow":
                policy_allowed.append(name)
                self.metrics.record_policy_override()
                logger.info(f"Policy ALLOWED tool '{name}': {decision.reason}")
                tools_to_scan.append(tool)  # keep but skip scanning
            else:
                tools_to_scan.append(tool)

        # Scan remaining tools with the detection engine
        filtered_tools, report = self.scanner.filter_tools_list(
            server_name, tools_to_scan
        )
        duration = time.time() - start

        # Re-add policy-allowed tools that the scanner may have blocked
        allowed_set = set(policy_allowed)
        scanner_blocked = {r.tool_name for r in report.results if r.blocked}
        for tool in tools_to_scan:
            name = tool.get("name", "unknown")
            if name in allowed_set and name in scanner_blocked:
                filtered_tools.append(tool)
                logger.info(f"Policy override: allowing '{name}' despite scanner block")

        self.reporter.log_scan(report, gateway_identity=gateway_identity)

        # Record metrics
        self.metrics.record_scan(
            total_tools=report.total_tools + len(policy_blocked),
            blocked=report.tools_blocked + len(policy_blocked),
            warned=report.tools_warned,
            safe=report.tools_safe,
        )
        self.metrics.record_scan_duration(duration)
        for r in report.results:
            self.metrics.record_risk_score(r.risk_score)
            for d in r.detections:
                if d.matched:
                    self.metrics.record_detection(d.pattern_name)

        resp_data["result"]["tools"] = filtered_tools

        total_blocked = report.tools_blocked + len(policy_blocked)
        if total_blocked > 0:
            resp_data["result"]["_firewall"] = {
                "tools_blocked": total_blocked,
                "tools_warned": report.tools_warned,
                "max_risk_score": report.max_risk_score,
                "blocked_tools": (
                    [r.tool_name for r in report.results if r.blocked]
                    + [p["tool"] for p in policy_blocked]
                ),
                "policy_blocked": policy_blocked,
            }

        # Include agentgateway identity in firewall metadata
        if gateway_identity:
            resp_data["result"].setdefault("_firewall", {})
            resp_data["result"]["_firewall"]["gateway_identity"] = gateway_identity

        return resp_data

    def _inspect_tool_response(self, resp_data: dict) -> dict:
        """Scan tool call responses for secrets, PII, and data leaks."""
        result = resp_data.get("result", {})
        content_list = result.get("content", [])

        for item in content_list:
            if item.get("type") != "text":
                continue

            text = item.get("text", "")
            if not text:
                continue

            scan_result = self.response_scanner.scan_response(text)

            if scan_result.findings:
                # Record metrics for response findings
                for finding in scan_result.findings:
                    self.metrics.record_response_finding(finding.finding_type)

                # Add firewall metadata about findings
                if "_firewall_response" not in resp_data.get("result", {}):
                    resp_data.setdefault("result", {})["_firewall_response"] = {
                        "findings_count": len(scan_result.findings),
                        "risk_level": scan_result.risk_level,
                        "findings": [f.to_dict() for f in scan_result.findings],
                    }

                # If critical, redact the sensitive content
                if scan_result.should_redact:
                    for finding in scan_result.findings:
                        if finding.severity >= 80 and finding.evidence:
                            text = text.replace(
                                finding.evidence,
                                f"[REDACTED:{finding.finding_type}]"
                            )
                    item["text"] = text

        return resp_data


def main():
    parser = argparse.ArgumentParser(description="MCP Tool Poisoning Firewall")
    parser.add_argument("--port", type=int, default=8888, help="Firewall proxy port")
    parser.add_argument("--upstream-host", default="localhost", help="Upstream MCP server host")
    parser.add_argument("--upstream-port", type=int, default=9999, help="Upstream MCP server port")
    parser.add_argument("--block-threshold", type=int, default=51, help="Risk score threshold for blocking")
    parser.add_argument("--warn-threshold", type=int, default=26, help="Risk score threshold for warnings")
    parser.add_argument("--log-dir", default="logs", help="Directory for audit logs")
    parser.add_argument("--kill-switch", action="store_true", help="Start with kill switch enabled")
    parser.add_argument("--config", default=None, help="Path to firewall config YAML (policy engine)")
    parser.add_argument(
        "--trusted-gateways",
        default=None,
        help="Comma-separated IPs/CIDRs of trusted agentgateway instances (e.g. 10.0.0.5,10.96.0.0/16)",
    )
    parser.add_argument(
        "--enable-semantic",
        action="store_true",
        default=True,
        help="Enable LLM-based semantic analysis (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--disable-semantic",
        action="store_true",
        default=False,
        help="Disable LLM-based semantic analysis",
    )
    parser.add_argument(
        "--semantic-model",
        default="claude-haiku-4-5-20251001",
        help="Model for semantic analysis (default: claude-haiku-4-5-20251001)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    trusted = (
        [g.strip() for g in args.trusted_gateways.split(",") if g.strip()]
        if args.trusted_gateways
        else []
    )

    enable_semantic = args.enable_semantic and not args.disable_semantic

    firewall = MCPToolFirewall(
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        block_threshold=args.block_threshold,
        warn_threshold=args.warn_threshold,
        log_dir=args.log_dir,
        kill_switch=args.kill_switch,
        config_path=args.config,
        trusted_gateways=trusted,
        enable_semantic=enable_semantic,
        semantic_model=args.semantic_model,
    )

    semantic_status = "enabled" if (firewall.scanner.semantic_detector and firewall.scanner.semantic_detector.is_available) else "disabled"

    print(f"MCP Tool Firewall starting on port {args.port}")
    print(f"Upstream: {firewall.upstream_url}")
    print(f"Block threshold: {args.block_threshold}, Warn threshold: {args.warn_threshold}")
    print(f"Kill switch: {'ENABLED' if args.kill_switch else 'disabled'}")
    print(f"Semantic analysis: {semantic_status} (model: {args.semantic_model})")
    print(f"Policy engine: {'loaded from ' + args.config if args.config else 'default (no config)'}")
    print(f"Gateway lockdown: {trusted if trusted else 'disabled (accepting all sources)'}")
    print(f"Endpoints: /mcp (proxy), /health, /metrics, /admin/status, /admin/kill-switch")

    web.run_app(firewall.app, port=args.port)


if __name__ == "__main__":
    main()
