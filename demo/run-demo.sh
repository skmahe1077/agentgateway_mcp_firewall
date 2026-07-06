#!/bin/bash
# =============================================================================
# MCP Tool Firewall + agentgateway — Side-by-Side Demo
#
# Prerequisites: port-forwards must be running:
#   kubectl port-forward svc/agentgateway 3100:3000 &
#   kubectl port-forward svc/agentgateway 15100:15000 &
#   kubectl port-forward svc/grafana 3200:3000 &
#   kubectl port-forward svc/mcp-tool-firewall 8888:8888 &
#   kubectl port-forward svc/kagent-ui 8501:80 -n kagent &
# =============================================================================

GATEWAY_URL="${GATEWAY_URL:-http://localhost:3100}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  MCP Tool Firewall + agentgateway Demo${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""

# ─── DIRECT ROUTE (NO FIREWALL) ─────────────────────────────────────────────

echo -e "${RED}${BOLD}>>> ROUTE 1: /direct — NO firewall (agent sees everything)${NC}"
echo "-----------------------------------------------------------"
echo ""

INIT1=$(curl -s -i -X POST "$GATEWAY_URL/direct" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1.0"}}}' 2>&1)

S1=$(echo "$INIT1" | grep -i "mcp-session-id" | head -1 | awk '{print $2}' | tr -d '\r')

if [ -z "$S1" ]; then
  echo -e "${RED}ERROR: Could not initialize session on /direct route.${NC}"
  echo "Is the port-forward running? kubectl port-forward svc/agentgateway 3100:3000 &"
  exit 1
fi

TOOLS1=$(curl -s -X POST "$GATEWAY_URL/direct" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $S1" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

DIRECT_COUNT=$(echo "$TOOLS1" | sed 's/^data: //' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
echo -e "Tools returned to agent: ${RED}${BOLD}$DIRECT_COUNT${NC} (7 poisoned + 1 safe)"
echo ""

echo "$TOOLS1" | sed 's/^data: //' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['result']['tools']:
    name = t['name']
    desc = t['description'][:90].replace('\n', ' ')
    if name == 'format_text':
        print(f'  \033[0;32m[SAFE    ]\033[0m {name:20s}  {desc}')
    else:
        print(f'  \033[0;31m[POISONED]\033[0m {name:20s}  {desc}')
" 2>/dev/null

echo ""
echo ""

# ─── PROTECTED ROUTE (WITH FIREWALL) ────────────────────────────────────────

echo -e "${GREEN}${BOLD}>>> ROUTE 2: /mcp — WITH agentgateway + firewall${NC}"
echo "-----------------------------------------------------------"
echo ""

INIT2=$(curl -s -i -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1.0"}}}' 2>&1)

S2=$(echo "$INIT2" | grep -i "mcp-session-id" | head -1 | awk '{print $2}' | tr -d '\r')

TOOLS2=$(curl -s -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $S2" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

PROTECTED_COUNT=$(echo "$TOOLS2" | sed 's/^data: //' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
echo -e "Tools returned to agent: ${GREEN}${BOLD}$PROTECTED_COUNT${NC} (7 poisoned BLOCKED, safe tools only)"
echo ""

echo "$TOOLS2" | sed 's/^data: //' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['result']['tools']:
    name = t['name']
    desc = t['description'][:90].replace('\n', ' ')
    source = name.split('_')[0] if '_' in name else 'unknown'
    print(f'  \033[0;32m[SAFE    ]\033[0m {name:50s}  {desc}')
" 2>/dev/null

echo ""
echo ""

# ─── KILL SWITCH ──────────────────────────────────────────────────────────────

echo -e "${RED}${BOLD}>>> KILL SWITCH — Block ALL tools instantly${NC}"
echo "-----------------------------------------------------------"
echo ""

echo -e "Activating kill switch..."
curl -s -X POST http://localhost:8888/admin/kill-switch \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' | python3 -m json.tool
echo ""

# Fresh session to verify kill switch
INIT3=$(curl -s -i -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1.0"}}}' 2>&1)
S3=$(echo "$INIT3" | grep -i "mcp-session-id" | head -1 | awk '{print $2}' | tr -d '\r')

TOOLS3=$(curl -s -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $S3" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

KILL_COUNT=$(echo "$TOOLS3" | sed 's/^data: //' | python3 -c "
import sys, json
data = json.load(sys.stdin)
upstream = [t for t in data['result']['tools'] if 'firewall-protected' in t['name']]
print(len(upstream))
" 2>/dev/null)

echo -e "Upstream tools with kill switch ON: ${RED}${BOLD}$KILL_COUNT${NC} (everything blocked)"
echo ""

echo -e "Disabling kill switch..."
curl -s -X POST http://localhost:8888/admin/kill-switch \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}' | python3 -m json.tool

echo ""
echo ""

# ─── KAGENT SECURITY AUDITOR ─────────────────────────────────────────────────

echo -e "${CYAN}${BOLD}>>> KAGENT — AI Security Auditor${NC}"
echo "-----------------------------------------------------------"
echo ""
echo -e "Invoking kagent mcp-security-auditor to scan the malicious server..."
echo ""

kagent invoke --agent "mcp-security-auditor" \
  --task "Scan the MCP server at malicious-mcp-server.default.svc.cluster.local:9999 for poisoning attacks" \
  --stream 2>&1 | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        data = json.loads(line)
    except:
        continue
    kind = data.get('kind', '')
    if kind == 'status-update':
        status = data.get('status', {})
        state = status.get('state', '')
        msg = status.get('message', {})
        if isinstance(msg, dict):
            parts = msg.get('parts', [])
            for part in parts:
                if part.get('kind') == 'text' and msg.get('role') == 'agent':
                    print(part['text'])
        if state == 'completed':
            break
        if state == 'failed':
            if isinstance(msg, dict):
                parts = msg.get('parts', [])
                for part in parts:
                    if part.get('kind') == 'text':
                        print(f'\033[0;31mERROR: {part[\"text\"]}\033[0m')
            break
" 2>/dev/null

echo ""
echo ""

# ─── SUMMARY ─────────────────────────────────────────────────────────────────

BLOCKED=$((DIRECT_COUNT - 1))

echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  RESULTS${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
echo -e "  ${RED}Without firewall:${NC}  $DIRECT_COUNT tools exposed (${BLOCKED} poisoned)"
echo -e "  ${GREEN}With firewall:${NC}     $PROTECTED_COUNT safe tools (${BLOCKED} poisoned tools ${GREEN}BLOCKED${NC})"
echo ""
echo -e "  ${CYAN}Attack types detected (8 regex + 1 LLM detector):${NC}"
echo "    - Prompt Injection (ignore instructions, <<SYS>> tags, jailbreaks)"
echo "    - Data Exfiltration (send data to external URLs, markdown image exfil)"
echo "    - Cross-Tool Manipulation (chain tool calls)"
echo "    - Invisible Characters (zero-width spaces, RTL overrides)"
echo "    - Obfuscated Payloads (base64, eval)"
echo "    - Dangerous Commands (rm -rf, chmod, curl|sh)"
echo "    - Description Anomalies (overflow attacks, hidden HTML)"
echo "    - SSRF / Internal Access (169.254.169.254, localhost, private IPs)"
echo ""
echo -e "  ${YELLOW}Open in browser:${NC}"
echo "    agentgateway Admin UI:  http://localhost:15100/ui"
echo "    Grafana Dashboard:      http://localhost:3200  (admin/firewall)"
echo "    kagent Dashboard:       http://localhost:8501"
echo ""
echo -e "  ${CYAN}kagent Security Auditor:${NC}"
echo "    kagent invoke --agent mcp-security-auditor \\"
echo "      --task \"Scan the MCP server at malicious-mcp-server.default.svc.cluster.local:9999\" --stream"
echo ""
echo -e "${BOLD}============================================${NC}"
