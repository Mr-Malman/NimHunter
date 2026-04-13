#!/usr/bin/env python3
# scripts/cfg_gin.py — CFG Construction + Graph Isomorphism Network
# NimHunter v2 — Chapter 4.3 / 5.4 implementation
#
# Pipeline:
#   1. Disassemble .text section with capstone
#   2. Build basic-block Control Flow Graph (networkx DiGraph)
#   3. Apply 2-layer GIN aggregation (numpy, no PyTorch needed)
#   4. Detect Nim-specific CFG motifs (NimMain cascade, ORC loops, GC fan-out)
#   5. Return: gin_score (0-15), embedding vector, motifs detected
#
# Usage:
#   .venv/bin/python3.13 scripts/cfg_gin.py <pe_file.exe>

import sys, os, struct, json, hashlib
import numpy as np

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    CAPSTONE_OK = True
except ImportError:
    CAPSTONE_OK = False

try:
    import networkx as nx
    NETWORKX_OK = True
except ImportError:
    NETWORKX_OK = False

# ── PE Parser (minimal — just find .text section) ─────────────────────────────

def get_text_section(pe_bytes: bytes):
    """Extract .text section VA, offset, and raw bytes from a PE file."""
    if len(pe_bytes) < 64 or pe_bytes[:2] != b"MZ":
        return None, None, None

    pe_offset = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_offset + 24 > len(pe_bytes):
        return None, None, None
    if pe_bytes[pe_offset:pe_offset+4] != b"PE\x00\x00":
        return None, None, None

    machine     = struct.unpack_from("<H", pe_bytes, pe_offset + 4)[0]
    num_sections = struct.unpack_from("<H", pe_bytes, pe_offset + 6)[0]
    opt_size    = struct.unpack_from("<H", pe_bytes, pe_offset + 20)[0]
    is_64       = (machine == 0x8664)

    section_offset = pe_offset + 24 + opt_size
    for i in range(num_sections):
        base = section_offset + i * 40
        name    = pe_bytes[base:base+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize   = struct.unpack_from("<I", pe_bytes, base+8)[0]
        va      = struct.unpack_from("<I", pe_bytes, base+12)[0]
        rawsize = struct.unpack_from("<I", pe_bytes, base+16)[0]
        rawoff  = struct.unpack_from("<I", pe_bytes, base+20)[0]
        if ".text" in name or name == ".code":
            data = pe_bytes[rawoff:rawoff+rawsize]
            return va, data, is_64
    return None, None, None


# ── Step 1: Disassemble .text → instruction list ──────────────────────────────

def disassemble(code: bytes, base_va: int, is_64: bool):
    """Disassemble code bytes. Returns list of (addr, mnemonic, op_str, bytes)."""
    if not CAPSTONE_OK:
        return []
    mode = CS_MODE_64 if is_64 else CS_MODE_32
    md   = Cs(CS_ARCH_X86, mode)
    md.detail = True
    return list(md.disasm(code, base_va))


# ── Step 2: Build Control Flow Graph ─────────────────────────────────────────

BRANCH_MNEMONICS = {
    "jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
    "ja", "jb", "jae", "jbe", "js", "jns", "jo", "jno",
    "call", "ret", "retn", "retf",
}

def build_cfg(insns, max_insns=5000) -> "nx.DiGraph | None":
    """
    Build a basic-block CFG from the instruction list.
    Returns a networkx DiGraph where:
      - nodes = basic block start addresses
      - edges = control flow transfers
      - node[addr]['size'] = number of instructions in block
    """
    if not NETWORKX_OK or not insns:
        return None

    # Limit to first N instructions to keep runtime bounded
    insns = insns[:max_insns]

    # 1. Find all block leaders (targets of branches + instructions after branches)
    leaders = set()
    leaders.add(insns[0].address)
    for i, ins in enumerate(insns):
        mn = ins.mnemonic.lower()
        if mn in BRANCH_MNEMONICS:
            # Instruction after a branch starts a new block
            if i + 1 < len(insns):
                leaders.add(insns[i+1].address)
            # Branch target (if immediate operand)
            if ins.op_str and "0x" in ins.op_str:
                try:
                    leaders.add(int(ins.op_str.strip().split()[-1], 16))
                except ValueError:
                    pass

    # 2. Partition into basic blocks
    blocks = {}  # addr → [insn, ...]
    current_block_start = None
    for ins in insns:
        if ins.address in leaders:
            current_block_start = ins.address
            blocks[current_block_start] = []
        if current_block_start is not None:
            blocks[current_block_start].append(ins)

    # 3. Build DiGraph
    G = nx.DiGraph()
    addr_set = set(insns_obj.address for insns_obj in insns)

    for leader, block in blocks.items():
        G.add_node(leader, size=len(block), insn_count=len(block))
        if not block:
            continue
        last = block[-1]
        mn = last.mnemonic.lower()
        if mn.startswith("ret"):
            continue  # Exit block
        if mn == "jmp" or mn in BRANCH_MNEMONICS:
            # Unconditional branch
            if "0x" in last.op_str:
                try:
                    target = int(last.op_str.strip().split()[-1], 16)
                    if target in blocks:
                        G.add_edge(leader, target, kind="branch")
                except ValueError:
                    pass
            # For conditional branches, also fall-through
            if mn != "jmp":
                next_insn_idx = insns.index(next((i for i in insns if i.address == last.address), None))
                if next_insn_idx + 1 < len(insns):
                    fall = insns[next_insn_idx + 1].address
                    if fall in blocks:
                        G.add_edge(leader, fall, kind="fall")
        else:
            # Fall-through to next block
            all_insns_sorted = sorted(insns, key=lambda x: x.address)
            idx = next((j for j, i in enumerate(all_insns_sorted) if i.address == last.address), -1)
            if idx + 1 < len(all_insns_sorted):
                fall = all_insns_sorted[idx + 1].address
                if fall in blocks:
                    G.add_edge(leader, fall, kind="fall")

    return G


# ── Step 3: GIN (Graph Isomorphism Network) — 2 layers, numpy only ───────────

def gin_aggregate(G, feat_dim=16, n_layers=2) -> np.ndarray:
    """
    2-layer GIN aggregation:
      h_v^(k) = MLP( h_v^(k-1) + sum_{u in N(v)} h_u^(k-1) )
    where MLP = ReLU(W @ x + b) with random fixed weights.
    Input features: [in_degree, out_degree, block_size, is_leaf, is_root, ...]
    Returns graph-level sum-pool embedding (feat_dim,).
    """
    if G is None or len(G.nodes) == 0:
        return np.zeros(feat_dim)

    nodes = list(G.nodes)
    n = len(nodes)
    idx = {v: i for i, v in enumerate(nodes)}

    # Node features (5 raw → padded to feat_dim)
    H = np.zeros((n, feat_dim))
    for i, v in enumerate(nodes):
        data = G.nodes[v]
        H[i, 0] = G.in_degree(v)
        H[i, 1] = G.out_degree(v)
        H[i, 2] = data.get("size", 1)
        H[i, 3] = 1.0 if G.in_degree(v) == 0 else 0.0   # is_root
        H[i, 4] = 1.0 if G.out_degree(v) == 0 else 0.0  # is_leaf

    # Fixed random MLP weights (seed = architecture fingerprint)
    rng = np.random.RandomState(42)
    Ws = [rng.randn(feat_dim, feat_dim).astype(np.float32) * 0.1 for _ in range(n_layers)]
    bs = [np.zeros(feat_dim) for _ in range(n_layers)]

    # Adjacency (sparse)
    adj = nx.to_numpy_array(G, nodelist=nodes)

    for k in range(n_layers):
        # Aggregate: h = h + A @ h
        agg = H + adj @ H
        # MLP: ReLU(W @ h.T + b).T
        H = np.maximum(0, (Ws[k] @ agg.T).T + bs[k])

    # Graph-level sum pooling
    return H.sum(axis=0) / max(n, 1)


# ── Step 4: Nim CFG Motif Detection ──────────────────────────────────────────

def detect_nim_motifs(G, insns) -> dict:
    """
    Detect Nim-specific CFG patterns.
    Returns dict with boolean flags and a motif_score.
    """
    motifs = {
        "nimMain_cascade":      False,  # Long linear chain at entry
        "orc_back_edge":        False,  # Back-edges (cycles in GC loop)
        "gc_marker_fan_out":    False,  # Root with many outgoing edges
        "deep_call_chain":      False,  # Chain depth > 10
        "motif_score":          0,
        "node_count":           0,
        "edge_count":           0,
        "cyclomatic_complexity": 0,
    }
    if G is None or len(G.nodes) == 0:
        return motifs

    motifs["node_count"] = len(G.nodes)
    motifs["edge_count"] = len(G.edges)
    # Cyclomatic complexity: E - N + 2P
    motifs["cyclomatic_complexity"] = len(G.edges) - len(G.nodes) + 2

    # 1. NimMain cascade: long linear chain from the first root node
    roots = [n for n in G.nodes if G.in_degree(n) == 0]
    if roots:
        # BFS max chain length from root
        chain_len = 0
        q = [roots[0]]
        visited = set()
        while q:
            node = q.pop(0)
            if node in visited: continue
            visited.add(node)
            chain_len += 1
            succs = list(G.successors(node))
            if len(succs) == 1:
                q.extend(succs)
        if chain_len >= 8:
            motifs["nimMain_cascade"] = True
            motifs["motif_score"] += 5

    # 2. ORC back-edge: cycles exist in CFG
    try:
        cycles = list(nx.simple_cycles(G))
        if cycles:
            motifs["orc_back_edge"] = True
            motifs["motif_score"] += 5
    except Exception:
        pass

    # 3. GC marker fan-out: any node with out-degree > 8
    max_out = max((G.out_degree(n) for n in G.nodes), default=0)
    if max_out >= 6:
        motifs["gc_marker_fan_out"] = True
        motifs["motif_score"] += 3

    # 4. Deep call chain (DAG longest path)
    try:
        dag = nx.DiGraph(G)
        for u, v in list(nx.simple_cycles(G)):
            if dag.has_edge(u, v):
                dag.remove_edge(u, v)
        if nx.is_directed_acyclic_graph(dag):
            lp = nx.dag_longest_path_length(dag)
            if lp >= 10:
                motifs["deep_call_chain"] = True
                motifs["motif_score"] += 2
    except Exception:
        pass

    return motifs


# ── Main ──────────────────────────────────────────────────────────────────────

def analyze_cfg_gin(pe_path: str) -> dict:
    result = {
        "module":         "cfg_gin",
        "gin_score":      0,
        "gin_embedding":  [],
        "motifs":         {},
        "node_count":     0,
        "edge_count":     0,
        "error":          None,
    }

    if not CAPSTONE_OK:
        result["error"] = "capstone not installed — run: .venv/bin/pip install capstone"
        return result
    if not NETWORKX_OK:
        result["error"] = "networkx not installed — run: .venv/bin/pip install networkx"
        return result

    try:
        pe_bytes = open(pe_path, "rb").read()
    except Exception as e:
        result["error"] = str(e)
        return result

    va, text_bytes, is_64 = get_text_section(pe_bytes)
    if text_bytes is None:
        result["error"] = "Could not find .text section"
        return result

    # Limit disassembly to first 64 KB for speed
    insns = disassemble(text_bytes[:65536], va or 0x1000, is_64 or True)
    if not insns:
        result["error"] = "Disassembly produced no instructions"
        return result

    G = build_cfg(insns)
    embedding = gin_aggregate(G)
    motifs = detect_nim_motifs(G, insns)

    result["gin_score"]     = min(motifs["motif_score"], 15)
    result["gin_embedding"] = [round(float(v), 4) for v in embedding]
    result["motifs"]        = motifs
    result["node_count"]    = motifs["node_count"]
    result["edge_count"]    = motifs["edge_count"]

    # Save CFG dot file for visualization in thesis
    if G and len(G.nodes) <= 200:
        import os
        os.makedirs("models", exist_ok=True)
        fname = os.path.splitext(os.path.basename(pe_path))[0]
        dot_path = f"models/cfg_{fname}.dot"
        nx.drawing.nx_pydot.write_dot(G, dot_path)
        result["cfg_dot"] = dot_path

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: .venv/bin/python3.13 scripts/cfg_gin.py <pe_file.exe>")
        sys.exit(1)
    out = analyze_cfg_gin(sys.argv[1])
    print(json.dumps(out, indent=2))
