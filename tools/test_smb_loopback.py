#!/usr/bin/env python3
"""Optional SMB interoperability test; requires Python impacket and Go.

Only binds loopback ephemeral ports. Uses synthetic credentials and a temporary
share root, never the user's SMB configuration or an external server.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def serve(root: Path, partial: bool) -> None:
    from impacket import smbserver
    from impacket import smb3structs as smb2
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket.dcerpc.v5 import srvs
    from impacket.dcerpc.v5.rpcrt import DCERPCServer, MSRPCRespHeader

    trace = []

    def enumerate_page(server, data):
        request = srvs.NetrShareEnum(data)
        assert request["InfoStruct"]["Level"] == 1
        assert request["PreferedMaximumLength"] == 0xFFFFFFFF
        resume = request["ResumeHandle"]
        trace.append(resume)
        (root / "trace.json").write_text(json.dumps(trace))
        entries = list(server._shares.items())
        selected = entries[resume:resume + 40]
        response = srvs.NetrShareEnumResponse()
        response["InfoStruct"]["Level"] = 1
        response["InfoStruct"]["ShareInfo"]["tag"] = 1
        response["TotalEntries"] = len(entries)
        if partial and resume:
            selected = []
            response["ErrorCode"] = 5
            response["ResumeHandle"] = 0
        else:
            more = resume + len(selected) < len(entries)
            response["ErrorCode"] = 234 if more else 0
            response["ResumeHandle"] = resume + len(selected) if more else 0
        response["InfoStruct"]["ShareInfo"]["Level1"]["EntriesRead"] = len(selected)
        for name, details in selected:
            share = srvs.SHARE_INFO_1()
            share["shi1_netname"] = name + "\0"
            share["shi1_type"] = int(details["share type"])
            # Large pages force DCE/RPC fragmentation in the independent server.
            share["shi1_remark"] = ("Fixture comment " * 12) + "\0"
            response["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"].append(share)
        return response.getData()

    def send_fragments(server, response):
        # This Impacket server's default fragmenter keeps the whole response's
        # frag_len on each fragment. Supply valid framing; NDR and SMB remain
        # independently encoded by Impacket.
        payload = response["pduData"]
        limit = min(4280, server._max_xmit_size) - 24
        for offset in range(0, len(payload), limit):
            chunk = payload[offset:offset + limit]
            fragment = MSRPCRespHeader()
            fragment["type"] = response["type"]
            fragment["call_id"] = response["call_id"]
            fragment["ctx_id"] = response["ctx_id"]
            fragment["alloc_hint"] = len(payload) - offset
            fragment["flags"] = (1 if offset == 0 else 0) | (2 if offset + len(chunk) == len(payload) else 0)
            fragment["pduData"] = chunk
            fragment["frag_len"] = 24 + len(chunk)
            server._clientSock.sendall(fragment.get_packet())
        server._callid += 1

    smbserver.SRVSServer.NetrShareEnum = enumerate_page
    DCERPCServer.send = send_fragments
    server = smbserver.SimpleSMBServer(listenAddress="127.0.0.1", listenPort=0)
    server.setSMB2Support(True)
    faults = {"srvsvcOpens": 0, "nonFileTreeConnects": []}
    non_file_shares = {"OFFICE-PRINTER", "LEGACY-DEVICE", "SERVICE-PIPE"}

    def save_faults():
        (root / "faults.json").write_text(json.dumps(faults))

    def create_with_busy_pipe(conn_id, smb_server, packet):
        request = smb2.SMB2Create(packet["Data"])
        name = request["Buffer"][:request["NameLength"]].decode("utf-16le").strip("\\").lower()
        if name == "srvsvc":
            faults["srvsvcOpens"] += 1
            save_faults()
            if faults["srvsvcOpens"] < 4:
                return [smb2.SMB2Error()], None, 0xC00000AC  # STATUS_PIPE_NOT_AVAILABLE
        return original_create(conn_id, smb_server, packet)

    def trace_tree_connect(conn_id, smb_server, packet):
        request = smb2.SMB2TreeConnect(packet["Data"])
        path = packet.getData()[request["PathOffset"]:][:request["PathLength"]].decode("utf-16le")
        if path.split("\\")[-1].upper() in non_file_shares:
            faults["nonFileTreeConnects"].append(path)
            save_faults()
        return original_tree_connect(conn_id, smb_server, packet)

    original_create = server.getServer().hookSmb2Command(smb2.SMB2_CREATE, create_with_busy_pipe)
    original_tree_connect = server.getServer().hookSmb2Command(smb2.SMB2_TREE_CONNECT, trace_tree_connect)
    server.addCredential("tknet-fixture", 0, compute_lmhash("fixture-only-password"),
                         compute_nthash("fixture-only-password"))
    data = root / "data"
    data.mkdir()
    (data / "keep.txt").write_text("untouched fixture")
    empty = root / "empty"
    empty.mkdir()
    for index in range(128):
        server.addShare(f"SHARE-{index:03}", str(data), shareType=str(0x0E000000 if index == 127 else 0))
    server.addShare("HIDDEN$", str(data), shareType=str(0x80000000))
    server.addShare("資料", str(data))
    server.addShare("EMPTY", str(empty))
    for name, resource_type in [("OFFICE-PRINTER", 1), ("LEGACY-DEVICE", 2), ("SERVICE-PIPE", 3)]:
        server.addShare(name, str(data), shareType=str(resource_type))
    port_file = root / "port.tmp"
    port_file.write_text(str(server.getServer().server_address[1]))
    port_file.replace(root / "port")
    server.start()


def run() -> None:
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="tknet-smb-loopback-") as directory:
        workspace = Path(directory)
        binary = workspace / ("scanner.test.exe" if os.name == "nt" else "scanner.test")
        # A cold race build can take longer than the SMB exchange itself.
        subprocess.run([os.getenv("GO_BIN", "go"), "test", "-race", "-c", "-o", str(binary), "./scanner"],
                       cwd=repo, check=True)
        for partial in (False, True):
            root = workspace / ("partial" if partial else "full")
            root.mkdir()
            with (root / "server.log").open("w") as log:
                server = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), "--serve", str(root), str(int(partial))],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 10
                    while not (root / "port").exists():
                        if server.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("fixture startup failed: " + (root / "server.log").read_text())
                        time.sleep(0.05)
                    env = dict(os.environ, TKNET_TEST_SMB_ADDRESS="127.0.0.1:" + (root / "port").read_text(),
                               TKNET_TEST_SMB_PARTIAL=str(int(partial)))
                    try:
                        subprocess.run([str(binary), "-test.run=^TestSMBLoopbackInteroperability$", "-test.v"],
                                       cwd=repo / "scanner", env=env, timeout=100, check=True)
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        print((root / "server.log").read_text(), file=sys.stderr)
                        raise
                    expected = [0, 40] if partial else [0, 40, 80, 120]
                    assert json.loads((root / "trace.json").read_text()) == expected
                    assert json.loads((root / "faults.json").read_text()) == {"srvsvcOpens": 4, "nonFileTreeConnects": []}
                    assert [p.name for p in (root / "data").iterdir()] == ["keep.txt"]
                    assert (root / "data" / "keep.txt").read_text() == "untouched fixture"
                    assert not list((root / "empty").iterdir())
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
    print("PASS: full/partial SMB2 + NTLM; busy pipe recovered in one session; non-file shares retained without file probes; temporary files cleaned")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--serve":
        serve(Path(sys.argv[2]), sys.argv[3] == "1")
    else:
        run()
