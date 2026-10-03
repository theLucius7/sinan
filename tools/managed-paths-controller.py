#!/usr/bin/env python3
"""Fixed operations on three pre-provisioned, owned Linux systemd namespaces.

This controller never provisions machines or mutates a product database. Its
manifest must bind existing dedicated namespaces and TEST_ONLY native artifacts.
Ordinary enrollment and service operations are the only product-side writes.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import sys
import urllib.parse

from managed_paths_support import capture as bounded_capture, identity, load, owned_root, regular, require, within

ROLES = {"A", "M", "B"}
OPERATIONS = {"inspect", "enroll", "agent_stop", "agent_start", "agent_restart", "runtime_restart",
              "panel_stop", "panel_start", "device_snapshot", "panel_evidence", "restore_all", "cleanup"}


def capture(command, **options):
    options.setdefault("env", {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    return bounded_capture(command, **options)


def proc_identity(pid):
    require(isinstance(pid, int) and pid > 1, "namespace_init_pid_invalid")
    root = Path("/proc") / str(pid)
    with (root / "stat").open("rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536, "namespace_proc_stat_limit")
    fields = data.decode().rsplit(")", 1)[1].split()
    return {"starttime": int(fields[19]), "netns_id": (root / "ns/net").stat().st_ino,
            "mountns_id": (root / "ns/mnt").stat().st_ino, "pidns_id": (root / "ns/pid").stat().st_ino}


def role_capture(row, command, timeout=30):
    expected = {key: row[key] for key in ("starttime", "netns_id", "mountns_id", "pidns_id")}
    require(proc_identity(row["init_pid"]) == expected, "namespace_identity_changed")
    descriptors, prefix = [], ["/usr/bin/nsenter"]
    try:
        for kind in ("mnt", "uts", "ipc", "net", "pid"):
            fd = os.open(f"/proc/{row['init_pid']}/ns/{kind}", os.O_RDONLY)
            descriptors.append(fd)
            expected_key = {"mnt": "mountns_id", "net": "netns_id", "pid": "pidns_id"}.get(kind)
            if expected_key:
                require(os.fstat(fd).st_ino == expected[expected_key], "namespace_identity_changed")
            option = "mount" if kind == "mnt" else kind
            prefix.append("--" + option + "=/proc/self/fd/" + str(fd))
        root_fd = os.open(f"/proc/{row['init_pid']}/root", os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(root_fd)
        root_metadata = os.fstat(root_fd)
        require(f"{root_metadata.st_dev}:{root_metadata.st_ino}" == row["filesystem_id"],
                "namespace_root_filesystem_identity_mismatch")
        require(proc_identity(row["init_pid"]) == expected, "namespace_identity_changed")
        prefix.extend(["--root=/proc/self/fd/" + str(root_fd), "--wd=/", "--"])
        return capture(prefix + command, timeout=timeout, pass_fds=tuple(descriptors),
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    finally:
        for fd in descriptors:
            os.close(fd)


def validate_manifest(path):
    manifest = load(path)
    require(manifest.get("schema") == 1 and manifest.get("test_only") is True and
            manifest.get("dedicated") is True and platform.system() == "Linux" and os.geteuid() == 0,
            "root_on_dedicated_linux_required")
    root = owned_root(manifest["run_root"], manifest["run_id"])
    require(set(manifest["roles"]) == ROLES, "three_role_namespaces_required")
    require(manifest["source_identity"].get("frozen_inputs_sha256") and
            manifest["artifacts"].get("test_only") is True, "frozen_test_only_artifacts_required")
    prepared = load(within(root, manifest["artifacts"]["prepared_receipt_file"]))
    require(prepared.get("status") == "prepared" and prepared.get("test_only") is True and
            prepared.get("run_id") == manifest["run_id"] and
            prepared["source_identity"] == manifest["source_identity"] and
            prepared["release"]["official_publication_rejected"] is True,
            "successful_frozen_native_preparation_required")
    for name, row in manifest["artifacts"]["binaries"].items():
        require(name in {"sinan-agent", "sinan-panel"}, "unexpected_product_binary")
        require(identity(within(root, row["path"])) == {"sha256": row["sha256"], "size": row["size"]},
                "native_artifact_changed")
        require(prepared["binaries"][name] == {"sha256": row["sha256"], "size": row["size"]},
                "binary_not_bound_to_prepared_receipt")
    require(set(manifest["artifacts"]["binaries"]) == {"sinan-agent", "sinan-panel"},
            "both_native_binaries_required")
    identities = []
    host = {"netns_id": Path("/proc/self/ns/net").stat().st_ino,
            "mountns_id": Path("/proc/self/ns/mnt").stat().st_ino,
            "pidns_id": Path("/proc/self/ns/pid").stat().st_ino}
    for role, row in manifest["roles"].items():
        actual = proc_identity(row["init_pid"])
        require(actual == {key: row[key] for key in actual}, "namespace_identity_changed")
        require(all(actual[key] != host[key] for key in host), "host_namespace_refused")
        marker = role_capture(row, ["/bin/cat", "/etc/sinan-managed-test-run"], timeout=5)
        require(marker.decode().strip() == manifest["run_id"], "namespace_ownership_mismatch")
        machine_id = role_capture(row, ["/bin/cat", "/etc/machine-id"], timeout=5).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{32}", machine_id) and machine_id == row["systemd_id"],
                "namespace_systemd_identity_mismatch")
        filesystem_id = role_capture(row, ["/usr/bin/stat", "-Lc", "%d:%i", "/"], timeout=5).decode().strip()
        require(re.fullmatch(r"[0-9]+:[0-9]+", filesystem_id) and filesystem_id == row["filesystem_id"],
                "namespace_root_filesystem_identity_mismatch")
        require(row["agent_config"] == "/etc/sinan/agent.toml" and
                row["agent_binary"] == "/opt/sinan/core/current/sinan-agent", "standard_agent_paths_required")
        artifact_hash = manifest["artifacts"]["binaries"]["sinan-agent"]["sha256"]
        copied_hash = role_capture(row, ["/usr/bin/sha256sum", row["agent_binary"]], timeout=10).decode().split()[0]
        require(copied_hash == artifact_hash, "namespace_agent_binary_changed")
        identities.append({"role": role, **actual, "systemd_id": machine_id,
                           "filesystem_id": filesystem_id})
    for key in ("netns_id", "mountns_id", "pidns_id", "systemd_id", "filesystem_id"):
        require(len({row[key] for row in identities}) == 3, "roles_share_service_namespace")
    panel = manifest["panel"]
    require(panel["unit"] == "sinan-managed-panel-" + manifest["run_id"] + ".service",
            "unowned_panel_unit_refused")
    pg = panel["postgres"]
    require(pg["database"] == "sinan_managed_" + manifest["run_id"].replace("-", "") and
            pg["username"] == "postgres" and 1024 <= pg["port"] <= 65535,
            "dedicated_database_required")
    within(root, pg["socket_dir"])
    require(regular(within(root, panel["ownership_file"]), 128).decode().strip() == manifest["run_id"],
            "panel_ownership_mismatch")
    properties = capture(["/bin/systemctl", "show", panel["unit"], "--property=ExecStart",
                          "--property=FragmentPath", "--property=EnvironmentFiles", "--property=MainPID"],
                         timeout=5, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}).decode()
    require("path=" + manifest["artifacts"]["binaries"]["sinan-panel"]["path"] + " ;" in properties,
            "panel_unit_executable_not_bound")
    fragment = next((line.partition("=")[2] for line in properties.splitlines()
                     if line.startswith("FragmentPath=")), "")
    require(fragment == panel["unit_file"] and identity(Path(fragment), 65536)["sha256"] == panel["unit_sha256"],
            "panel_unit_identity_mismatch")
    environment_file = within(root, panel["environment_file"])
    require(identity(environment_file, 65536)["sha256"] == panel["environment_sha256"],
            "panel_environment_identity_mismatch")
    environment_line = next((line.partition("=")[2] for line in properties.splitlines()
                             if line.startswith("EnvironmentFiles=")), "")
    require(environment_line == str(environment_file) + " (ignore_errors=no)",
            "panel_unit_environment_file_not_bound")
    environment = {}
    for line in regular(environment_file, 65536).decode().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        require(separator and re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) and name not in environment and
                value and not any(character.isspace() for character in value) and
                not any(character in value for character in ("'", '"', "\\")),
                "simple_private_environment_file_required")
        environment[name] = value
    validate_panel_environment(environment, panel, root)
    pid = int(next((line.partition("=")[2] for line in properties.splitlines()
                    if line.startswith("MainPID=")), "0"))
    if pid:
        with Path(f"/proc/{pid}/environ").open("rb") as stream:
            data = stream.read(65537)
        require(len(data) <= 65536, "panel_process_environment_budget")
        actual_environment = dict(item.decode().split("=", 1) for item in data.split(b"\0") if b"=" in item)
        validate_panel_environment(actual_environment, panel, root)
    return manifest, identities


def validate_panel_environment(environment, panel, root):
    """Compare private values locally; never put URLs or credentials in facts."""
    pg = panel["postgres"]
    url = urllib.parse.urlsplit(environment.get("SINAN_DATABASE_URL", ""))
    require(url.scheme in {"postgres", "postgresql"} and url.hostname in {"127.0.0.1", "localhost"} and
            url.port == pg["port"] and urllib.parse.unquote(url.path) == "/" + pg["database"] and
            urllib.parse.unquote(url.username or "") == pg["username"] and not url.query and not url.fragment,
            "panel_database_environment_not_owned")
    require(environment.get("SINAN_DATA_DIR") == panel["data_dir"], "panel_data_directory_not_bound")
    within(root, panel["data_dir"])
    origin = urllib.parse.urlsplit(panel["origin"])
    require(origin.scheme == "https" and origin.hostname and not origin.username and not origin.password and
            origin.path in {"", "/"} and not origin.query and not origin.fragment,
            "panel_https_origin_required")
    require(environment.get("SINAN_PUBLIC_URL", "").rstrip("/") == panel["origin"].rstrip("/"),
            "panel_public_origin_not_bound")


DEVICE_SCRIPT = r'''
import base64,json,pathlib,sqlite3,subprocess,tomllib,hashlib
config=tomllib.loads(pathlib.Path('/etc/sinan/agent.toml').read_text())
def unit(name):
    result=subprocess.run(['/bin/systemctl','show',name,'--property=ActiveState','--property=MainPID','--property=ControlGroup'],capture_output=True,text=True,check=True,timeout=5)
    return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
def process(value):
    pid=int(value.get('MainPID','0'))
    result={'active':value.get('ActiveState')=='active','pid':pid,'starttime':None,'netns_id':None,'cgroup':value.get('ControlGroup','')}
    if pid:
        root=pathlib.Path('/proc')/str(pid)
        result['starttime']=int((root/'stat').read_text().rsplit(')',1)[1].split()[19])
        result['netns_id']=(root/'ns/net').stat().st_ino
    group=pathlib.Path('/sys/fs/cgroup')/result['cgroup'].lstrip('/') if result['cgroup'] else None
    result['populated']=bool(group and (group/'cgroup.events').exists() and 'populated 1' in (group/'cgroup.events').read_text().splitlines())
    return result
agent=process(unit('sinan-agent.service'))
runtime=process(unit('sinan-singbox@main.service'))
uri=pathlib.Path(config['state_db']).as_uri()+'?mode=ro'
db=sqlite3.connect(uri,uri=True,timeout=3)
if sqlite3.sqlite_version_info<(3,43,0):
    # The product's bundled SQLite index uses the newer byte-length function.
    # Register its read-only text/blob semantics before parsing that schema.
    db.create_function('octet_length',1,lambda value:None if value is None else len(value if isinstance(value,bytes) else str(value).encode()),deterministic=True)
db.execute('PRAGMA query_only=ON')
db.set_progress_handler(lambda:1 if __import__('time').monotonic()>deadline else 0,1000)
deadline=__import__('time').monotonic()+4
floor=db.execute('SELECT revision FROM runtime_revision_floors WHERE module=?',('singbox',)).fetchone()
activation=db.execute('SELECT value FROM kv WHERE key=?',('runtime_activation:singbox',)).fetchone()
value=(json.loads(activation[0]) or {}) if activation else {}
runtime.update({'minimum_revision':int(floor[0]) if floor else None,'activation_id':value.get('activation_id'),'instance_id':value.get('instance',{}).get('instance_id')})
count,size=db.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(batch AS BLOB))),0) FROM usage_outbox WHERE acknowledged=0').fetchone()
counters=[]
for epoch,seq,raw in db.execute('SELECT epoch,seq,batch FROM usage_outbox WHERE acknowledged=0 AND length(CAST(batch AS BLOB))<=1048447 ORDER BY length(seq),seq LIMIT 16'):
    value=json.loads(raw)
    for row in value.get('entries',value.get('records',[]))[:128]:
        counters.append({'stat_name_sha256':hashlib.sha256(row.get('stat_name','').encode()).hexdigest(),'epoch':epoch,'seq':seq,'uplink':row.get('uplink'),'downlink':row.get('downlink')})
if len(counters)>128: raise ValueError('device_counter_evidence_budget')
controls=[]
for request_id,kind,digest,result,ack in db.execute('SELECT request_id,kind,digest,result,acknowledged FROM runtime_control ORDER BY rowid DESC LIMIT 128'):
    value=(json.loads(result).get('payload',{}) or {}) if result else {}
    controls.append({'request_id':request_id,'kind':kind,'digest':digest,'acknowledged':bool(ack),'success':value.get('success')})
server_id=int((pathlib.Path(config['identity_dir'])/'server_id').read_text().strip())
print(json.dumps({'server_id':server_id,'agent':agent,'runtime':runtime,'usage':{'pending_batches':count,'pending_bytes':size,'counters':counters},'controls':controls},separators=(',',':')))
'''


def ids(arguments):
    owned = arguments.get("owned_ids", {})
    require(set(owned) <= {"servers", "chains", "users", "node_ids"}, "unsupported_id_filter")
    rows = {}
    for name in ("servers", "chains", "users", "node_ids"):
        values = owned.get(name, [])
        require(isinstance(values, list) and len(values) <= 64 and
                all(type(value) is int and 0 < value < 2**63 for value in values) and
                len(set(values)) == len(values), "bounded_positive_owned_ids_required")
        rows[name] = "ARRAY[" + ",".join(map(str, values)) + "]::bigint[]"
    return rows


def evidence_sql(arguments):
    filters = ids(arguments)
    server_ids, chain_ids, user_ids = filters["servers"], filters["chains"], filters["users"]
    # No credentials, configs, raw source bytes, controller secrets, or error text.
    return f"""BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT json_build_object(
'servers',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT id,device_public_key,last_seen FROM servers WHERE id=ANY({server_ids}) ORDER BY id LIMIT 64) v),
'chains',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT id,phase,desired_generation,applied_generation,minimum_generation FROM singbox_chains WHERE id=ANY({chain_ids}) ORDER BY id LIMIT 64) v),
'vectors',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT chain_id,generation,stage,server_id,revision,bundle_sha256,deployment_id,binding_digest,checkpoint_request_id,barrier_request_id,barrier_vector,observed_at FROM singbox_path_stage_deployments WHERE chain_id=ANY({chain_ids}) ORDER BY chain_id,generation,stage,server_id LIMIT 512) v),
'current_dependencies',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT d.server_id,d.chain_id,d.generation,d.role,d.hop_position,d.route_active,d.revision FROM singbox_path_deployment_dependencies d JOIN server_module_status m ON m.server_id=d.server_id AND m.module=d.module AND m.applied_rev=d.revision WHERE d.server_id=ANY({server_ids}) AND d.chain_id=ANY({chain_ids}) AND d.module='singbox' ORDER BY d.server_id,d.chain_id,d.generation,d.hop_position LIMIT 512) v),
'path_probes',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT chain_id,generation,stage,probe_id,request_id,dependency_vector,state,observed_at FROM singbox_path_probes WHERE chain_id=ANY({chain_ids}) ORDER BY chain_id,generation,stage LIMIT 128) v),
'requests',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT request_id,server_id,kind,request_digest AS digest,expires_at,state,request_json->'expected' AS expected,request_json->'probe_id' AS probe_id,request_json->'minimum_revision' AS minimum_revision FROM runtime_control_requests WHERE server_id=ANY({server_ids}) ORDER BY created_at DESC,request_id LIMIT 512) v),
'receipts',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT c.request_id,c.outcome,c.received_at,jsonb_build_object('request_id',c.result_json->'request_id','request_digest',c.result_json->'request_digest','observed',c.result_json->'observed','probe_id',c.result_json->'probe_id','success',c.result_json->'success','minimum_revision',c.result_json->'minimum_revision','pending_intents_clear',c.result_json->'pending_intents_clear') AS result FROM runtime_control_receipts c JOIN runtime_control_requests r USING(request_id) WHERE r.server_id=ANY({server_ids}) ORDER BY c.received_at DESC,c.request_id LIMIT 512) v),
'runtime_checkpoints',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT server_id,checkpoint_json AS checkpoint,verified_at,minimum_revision,checkpoint_request_id,barrier_request_id FROM runtime_module_checkpoints WHERE server_id=ANY({server_ids}) ORDER BY server_id,module LIMIT 64) v),
'usage',json_build_object('batches_count',(SELECT count(*) FROM usage_batches WHERE server_id=ANY({server_ids})),'records_count',(SELECT count(*) FROM usage_records WHERE server_id=ANY({server_ids}) AND user_id=ANY({user_ids})),'duplicate_identities',(SELECT count(*) FROM (SELECT server_id,epoch,seq,stat_name FROM usage_records WHERE server_id=ANY({server_ids}) GROUP BY server_id,epoch,seq,stat_name HAVING count(*)>1) d),'records',(SELECT COALESCE(json_agg(v),'[]') FROM (SELECT server_id,user_id,node_id,epoch,seq,uplink,downlink FROM usage_records WHERE server_id=ANY({server_ids}) AND user_id=ANY({user_ids}) ORDER BY server_id,epoch,seq LIMIT 512) v)));
COMMIT;"""


def panel_evidence(manifest, arguments):
    pg = manifest["panel"]["postgres"]
    output = capture(["/usr/bin/psql", "--no-psqlrc", "--quiet", "--no-align", "--tuples-only",
                      "--set=ON_ERROR_STOP=1", "--host", pg["socket_dir"], "--port", str(pg["port"]),
                      "--username", pg["username"], "--dbname", pg["database"]], timeout=8,
                     input_bytes=evidence_sql(arguments).encode(),
                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    value = json.loads(output)
    require(isinstance(value, dict), "panel_readonly_evidence_shape_invalid")
    for name, maximum in (("servers", 64), ("chains", 64), ("vectors", 512), ("current_dependencies", 512),
                          ("path_probes", 128), ("requests", 512), ("receipts", 512),
                          ("runtime_checkpoints", 64)):
        require(len(value[name]) < maximum, "panel_evidence_row_budget_reached")
    require(value["usage"]["records_count"] == len(value["usage"]["records"]),
            "panel_usage_evidence_would_be_partial")
    return value


def host_pid(row, guest_pid, starttime):
    if guest_pid == 0:
        return 0
    entries = [path for path in Path("/proc").iterdir() if path.name.isdecimal()]
    require(len(entries) <= 8192, "host_process_observation_budget")
    matches = []
    for path in entries:
        try:
            if (path / "ns/pid").stat().st_ino != row["pidns_id"]:
                continue
            status = (path / "status").read_text()
            namespace_pids = next(line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:"))
            if int(namespace_pids[-1]) == guest_pid and proc_identity(int(path.name))["starttime"] == starttime:
                matches.append(int(path.name))
        except (FileNotFoundError, ProcessLookupError, StopIteration):
            continue
    require(len(matches) == 1, "controlled_process_identity_not_unique")
    return matches[0]


def service(row, action, runtime=False):
    unit = "sinan-singbox@main.service" if runtime else "sinan-agent.service"
    require(action in {"stop", "start", "restart"}, "service_operation_not_allowed")
    role_capture(row, ["/bin/systemctl", action, unit], timeout=30)


def dispatch(manifest, identities, request):
    require(request.get("schema") == 1 and request.get("run_id") == manifest["run_id"] and
            request.get("operation") in OPERATIONS, "controller_request_identity_invalid")
    operation, role, arguments = request["operation"], request.get("role"), request.get("arguments", {})
    require(isinstance(arguments, dict), "controller_arguments_invalid")
    if operation == "inspect":
        require(not arguments and role is None, "inspect_takes_no_arguments")
        cgroups = Path("/proc/self/cgroup").read_text().splitlines()
        relative = next((line[3:] for line in cgroups if line.startswith("0::/")), None)
        require(relative is not None and ".." not in Path(relative).parts, "bounded_helper_cgroup_required")
        group = Path("/sys/fs/cgroup") / relative.lstrip("/")
        limits = {name: (group / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "pids.max")}
        require(limits["memory.max"].isdigit() and 0 < int(limits["memory.max"]) <= 512 * 1024**2 and
                limits["memory.swap.max"] == "0" and limits["pids.max"].isdigit() and
                0 < int(limits["pids.max"]) <= 96, "helper_resource_budget_not_enforced")
        return {"dedicated": True, "isolated": True, "test_only": True,
                "source_identity": manifest["source_identity"],
                "panel_origin": manifest["panel"]["origin"].rstrip("/"),
                "helper_cgroup_limits": limits,
                "roles": {row["role"]: row for row in identities}}
    if operation in {"agent_stop", "agent_start", "agent_restart", "runtime_restart", "enroll", "device_snapshot"}:
        require(role in ROLES, "device_role_required")
        row = manifest["roles"][role]
        if operation.startswith("agent_") or operation == "runtime_restart":
            require(not arguments, "service_takes_no_arguments")
            service(row, operation.rsplit("_", 1)[1], runtime=operation == "runtime_restart")
            return {"role": role, "operation_completed": True}
        if operation == "enroll":
            require(set(arguments) == {"descriptor_file"}, "enrollment_descriptor_required")
            path = within(owned_root(manifest["run_root"], manifest["run_id"]), arguments["descriptor_file"])
            require(path.stat().st_mode & 0o077 == 0, "private_enrollment_descriptor_required")
            descriptor = load(path)
            require(isinstance(descriptor, dict) and type(descriptor.get("schema")) is int and descriptor["schema"] == 1
                    and descriptor.get("run_id") == manifest["run_id"] and descriptor.get("role") == role and
                    isinstance(descriptor.get("token"), str) and 0 < len(descriptor["token"]) <= 512
                    and all(33 <= ord(character) <= 126 for character in descriptor["token"]),
                    "enrollment_descriptor_identity_invalid")
            role_capture(row, [row["agent_binary"], "--config", row["agent_config"],
                               "enroll", "--panel=" + manifest["panel"]["origin"],
                               "--token=" + descriptor["token"]], timeout=45)
            service(row, "start")
            return {"role": role, "ordinary_enrollment_completed": True}
        require(not arguments, "snapshot_takes_no_arguments")
        snapshot = json.loads(role_capture(row, ["/usr/bin/python3", "-c", DEVICE_SCRIPT], timeout=10))
        for name in ("agent", "runtime"):
            process = snapshot[name]
            process["guest_pid"] = process["pid"]
            process["pid"] = host_pid(row, process["guest_pid"], process["starttime"])
        snapshot["role"] = role
        servers = panel_evidence(manifest, {"owned_ids": {"servers": [snapshot["server_id"]]}})["servers"]
        require(len(servers) == 1, "enrolled_server_evidence_missing")
        snapshot["device_public_key"] = servers[0]["device_public_key"]
        return snapshot
    require(role is None, "host_operation_cannot_target_role")
    if operation == "panel_evidence":
        require(set(arguments) == {"owned_ids"}, "owned_id_filter_required")
        return panel_evidence(manifest, arguments)
    require(not arguments, "host_service_takes_no_arguments")
    if operation in {"panel_stop", "panel_start"}:
        capture(["/bin/systemctl", operation.split("_")[1], manifest["panel"]["unit"]], timeout=30)
        return {"operation_completed": True}
    if operation == "restore_all":
        capture(["/bin/systemctl", "start", manifest["panel"]["unit"]], timeout=30)
        for row in manifest["roles"].values():
            service(row, "start")
        return {"services_restored": True}
    # No database/filesystem deletion. Only our explicitly owned units are stopped.
    for row in manifest["roles"].values():
        service(row, "stop")
        service(row, "stop", runtime=True)
        for unit in ("sinan-agent.service", "sinan-singbox@main.service"):
            state = role_capture(row, ["/bin/systemctl", "show", unit,
                            "--property=MainPID", "--property=ControlGroup"], timeout=10).decode()
            require("MainPID=0" in state.splitlines(), "product_cleanup_pid_not_confirmed")
            group = next((line.partition("=")[2] for line in state.splitlines() if line.startswith("ControlGroup=")), "")
            if group:
                events = role_capture(row, ["/usr/bin/python3", "-c",
                    "import pathlib; p=pathlib.Path('/sys/fs/cgroup')/" + repr(group.lstrip("/")) +
                    "/'cgroup.events'; print(p.read_text() if p.exists() else 'populated 0')"], timeout=5).decode()
                require("populated 0" in events.splitlines(), "product_cleanup_cgroup_not_confirmed")
    capture(["/bin/systemctl", "stop", manifest["panel"]["unit"]], timeout=30)
    state = capture(["/bin/systemctl", "show", manifest["panel"]["unit"],
                     "--property=MainPID", "--property=ControlGroup"], timeout=10).decode()
    require("MainPID=0" in state.splitlines(), "panel_cleanup_pid_not_confirmed")
    group = next((line.partition("=")[2] for line in state.splitlines() if line.startswith("ControlGroup=")), "")
    if group:
        events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
        require(not events.exists() or "populated 0" in events.read_text().splitlines(),
                "panel_cleanup_cgroup_not_confirmed")
    return {"product_units_stopped": True, "pid_and_cgroup_cleanup_confirmed": True,
            "databases_and_evidence_retained": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    def cancelled(_number, _frame):
        raise ValueError("controller_operation_cancelled")
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, cancelled)
    request, response = {}, {"schema": 1, "ok": False}
    try:
        data = sys.stdin.buffer.read(256 * 1024 + 1)
        require(len(data) <= 256 * 1024, "controller_input_limit")
        request = json.loads(data)
        response.update({key: request.get(key) for key in ("run_id", "operation")})
        manifest, identities = validate_manifest(args.manifest)
        response.update(ok=True, facts=dispatch(manifest, identities, request))
    except (ValueError, OSError, KeyError, TypeError) as error:
        response.update(ok=False, facts={}, error_code=str(error) if isinstance(error, ValueError)
                        and re.fullmatch(r"[a-z0-9_]+", str(error)) else "controller_private_failure")
    print(json.dumps(response, separators=(",", ":")))
    raise SystemExit(0 if response["ok"] else 1)


if __name__ == "__main__":
    main()
