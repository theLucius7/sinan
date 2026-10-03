import errno
import grp
import json
import os
import pwd
import sys


def inspect(path):
    result = {
        "path": path, "exists": False, "nearest_existing_parent": None,
        "readable": None, "writable": None, "executable": None,
        "symlink_free": False, "error": None,
    }
    if not path.startswith("/") or len(path) > 4096:
        result["error"] = "invalid_runtime_directory"
        return result
    parts = [part for part in path.split("/") if part]
    if any(part in (".", "..") for part in parts):
        result["error"] = "invalid_runtime_directory"
        return result
    descriptor = None
    current = "/"
    try:
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        exists = True
        for part in parts:
            try:
                child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    exists = False
                    break
                raise
            os.close(descriptor)
            descriptor = child
            current = os.path.join(current, part)
        result.update({
            "exists": exists, "nearest_existing_parent": current, "symlink_free": True,
            "readable": os.access(".", os.R_OK, dir_fd=descriptor, effective_ids=True),
            "writable": os.access(".", os.W_OK, dir_fd=descriptor, effective_ids=True),
            "executable": os.access(".", os.X_OK, dir_fd=descriptor, effective_ids=True),
        })
    except OSError as error:
        result["error"] = {errno.EACCES: "directory_access_denied", errno.ELOOP: "symlink_denied", errno.ENOTDIR: "not_directory_or_symlink"}.get(error.errno, "directory_inspection_failed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


runtime_path = sys.argv[1]
paths = {
    "runtime_directory": runtime_path,
    "data_directory": os.path.join(runtime_path, "data"),
    "certificate_directory": os.path.join(runtime_path, "data", "certificates"),
}
observation = {
    "privileged_effective_uid": os.geteuid(),
    "runtime_account": {"known": False, "source": "runtime_service_account_not_observed"},
}
for field, path in paths.items():
    observation[field] = inspect(path)
    observation[field].update({
        "runtime_readable": None, "runtime_writable": None,
        "runtime_executable": None, "runtime_error": "runtime_service_account_unknown",
    })

try:
    metadata = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    if not isinstance(metadata, dict) or metadata.get("known") is not True:
        raise ValueError("runtime_service_account_unknown")
    name = metadata.get("name")
    configured_group = metadata.get("group")
    additional = metadata.get("supplementary_groups")
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValueError("invalid_runtime_account")
    if not isinstance(configured_group, str) or len(configured_group) > 128:
        raise ValueError("invalid_runtime_group")
    if not isinstance(additional, list) or len(additional) > 32:
        raise ValueError("invalid_runtime_supplementary_groups")
    account = pwd.getpwuid(int(name)) if name.isascii() and name.isdecimal() else pwd.getpwnam(name)
    uid = account.pw_uid
    gid = account.pw_gid
    if configured_group:
        group = grp.getgrgid(int(configured_group)) if configured_group.isascii() and configured_group.isdecimal() else grp.getgrnam(configured_group)
        gid = group.gr_gid
    groups = set(os.getgrouplist(account.pw_name, gid))
    for name in additional:
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ValueError("invalid_runtime_supplementary_groups")
        group = grp.getgrgid(int(name)) if name.isascii() and name.isdecimal() else grp.getgrnam(name)
        groups.add(group.gr_gid)
    if len(groups) > 128 or not 0 <= uid < 2**32 - 1 or not 0 <= gid < 2**32 - 1:
        raise ValueError("invalid_runtime_account_ids")
    if os.geteuid() != 0:
        raise ValueError("privileged_identity_not_available")
    # Each root inspection closed its descriptors. Resolve the entire path again
    # after dropping identity so ancestor traversal cannot inherit root access.
    os.setgroups(sorted(groups))
    os.setgid(gid)
    os.setuid(uid)
    if os.geteuid() != uid or os.getegid() != gid:
        raise ValueError("runtime_identity_transition_failed")
    observation["runtime_account"] = {
        "known": True, "uid": uid, "gid": gid,
        "supplementary_gids": sorted(groups), "source": "actual_loaded_unit_account_nss_and_dropped_identity",
    }
    for field, path in paths.items():
        runtime = inspect(path)
        observation[field].update({
            "runtime_readable": runtime["readable"],
            "runtime_writable": runtime["writable"],
            "runtime_executable": runtime["executable"],
            "runtime_error": runtime["error"],
        })
except (KeyError, ValueError, TypeError, OSError, OverflowError):
    observation["runtime_account"]["known"] = False
    for field in paths:
        observation[field]["runtime_error"] = "runtime_service_account_unavailable_or_inspection_failed"

print(json.dumps(observation))
