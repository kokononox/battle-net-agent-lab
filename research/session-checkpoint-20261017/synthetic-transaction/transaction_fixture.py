"""POSIX-only SYNTHETIC transaction experiment, not a game updater.

Only deterministic bytes generated here are accepted. No archives, user files,
downloads, patches, CASC layout or game paths are inputs. Callers must supply
the private capability created by create_fixture(), not a user installation.
Process-exit experiments do NOT establish power-loss durability.
"""
from contextlib import contextmanager
from pathlib import Path
import errno
import fcntl
import hashlib
import json
import os
import stat
import uuid

NAMES = ("alpha.fixture", "beta.fixture", "gamma.fixture")
PHASES = (
    "stage_created", "alpha_half", "alpha_synced", "beta_synced",
    "gamma_synced", "stage_verified", "generation_ready",
    "pointer_half", "pointer_synced", "pointer_replaced", "root_synced",
)
ROLLBACK_PHASES = ("pointer_half", "pointer_synced", "pointer_replaced", "root_synced")
MAX_FILE = 256 * 1024


class Stopped(Exception):
    pass


def require(value, reason):
    if not value:
        raise Stopped(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def payloads(generation):
    require(generation in ("g0", "g1"), "synthetic_generation_only")
    return {
        NAMES[0]: (generation.encode() + b"/alpha/") * 8192,
        NAMES[1]: (generation.encode() + b"/beta/") * 12288,
        NAMES[2]: generation.encode() + b"/gamma\n",
    }


def manifest(generation):
    return canonical({
        name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for name, raw in payloads(generation).items()
    })


def pointer(generation):
    return canonical({"format": "synthetic-pointer-1", "generation": generation})


def no_link(path, directory=False):
    st = path.lstat()
    require(not stat.S_ISLNK(st.st_mode), "links_forbidden")
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), "wrong_file_type")
    if not directory:
        require(st.st_nlink == 1, "hardlinks_forbidden")
        require(st.st_size <= MAX_FILE, "fixture_file_too_large")


def read(path, *, retained_pointer=False):
    # Validate the opened descriptor, not a separate pathname stat. A reader
    # may have opened the old pointer just before atomic replacement; its
    # inode legitimately has nlink=0 while its descriptor remains readable.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise Stopped("links_forbidden") from None
        raise
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode), "wrong_file_type")
        require(st.st_nlink in ((0, 1) if retained_pointer else (1,)), "hardlinks_forbidden")
        require(st.st_size <= MAX_FILE, "fixture_file_too_large")
        raw = bytearray()
        while chunk := os.read(fd, 16384):
            raw.extend(chunk)
            require(len(raw) <= MAX_FILE, "fixture_file_too_large")
        return bytes(raw)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, *, half_hook=None, fail=None):
    """Real writes, but ENOSPC/short-write are explicitly injected, not physical."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        split = len(raw) // 2
        first = raw[:split]
        require(os.write(fd, first) == len(first), "unexpected_short_write")
        if half_hook:
            half_hook()
        if fail == "enospc":
            raise OSError(errno.ENOSPC, "synthetic injected disk-full")
        if fail == "short_write":
            # The checked write reports fewer bytes than requested.
            actual = os.write(fd, raw[split:split + 1])
            require(actual == len(raw) - split, "injected_short_write")
        else:
            remainder = raw[split:]
            require(os.write(fd, remainder) == len(remainder), "unexpected_short_write")
        if fail == "fsync":
            raise OSError(errno.EIO, "synthetic injected file fsync failure")
        os.fsync(fd)
    finally:
        os.close(fd)


def create_fixture(parent):
    """Allocate a NEW private experiment; never initializes a caller's game."""
    require(os.name == "posix", "POSIX_only_NOT_Windows_tested")
    parent = Path(parent)
    require(parent.is_absolute() and parent.resolve() == parent, "physical_absolute_parent_only")
    root = parent / ("synthetic-txn-" + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    capability = uuid.uuid4().hex
    write_new(root / "FIXTURE-ONLY.json", canonical({
        "format": "generated-transaction-fixture-1",
        "capability": capability, "installation_ready": False,
    }))
    write_new(root / "LOCK", b"0")
    (root / "generations").mkdir()
    initial = root / "generations/g0"
    initial.mkdir()
    for name, raw in payloads("g0").items():
        write_new(initial / name, raw)
    write_new(initial / "MANIFEST.json", manifest("g0"))
    sync_dir(initial)
    sync_dir(root / "generations")
    write_new(root / "ACTIVE.json", pointer("g0"))
    sync_dir(root)
    return root, capability


def validate_generation(path, generation):
    no_link(path, directory=True)
    require(set(os.listdir(path)) == {*NAMES, "MANIFEST.json"}, "generation_layout")
    for name, expected in payloads(generation).items():
        require(read(path / name) == expected, "generation_content_mismatch")
    require(read(path / "MANIFEST.json") == manifest(generation), "manifest_mismatch")


def validate_partial_stage(path):
    no_link(path, directory=True)
    names = set(os.listdir(path))
    require(names <= {*NAMES, "MANIFEST.json"}, "unexpected_stage_file")
    for name in names:
        expected = manifest("g1") if name == "MANIFEST.json" else payloads("g1")[name]
        require(expected.startswith(read(path / name)), "stage_not_generated_prefix")


def check_root(root, capability):
    root = Path(root)
    require(root.is_absolute() and root.resolve() == root, "physical_root_only")
    require(root.name.startswith("synthetic-txn-"), "fixture_root_name")
    no_link(root, directory=True)
    marker = canonical({"format": "generated-transaction-fixture-1",
                        "capability": capability, "installation_ready": False})
    require(read(root / "FIXTURE-ONLY.json") == marker, "private_fixture_capability_required")
    require(set(os.listdir(root)) <= {
        "FIXTURE-ONLY.json", "LOCK", "generations", "ACTIVE.json", "ACTIVE.next",
    }, "unexpected_root_file")
    require(read(root / "LOCK") == b"0", "lock_shape")
    no_link(root / "generations", directory=True)
    require(set(os.listdir(root / "generations")) <= {"g0", "g1", ".stage-g1"}, "unexpected_generation")
    validate_generation(root / "generations/g0", "g0")
    g1 = root / "generations/g1"
    if g1.exists() or g1.is_symlink():
        validate_generation(g1, "g1")
    stage = root / "generations/.stage-g1"
    if stage.exists() or stage.is_symlink():
        validate_partial_stage(stage)
    tmp = root / "ACTIVE.next"
    if tmp.exists() or tmp.is_symlink():
        raw = read(tmp)
        require(any(pointer(g).startswith(raw) for g in ("g0", "g1")), "pointer_temp_not_generated_prefix")
    active = read(root / "ACTIVE.json")
    require(active in (pointer("g0"), pointer("g1")), "active_pointer_invalid")
    require(active != pointer("g1") or g1.is_dir(), "active_generation_absent")
    return root


@contextmanager
def writer(root, capability):
    root = check_root(root, capability)
    fd = os.open(root / "LOCK", os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stopped("competing_writer") from None
        # Recheck after acquiring the cooperative lock.
        check_root(root, capability)
        yield root
    finally:
        os.close(fd)


def visible(root, capability):
    """Read the pointer ONCE; retained immutable generations keep this stable."""
    root = Path(root)
    expected_marker = canonical({"format": "generated-transaction-fixture-1",
                                 "capability": capability, "installation_ready": False})
    require(read(root / "FIXTURE-ONLY.json") == expected_marker, "private_fixture_capability_required")
    raw = read(root / "ACTIVE.json", retained_pointer=True)
    require(raw in (pointer("g0"), pointer("g1")), "active_pointer_invalid")
    generation = json.loads(raw)["generation"]
    validate_generation(root / "generations" / generation, generation)
    return generation


def publish(root, generation, hook, fail):
    tmp = root / "ACTIVE.next"
    if tmp.exists():
        tmp.unlink()  # Only validated private generated-prefix scratch.
    write_new(tmp, pointer(generation), half_hook=lambda: hook("pointer_half"),
              fail={"enospc_pointer": "enospc", "short_pointer": "short_write",
                    "fsync_pointer": "fsync"}.get(fail))
    hook("pointer_synced")
    if fail == "replace":
        raise OSError(errno.EIO, "synthetic injected replace failure")
    os.replace(tmp, root / "ACTIVE.json")
    hook("pointer_replaced")
    if fail == "sync_root":
        raise OSError(errno.EIO, "synthetic injected directory fsync failure")
    sync_dir(root)
    hook("root_synced")


def advance(root, capability, *, hook=lambda phase: None, fail=None):
    with writer(root, capability) as root:
        if visible(root, capability) == "g1":
            # A prior caller may have seen an error AFTER pointer replace.
            # Revalidate (above) and retry directory syncs before acknowledging
            # an idempotent result; do not silently forget that failure.
            sync_dir(root / "generations/g1")
            sync_dir(root / "generations")
            sync_dir(root)
            return {"state": "g1", "idempotent": True, "installation_ready": False}
        g1 = root / "generations/g1"
        if not g1.exists():
            stage = root / "generations/.stage-g1"
            if stage.exists():
                # check_root established every file is a generated prefix.
                for name in os.listdir(stage):
                    (stage / name).unlink()
                stage.rmdir()
            stage.mkdir()
            hook("stage_created")
            for index, (name, raw) in enumerate(payloads("g1").items()):
                write_new(stage / name, raw,
                          half_hook=(lambda: hook("alpha_half")) if index == 0 else None,
                          fail=fail if index == 1 else None)
                hook(("alpha_synced", "beta_synced", "gamma_synced")[index])
            write_new(stage / "MANIFEST.json", manifest("g1"),
                      fail="enospc" if fail == "enospc_manifest" else None)
            validate_generation(stage, "g1")
            if fail == "sync_stage":
                raise OSError(errno.EIO, "synthetic injected stage fsync failure")
            sync_dir(stage)
            hook("stage_verified")
            if fail == "rename_generation":
                raise OSError(errno.EIO, "synthetic injected generation rename failure")
            os.rename(stage, g1)
            if fail == "sync_generation":
                raise OSError(errno.EIO, "synthetic injected generation fsync failure")
            sync_dir(root / "generations")
            hook("generation_ready")
        # Also needed when recovering a generation rename whose parent fsync
        # failed before the pointer could be published.
        sync_dir(g1)
        sync_dir(root / "generations")
        publish(root, "g1", hook, fail)
        require(visible(root, capability) == "g1", "post_commit_validation")
        return {"state": "g1", "idempotent": False, "installation_ready": False}


def rollback(root, capability, *, hook=lambda phase: None):
    """Fixture-only pointer rollback; never claims CASC/application rollback."""
    with writer(root, capability) as root:
        publish(root, "g0", hook, None)
        require(visible(root, capability) == "g0", "post_rollback_validation")
        return {"state": "g0", "installation_ready": False}