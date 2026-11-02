// Linux constraint behind #6: an inherited root 0600 pipe can be read by the consumer,
// but a filename consumer reopening /dev/fd/N gets the same EACCES as the agent.
// User namespaces reproduce root -> ordinary uid without sudo or an installed broker.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const probe = spawnSync("unshare", ["-r", "--map-auto", "/usr/bin/python3", "-I", "-c", "pass"], {
	encoding: "utf8", timeout: 5_000,
});
const skip = process.platform !== "linux" || probe.status !== 0
	? "needs Linux user namespaces with subordinate uid/gid mappings (no sudo required)" : false;

test("root 0600 inherited pipe is readable, but cannot be reopened as /dev/fd/N", { skip }, () => {
	const consumer = `
import json, os, stat
fd = 9
info = os.fstat(fd)
result = {"uid": os.getuid(), "owner": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
          "pipe": stat.S_ISFIFO(info.st_mode), "reopen_errno": {}}
for path in ("/dev/fd/9", f"/proc/{os.getpid()}/fd/9"):
    try:
        reopened = os.open(path, os.O_RDONLY)
    except OSError as error:
        result["reopen_errno"][path.split("/")[1]] = error.errno
    else:
        os.close(reopened)
        result["reopen_errno"][path.split("/")[1]] = None
result["received"] = os.read(fd, 1024).decode()
print(json.dumps(result))
`;
	const setup = `
import os, sys
read_end, write_end = os.pipe()
os.fchmod(read_end, 0o600)
os.write(write_end, b"synthetic-secret\\n")
os.close(write_end)
os.dup2(read_end, 9, inheritable=True)
if read_end != 9:
    os.close(read_end)
os.setgroups([])
os.setresgid(1, 1, 1)
os.setresuid(1, 1, 1)
os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", "-c", sys.argv[1]], {})
`;
	const result = spawnSync("unshare", ["-r", "--map-auto", "/usr/bin/python3", "-I", "-c", setup, consumer], {
		encoding: "utf8", timeout: 5_000,
	});
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(JSON.parse(result.stdout), {
		uid: 1, owner: 0, mode: 0o600, pipe: true,
		received: "synthetic-secret\n", reopen_errno: { dev: 13, proc: 13 }, // Linux EACCES
	});
});
