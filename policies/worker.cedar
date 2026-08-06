// A sandbox that works on itself.
//
// Pair this with readonly.cedar. It adds the ability to run a command inside
// itself and to move files between itself and the host, and it deliberately
// stops there: a worker cannot create or destroy a sandbox, and cannot reach
// another one.
//
// Two conditions carry the whole rule. targetsSelf holds only when the sandbox
// the command names is the caller, which is what keeps a worker out of its
// siblings. hostPathsUnderWorkdir holds only when every host path the command
// named lies under the directory sbx-warden runs in, which is what stops "sbx cp"
// from reaching the rest of the filesystem. Both are computed from the parse the
// server already performed, so neither can be talked around with ".." or a
// relative path.
permit (
    principal,
    action in [SBX::Action::"runInSandbox", SBX::Action::"changeSandbox"],
    resource
) when {
    context.targetsSelf &&
    context.hostPathsUnderWorkdir
};
