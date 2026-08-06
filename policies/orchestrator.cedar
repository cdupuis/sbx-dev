// A sandbox that manages other sandboxes.
//
// Pair this with readonly.cedar. It is the most capable role shipped here: it can
// bring sandboxes up, tear them down, change them, and run commands inside them.
// It is still bounded in two ways. baseline.cedar keeps it away from the
// credential store, the daemon and the registry; hostPathsUnderWorkdir keeps
// every workspace it mounts, and every file it copies, under the directory
// sbx-dev runs in.
//
// Creating a sandbox mounts a host directory into it, so the path condition is
// what stands between "orchestrate my project" and handing out a mount of the
// whole filesystem.
permit (
    principal,
    action in [
        SBX::Action::"createSandbox",
        SBX::Action::"destroySandbox",
        SBX::Action::"changeSandbox",
        SBX::Action::"runInSandbox"
    ],
    resource
) when {
    context.hostPathsUnderWorkdir
};

// Widening what a sandbox may reach on the network is an escalation an
// orchestrator is not given here. To grant it, add a rule for the writePolicy
// capability, and consider marking it @requireApproval so it has to be confirmed
// rather than simply taken. See the README for that form.
