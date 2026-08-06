// Guardrails that hold whatever else a sandbox is granted.
//
// Nothing here permits anything. A forbid in Cedar beats every permit, so a rule
// in this file cannot be undone by a role policy that is more generous, and
// binding this file to "*" is what makes these limits absolute.
//
// These are the capabilities a sandbox almost never has a reason to hold. What
// is deliberately absent is as important: writePolicy and touchHostFiles are
// left to role policies, because orchestrating sandboxes legitimately needs
// them, and confining them is the role policy's job.

// The credential store is how the host authenticates to everything. A sandbox
// that can write it can replace a credential with one it controls; a sandbox
// that can list it learns which services are worth attacking.
forbid (
    principal,
    action in SBX::Action::"writeSecrets",
    resource
);

forbid (
    principal,
    action in SBX::Action::"inspectSecrets",
    resource
);

// Every sandbox on the host depends on the daemon, so stopping or restarting it
// reaches far outside the caller.
forbid (
    principal,
    action in SBX::Action::"controlDaemon",
    resource
);

// Pushing an artifact spends the host's registry credentials under the host's
// name.
forbid (
    principal,
    action in SBX::Action::"publishArtifacts",
    resource
);

// A privileged process is not confined by the sandbox boundary, so asking for
// one is refused however the command was otherwise permitted.
forbid (
    principal,
    action,
    resource
) when {
    context.flags.contains("privileged")
};
