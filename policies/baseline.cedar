// Guardrails that hold whatever else a sandbox is granted.
//
// Nothing here permits anything. A forbid in Cedar beats every permit, so a rule
// in this file cannot be undone by a role policy that is more generous, and
// binding this file to "*" is what makes these limits hold everywhere.
//
// These are the capabilities a sandbox almost never has a reason to hold. What
// is deliberately absent is as important: writePolicy and touchHostFiles are
// left to role policies, because orchestrating sandboxes legitimately needs
// them, and confining them is the role policy's job.
//
// Every rule below exempts SBX::Group::"root", which is the one way past them.
// Since a forbid cannot be overridden, a policy that grants what this file
// withholds would otherwise be capped without saying so, and the exemption has
// to be written here or not exist at all. That is also why membership of the
// group, rather than the root policy, is the thing to guard: give it only to a
// sandbox meant to have the host.

// The credential store is how the host authenticates to everything. A sandbox
// that can write it can replace a credential with one it controls; a sandbox
// that can list it learns which services are worth attacking.
forbid (
    principal,
    action in SBX::Action::"writeSecrets",
    resource
) unless {
    principal in SBX::Group::"root"
};

forbid (
    principal,
    action in SBX::Action::"inspectSecrets",
    resource
) unless {
    principal in SBX::Group::"root"
};

// Every sandbox on the host depends on the daemon, so stopping or restarting it
// reaches far outside the caller.
forbid (
    principal,
    action in SBX::Action::"controlDaemon",
    resource
) unless {
    principal in SBX::Group::"root"
};

// Pushing an artifact spends the host's registry credentials under the host's
// name.
forbid (
    principal,
    action in SBX::Action::"publishArtifacts",
    resource
) unless {
    principal in SBX::Group::"root"
};

// A privileged process is not confined by the sandbox boundary, so asking for
// one is refused however the command was otherwise permitted.
//
// This exemption is the widest one, because unlike the rules above this withholds
// no capability of its own: it only refuses a flag. Lifting it therefore needs no
// matching permit to have an effect — every command the root group may already
// run, it may run privileged.
forbid (
    principal,
    action,
    resource
) when {
    context.flags.contains("privileged")
} unless {
    principal in SBX::Group::"root"
};
