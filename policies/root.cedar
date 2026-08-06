// A sandbox that may do anything the host's sbx can do, once an operator agrees.
//
// Every other file here confines. This one is the opposite, so it is worth being
// explicit about how far it reaches: nothing is refused outright, on the host or
// on any sandbox, with any flag.
//
// What bounds it is not a smaller list of commands but a person. Only reading is
// granted outright; everything else is withheld until an operator confirms it at
// the terminal sbx-warden runs on, so a sandbox holding this can ask for anything
// and take nothing.
permit (
    principal in SBX::Group::"root",
    action in SBX::Action::"read",
    resource
);

// The unconstrained action is what makes this cover everything, and no list
// could. Capability groups are a closed set, some commands belong to none of
// them, and a command sbx gains later may belong to none either — so anything not
// named above is confirmed rather than assumed harmless.
//
// The read exclusion is required, not tidiness. A permit carrying this annotation
// grants nothing on its own, and one is enough to withhold a request, so without
// it this rule would also match the plain reads above and put every "sbx ls"
// behind a prompt.
@requireApproval("a root sandbox is bounded by the operator, not by its policy")
permit (
    principal in SBX::Group::"root",
    action,
    resource
) unless {
    action in SBX::Action::"read"
};
