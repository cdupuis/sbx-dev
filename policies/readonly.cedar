// Observing the host's sbx installation, and nothing else.
//
// This is the smallest useful grant and a reasonable floor for any sandbox that
// talks to sbx-warden at all: it can find out what exists but cannot change
// anything, and it cannot read the credential store, which baseline.cedar
// forbids separately because those commands report on secrets rather than state.
permit (
    principal,
    action in SBX::Action::"read",
    resource
);
