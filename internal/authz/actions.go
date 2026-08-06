package authz

// Action groups let a policy grant a capability rather than a list of command
// names, and let it keep granting that capability as sbx grows.
//
// Membership is curated rather than derived, because nothing in sbx's published
// reference says whether a command observes or changes the world. Being
// incomplete is safe in one direction only: an unclassified command belongs to
// no group, so a policy written in terms of groups does not reach it, and it can
// only be granted by name. Membership in Read is therefore kept narrow, and
// membership in the escalating groups broad.
const (
	// GroupRead names commands that only report state.
	GroupRead = "read"
	// GroupInspectSecrets names commands that report on stored credentials.
	// They mask values, which is why they are not simply Read.
	GroupInspectSecrets = "inspectSecrets"
	// GroupCreateSandbox names commands that bring a sandbox into being, which
	// also mounts host directories into it.
	GroupCreateSandbox = "createSandbox"
	// GroupDestroySandbox names commands that stop or delete sandboxes.
	GroupDestroySandbox = "destroySandbox"
	// GroupChangeSandbox names commands that alter an existing sandbox.
	GroupChangeSandbox = "changeSandbox"
	// GroupRunInSandbox names commands that execute a caller-chosen program
	// inside a sandbox.
	GroupRunInSandbox = "runInSandbox"
	// GroupTouchHostFiles names commands that read or write the host filesystem
	// at a path the caller chooses.
	GroupTouchHostFiles = "touchHostFiles"
	// GroupWritePolicy names commands that change what a sandbox may reach.
	// Widening is the escalation that matters, and sbx does not separate the two
	// directions by command, so both belong here.
	GroupWritePolicy = "writePolicy"
	// GroupWriteSecrets names commands that add or remove stored credentials.
	GroupWriteSecrets = "writeSecrets"
	// GroupControlDaemon names commands that control the host daemon every
	// sandbox depends on.
	GroupControlDaemon = "controlDaemon"
	// GroupPublishArtifacts names commands that push to a registry under the
	// host's credentials.
	GroupPublishArtifacts = "publishArtifacts"
)

// actionGroups maps a command path to the groups it belongs to. A command may
// belong to several: creating a sandbox both creates and mounts host paths.
var actionGroups = map[string][]string{
	"ls":                   {GroupRead},
	"ports":                {GroupRead},
	"version":              {GroupRead},
	"diagnose":             {GroupRead},
	"policy ls":            {GroupRead},
	"policy log":           {GroupRead},
	"policy inspect":       {GroupRead},
	"policy check network": {GroupRead},
	"mcp ls":               {GroupRead},
	"mcp inspect":          {GroupRead},
	"mcp auth status":      {GroupRead},
	"skills ls":            {GroupRead},
	"template ls":          {GroupRead},
	"kit inspect":          {GroupRead},
	"kit provenance":       {GroupRead},
	"kit verify":           {GroupRead},
	"daemon status":        {GroupRead},
	"daemon log-level":     {GroupRead},

	"secret ls": {GroupInspectSecrets},

	"create":              {GroupCreateSandbox, GroupTouchHostFiles},
	"create claude":       {GroupCreateSandbox, GroupTouchHostFiles},
	"create codex":        {GroupCreateSandbox, GroupTouchHostFiles},
	"create copilot":      {GroupCreateSandbox, GroupTouchHostFiles},
	"create cursor":       {GroupCreateSandbox, GroupTouchHostFiles},
	"create docker-agent": {GroupCreateSandbox, GroupTouchHostFiles},
	"create droid":        {GroupCreateSandbox, GroupTouchHostFiles},
	"create gemini":       {GroupCreateSandbox, GroupTouchHostFiles},
	"create kiro":         {GroupCreateSandbox, GroupTouchHostFiles},
	"create opencode":     {GroupCreateSandbox, GroupTouchHostFiles},
	"create shell":        {GroupCreateSandbox, GroupTouchHostFiles},
	"run":                 {GroupCreateSandbox, GroupRunInSandbox, GroupTouchHostFiles},
	"tui":                 {GroupCreateSandbox, GroupRunInSandbox, GroupTouchHostFiles},
	"template load":       {GroupCreateSandbox, GroupTouchHostFiles},

	"rm":    {GroupDestroySandbox},
	"stop":  {GroupDestroySandbox},
	"prune": {GroupDestroySandbox},
	"reset": {GroupDestroySandbox, GroupWritePolicy, GroupWriteSecrets},

	"exec": {GroupRunInSandbox},

	"cp":            {GroupTouchHostFiles, GroupChangeSandbox},
	"kit add":       {GroupChangeSandbox},
	"kit pack":      {GroupTouchHostFiles},
	"kit pull":      {GroupTouchHostFiles},
	"kit sign":      {GroupTouchHostFiles},
	"kit validate":  {GroupTouchHostFiles},
	"mcp add":       {GroupChangeSandbox},
	"mcp rm":        {GroupChangeSandbox},
	"mcp load":      {GroupChangeSandbox},
	"mcp auth":      {GroupChangeSandbox, GroupWriteSecrets},
	"mcp auth rm":   {GroupWriteSecrets},
	"skills import": {GroupChangeSandbox, GroupTouchHostFiles},
	"template save": {GroupChangeSandbox},
	"template rm":   {GroupChangeSandbox},

	"policy allow":         {GroupWritePolicy},
	"policy allow network": {GroupWritePolicy},
	"policy deny":          {GroupWritePolicy},
	"policy deny network":  {GroupWritePolicy},
	"policy rm":            {GroupWritePolicy},
	"policy rm network":    {GroupWritePolicy},
	"policy init":          {GroupWritePolicy},
	"policy reset":         {GroupWritePolicy},

	"secret set":        {GroupWriteSecrets},
	"secret set-custom": {GroupWriteSecrets},
	"secret rm":         {GroupWriteSecrets},
	"secret import":     {GroupWriteSecrets, GroupTouchHostFiles},
	"login":             {GroupWriteSecrets},
	"logout":            {GroupWriteSecrets},
	"setup ssh":         {GroupWriteSecrets, GroupTouchHostFiles},
	"setup ssh remove":  {GroupWriteSecrets, GroupTouchHostFiles},

	"daemon start":         {GroupControlDaemon},
	"daemon stop":          {GroupControlDaemon},
	"daemon restart":       {GroupControlDaemon},
	"daemon log-level set": {GroupControlDaemon},

	"kit push": {GroupPublishArtifacts},
}

// Groups returns the groups a command path belongs to.
func Groups(path string) []string { return actionGroups[path] }

// AllGroups lists every group name, so the entity set can declare them even
// when no command in a request belongs to one.
func AllGroups() []string {
	return []string{
		GroupRead,
		GroupInspectSecrets,
		GroupCreateSandbox,
		GroupDestroySandbox,
		GroupChangeSandbox,
		GroupRunInSandbox,
		GroupTouchHostFiles,
		GroupWritePolicy,
		GroupWriteSecrets,
		GroupControlDaemon,
		GroupPublishArtifacts,
	}
}
