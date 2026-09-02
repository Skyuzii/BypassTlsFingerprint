using System.Runtime.CompilerServices;

// The test project exercises internal plumbing (the response parser) directly, so it is allowed
// to see internals. Everything else stays private.
[assembly: InternalsVisibleTo("BypassTlsFingerprint.Tests")]
