# Privacy boundary

PhishGuard analyses only a URL deliberately submitted by the user. It does not
read message bodies, browser history or credentials, and the core detector does
not visit the submitted destination. This boundary does not make every submitted
URL anonymous: a path or query can contain email addresses, reset tokens,
session identifiers, order numbers or campaign identifiers.

To reduce that risk, persisted and exported detection records retain only the
URL scheme and host. Path, query and fragment components are removed before
storage and are redacted again during export. The response returned directly to
the submitting browser still contains the analysed URL so the user can verify
what was checked; clients should avoid submitting live secrets in the first
place.

Administrative records can contain a Supabase user identifier and email address
when an authenticated user performs an analysis. These fields support access
control and authorised filtering, are excluded from anonymised exports, and
must be accessible only to approved administrators. Guest records use an
anonymous marker. The current academic prototype does not implement a complete
institutional retention/deletion schedule; a production deployment must define
retention duration, deletion rights, breach handling and administrator audit
requirements before collecting real operational data.
