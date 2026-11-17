export function safeReturnTo(value: unknown, origin = window.location.origin): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return "/";
  }
  try {
    const url = new URL(value, origin);
    // History parses the returned string a second time. Dot segments may
    // have normalized an ordinary-looking pathname to one starting with //.
    if (url.origin === origin && !url.pathname.startsWith("//")) {
      return url.pathname + url.search + url.hash;
    }
  } catch {
    // Invalid saved state should still let the sign-in callback finish.
  }
  return "/";
}
