/**
 * Clear the auth_entity query param on /review.
 */

window.onload = function () {
  url = new URL(window.document.documentURI)
  if (url.pathname == '/review' && url.searchParams.has('auth_entity')) {
    window.history.replaceState(null, '', '/review')
  }
}
