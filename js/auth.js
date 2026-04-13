// Auth check — redirect to gate if not authenticated
(function() {
  if (sessionStorage.getItem('nokoribi_auth') !== 'true') {
    window.location.href = '/';
  }
})();
