/* Fernhill storefront behaviour: nav/search toggles, announcement rotation,
   sticky header shadow, cookie notice. No dependencies. */
(function () {
  'use strict';
  var d = document;

  d.addEventListener('click', function (e) {
    var t = e.target.closest('[data-fh-toggle]');
    if (!t) return;
    var which = t.getAttribute('data-fh-toggle');
    if (which === 'nav') {
      var open = d.body.classList.toggle('fh-nav-open');
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
    } else if (which === 'search') {
      var s = d.getElementById('fh-search');
      if (!s) return;
      s.hidden = !s.hidden;
      if (!s.hidden) { var i = s.querySelector('input[type=search]'); if (i) i.focus(); }
    }
  });

  var rot = d.querySelector('[data-fh-rotate]');
  if (rot) {
    var msgs = rot.querySelectorAll('span'), idx = 0;
    if (msgs.length > 1) {
      setInterval(function () {
        msgs[idx].classList.remove('is-on');
        idx = (idx + 1) % msgs.length;
        msgs[idx].classList.add('is-on');
      }, 4500);
    }
  }

  var header = d.getElementById('fh-header');
  if (header) {
    var onScroll = function () { header.classList.toggle('is-stuck', window.scrollY > 8); };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  var bar = d.getElementById('fh-cookie');
  if (bar) {
    var seen = null;
    try { seen = localStorage.getItem('fh_cookie'); } catch (err) { /* private mode */ }
    if (!seen) bar.hidden = false;
    bar.addEventListener('click', function (e) {
      var b = e.target.closest('[data-fh-cookie]');
      if (!b) return;
      try { localStorage.setItem('fh_cookie', b.getAttribute('data-fh-cookie')); } catch (err) { /* ignore */ }
      bar.hidden = true;
    });
  }
})();
