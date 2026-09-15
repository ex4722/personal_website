(function () {
  var lightbox = document.getElementById("lightbox");
  if (!lightbox) return;

  var imgEl = document.getElementById("lightbox-img");
  var capEl = document.getElementById("lightbox-cap");
  var countEl = document.getElementById("lightbox-count");
  var triggers = Array.prototype.slice.call(document.querySelectorAll("[data-lightbox-src]"));
  var current = -1;
  var lastFocus = null;

  function captionFor(el) {
    var fig = el.closest("figure");
    var text = "";
    if (fig) {
      var cap = fig.querySelector("figcaption");
      if (cap) text = cap.textContent.trim();
    }
    return text || el.alt || "";
  }

  function show(index) {
    if (index < 0 || index >= triggers.length) return;
    current = index;
    var el = triggers[index];
    imgEl.classList.remove("is-shown");
    imgEl.src = el.getAttribute("data-lightbox-src");
    imgEl.alt = el.alt || "";
    imgEl.onload = function () {
      imgEl.classList.add("is-shown");
    };
    capEl.textContent = captionFor(el) + (triggers.length > 1 ? " · " + (index + 1) + " of " + triggers.length : "");
    countEl.textContent = index + 1 + "/" + triggers.length;
  }

  function open(index, trigger) {
    lastFocus = trigger || document.activeElement;
    show(index);
    lightbox.classList.add("is-open");
    lightbox.setAttribute("aria-hidden", "false");
    lightbox.setAttribute("tabindex", "-1");
    lightbox.focus();
    document.body.style.overflow = "hidden";
  }

  function close() {
    lightbox.classList.remove("is-open");
    lightbox.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function next() {
    show((current + 1) % triggers.length);
  }

  function prev() {
    show((current - 1 + triggers.length) % triggers.length);
  }

  triggers.forEach(function (el, i) {
    el.addEventListener("click", function () {
      open(i, el);
    });
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open(i, el);
      }
    });
  });

  lightbox.addEventListener("click", function (e) {
    if (e.target === lightbox || e.target.classList.contains("lightbox-body")) close();
  });

  lightbox.addEventListener("keydown", function (e) {
    if (e.key === "Escape" || e.key === "q") close();
    else if (e.key === "h" || e.key === "ArrowLeft") prev();
    else if (e.key === "l" || e.key === "ArrowRight") next();
  });

  var touchStartX = null;
  lightbox.addEventListener(
    "touchstart",
    function (e) {
      touchStartX = e.touches[0].clientX;
    },
    { passive: true }
  );
  lightbox.addEventListener(
    "touchend",
    function (e) {
      if (touchStartX === null) return;
      var dx = e.changedTouches[0].clientX - touchStartX;
      if (dx > 50) prev();
      else if (dx < -50) next();
      touchStartX = null;
    },
    { passive: true }
  );
})();
