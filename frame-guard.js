// Frame guard (public/index.html says why): the app stays hidden until this runs, and only the top window reveals it.
// Inside a frame it also stops the page from loading, so the app never boots there.
if (self === top) document.documentElement.setAttribute('data-top', '');
else window.stop();
