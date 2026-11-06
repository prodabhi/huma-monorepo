// The Mac app runs on a Mac; everyone else goes straight to the web editor. An iPad also says "Macintosh", but has touch.
// /download#mac shows this page on any computer.
if ((!/Macintosh/.test(navigator.userAgent) || navigator.maxTouchPoints > 1) && location.hash !== '#mac') location.replace('/write');
// Shown when /download/Huma.dmg isn't uploaded yet and sent the visitor back here.
addEventListener('DOMContentLoaded', () => { if (location.hash === '#soon') document.querySelector('.soon').hidden = false; });
