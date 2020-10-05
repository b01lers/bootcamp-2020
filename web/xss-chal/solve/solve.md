## XSS Challenge
The site has an input, and when you press enter, anything you have entered into the input gets put into the DOM. Checking the source code, it doesn't seem like the input is sanitized, so this is an opportunity for XSS.

`<script>alert()</script>` won't work, because the part of the DOM being injected into has already been run.

Something using an event handler, like this, will work: `<img onerror="alert()" src=x>`

Popping an alert() on the page displays the flag.
flag{y0u_sh0uldnt_h4v3_c0m3_b4ck_flynn}