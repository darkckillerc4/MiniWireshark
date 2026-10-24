# Logo and images

Everything here is in [`assets/`](assets/), drawn as SVG in the app's own palette (navy `#0f1b2d` to `#1b3354`, accent `#7fbaff`, wave `#4ea1ff` to `#b48cff`). Use them freely when you write about MiniWireshark.

## Logo

<img src="assets/logo.svg" width="128" alt="MiniWireshark logo">

A hub with four devices, and the traffic wave from the banner.

| File | Use |
|---|---|
| [`logo.svg`](assets/logo.svg) | Any size, web pages, documents |
| [`logo-512.png`](assets/logo-512.png) | Avatars, app stores, places that don't take SVG |
| [`logo.ico`](assets/logo.ico) | Windows icon (16, 32, 48, 64 and 256 px), for shortcuts and a future `.exe` |

## Banner and social preview

<img src="assets/social-preview.png" width="640" alt="MiniWireshark social preview">

| File | Use |
|---|---|
| [`banner.svg`](assets/banner.svg) | The top of the README |
| [`social-preview.png`](assets/social-preview.png) | The card shown when the repository link is shared (1280×640) |

To use the social preview on GitHub: open the repository's **Settings → General → Social preview → Edit → Upload an image** and choose `docs/assets/social-preview.png`. GitHub only accepts this upload from the website.

## Icons

One icon for each area of the app, 48×48 SVG. They are used in the README and in [Under the hood](UNDER-THE-HOOD.md).

| | | | | | |
|:-:|:-:|:-:|:-:|:-:|:-:|
| <img src="assets/icons/devices.svg" width="40" alt=""><br>devices | <img src="assets/icons/websites.svg" width="40" alt=""><br>websites | <img src="assets/icons/alerts.svg" width="40" alt=""><br>alerts | <img src="assets/icons/health.svg" width="40" alt=""><br>health | <img src="assets/icons/map.svg" width="40" alt=""><br>map | <img src="assets/icons/packets.svg" width="40" alt=""><br>packets |
| <img src="assets/icons/investigate.svg" width="40" alt=""><br>investigate | <img src="assets/icons/history.svg" width="40" alt=""><br>history | <img src="assets/icons/privacy.svg" width="40" alt=""><br>privacy | <img src="assets/icons/shield.svg" width="40" alt=""><br>shield | <img src="assets/icons/capture.svg" width="40" alt=""><br>capture | <img src="assets/icons/accessibility.svg" width="40" alt=""><br>accessibility |
| <img src="assets/icons/self-maintaining.svg" width="40" alt=""><br>self-maintaining | <img src="assets/icons/tests.svg" width="40" alt=""><br>tests | <img src="assets/icons/speed.svg" width="40" alt=""><br>speed | | | |

## Screenshots

28 pictures, every tab in the light and the dark theme, all from Demo Mode. See [Screenshots](SCREENSHOTS.md). To take them again after a change to the window, run the release gate, which photographs every tab:

```bash
xvfb-run -a python miniwireshark.py --release-gate
```
