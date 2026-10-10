# Extension Icons

The Chrome extension requires PNG format icons in specific sizes (16x16, 48x48, 128x128).

We have provided a base vector icon `icon.svg` which you can use to generate the PNGs.

## How to generate the PNGs:

1. You can use an online converter like [SVG to PNG](https://svgtopng.com/) or an image editor like GIMP, Photoshop, or Inkscape.
2. Export the SVG to the following files in this directory:
   - `icon16.png` (16x16 pixels)
   - `icon48.png` (48x48 pixels)
   - `icon128.png` (128x128 pixels)

Alternatively, for testing purposes, Chrome will sometimes scale up/down a single PNG if named correctly in manifest, but providing exact sizes is best practice.
