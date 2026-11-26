"""Build the HomeXDR brand asset kit (SVG + PNG + ICO) and zip it.

Run:  DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python build_kit.py <out_dir> <zip_path>
Needs cairosvg + Pillow (and Homebrew cairo on macOS).
"""
import io
import os
import sys
import zipfile

import cairosvg
from PIL import Image

NAVY = "#0c1e3f"
CYAN = "#69d8f4"
SIZE = 1024

# ---------------------------------------------------------------- full-detail emblem
# Drawn in the original 1024 grid. Door handle removed; door is a real hole so the
# emblem works on a transparent background with no navy fills.
EMBLEM = f"""
  <g fill="none" stroke="{CYAN}" stroke-linejoin="miter" stroke-miterlimit="10">
    <path stroke-width="24" d="M512 264 L303 330 V490 C303 600 380 690 512 758 C644 690 721 600 721 490 V330 Z"/>
    <path stroke-width="15" d="M397 302 L486 357 M627 302 L538 357 M512 404 V440"/>
    <circle cx="512" cy="372" r="26" stroke-width="16"/>
  </g>
  <g fill="{CYAN}">
    <path d="M512 434 L581 484.6 V459 H613 V508.1 L677 555 L664 572 L512 460 L360 572 L347 555 Z"/>
    <path fill-rule="evenodd" d="M394 682 V564 L512 477 L630 564 V682 H537 V600 H487 V682 Z M409 666 V572 L512 496 L615 572 V666 H552 V585 H472 V666 Z"/>
    <circle cx="512" cy="536" r="12"/>
    <path d="M506 544 L501 568 H523 L518 544 Z"/>
  </g>"""
# outer bounds incl. stroke + miter tips: x 291..733, y 251.4..771.5
EMBLEM_H, EMBLEM_CY = 520.1, 511.45

# ---------------------------------------------------------------- micro emblem (favicons)
# Same shield, hub node and house silhouette; one bold roof stroke, no keyhole,
# thicker strokes everywhere.
MICRO = f"""
  <g fill="none" stroke="{CYAN}" stroke-linejoin="miter" stroke-miterlimit="10">
    <path stroke-width="56" d="M512 264 L303 330 V490 C303 600 380 690 512 758 C644 690 721 600 721 490 V330 Z"/>
    <path stroke-width="32" d="M397 302 L476 350 M627 302 L548 350 M512 412 V460"/>
    <circle cx="512" cy="372" r="30" stroke-width="34"/>
  </g>
  <g fill="{CYAN}">
    <rect x="576" y="462" width="40" height="70"/>
    <path d="M422 560 L512 494 L602 560 V690 H422 Z"/>
  </g>
  <path fill="none" stroke="{CYAN}" stroke-width="54" stroke-linejoin="miter" d="M366 575 L512 468 L658 575"/>
  <rect x="488" y="606" width="48" height="84" fill="{NAVY}"/>"""
MICRO_H, MICRO_CY = 554.0, 512.0


def place(art, art_h, art_cy, fill_frac):
    """Centre `art` on the canvas, scaled so its height is fill_frac of the canvas."""
    s = fill_frac * SIZE / art_h
    return f'<g transform="translate(512 512) scale({s:.5f}) translate(-512 {-art_cy})">{art}\n  </g>'


def svg(body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{SIZE}" height="{SIZE}" '
            f'viewBox="0 0 {SIZE} {SIZE}">\n{body}\n</svg>\n')


def png(svg_text, px):
    return cairosvg.svg2png(bytestring=svg_text.encode(), output_width=px, output_height=px)


def main(out, zip_path):
    os.makedirs(out, exist_ok=True)
    files = {}

    # 1. full-bleed app icon: navy to every edge, emblem inside a 15% safe zone
    app = svg(f'  <rect width="{SIZE}" height="{SIZE}" fill="{NAVY}"/>\n  '
              + place(EMBLEM, EMBLEM_H, EMBLEM_CY, 0.70))
    files["app-icon-1024.svg"] = app.encode()
    files["app-icon-1024.png"] = png(app, 1024)

    # 2. transparent logo (emblem only, 5% margin)
    logo = svg("  " + place(EMBLEM, EMBLEM_H, EMBLEM_CY, 0.90))
    files["logo-transparent-1024.svg"] = logo.encode()
    files["logo-transparent-1024.png"] = png(logo, 1024)

    # 3. rounded navy tile (the approved layout), transparent outside the tile
    rounded = svg(f'  <rect x="106" y="104" width="812" height="816" rx="90" fill="{NAVY}"/>' + EMBLEM)
    files["logo-rounded-1024.png"] = png(rounded, 1024)

    # 4. favicons from the micro variant on a rounded navy square
    fav = svg(f'  <rect width="{SIZE}" height="{SIZE}" rx="180" fill="{NAVY}"/>\n  '
              + place(MICRO, MICRO_H, MICRO_CY, 0.90))
    files["favicon-32.png"] = png(fav, 32)
    files["favicon-16.png"] = png(fav, 16)
    frames = [Image.open(io.BytesIO(png(fav, n))).convert("RGBA") for n in (48, 32, 16)]
    ico = io.BytesIO()
    frames[0].save(ico, format="ICO", sizes=[(48, 48), (32, 32), (16, 16)], append_images=frames[1:])
    files["favicon.ico"] = ico.getvalue()

    for name, data in files.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            z.write(os.path.join(out, name), arcname=f"brand-asset-kit/{name}")
    print("\n".join(f"{n}: {len(d)} bytes" for n, d in sorted(files.items())))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
