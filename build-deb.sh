#!/bin/bash
# Builds sloth_<version>_all.deb.
#
# A .deb is an ar archive of three members in order: debian-binary,
# control.tar.gz and data.tar.gz. That means dpkg-dev is not required — this
# builds fine on any machine with ar, tar and gzip, including non-Debian ones.
# If dpkg-deb is present it is used instead, since it also runs the usual
# consistency checks.
set -euo pipefail

VERSION="${VERSION:-2.1.0}"
MAINTAINER="${MAINTAINER:-Sloth <root@localhost>}"

SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$SRC/dist}"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

PKGDIR="$BUILD/pkg"
APP=/usr/lib/sloth

say() { printf '  %s\n' "$*"; }

echo "Building sloth $VERSION"

# --- application files ---------------------------------------------------
install -d "$PKGDIR$APP"
cp -r "$SRC/sloth" "$PKGDIR$APP/"
cp -r "$SRC/templates"     "$PKGDIR$APP/"
cp -r "$SRC/static"        "$PKGDIR$APP/"
install -m 0644 "$SRC/scanner.py" "$PKGDIR$APP/scanner.py"

# Never ship build artefacts or a developer's scan results.
find "$PKGDIR$APP" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$PKGDIR$APP" -name '*.py[co]' -delete
say "application → $APP"

# --- launcher, service, config -------------------------------------------
install -d "$PKGDIR/usr/bin"
install -m 0755 "$SRC/packaging/sloth.launcher" "$PKGDIR/usr/bin/sloth"

install -d "$PKGDIR/lib/systemd/system"
install -m 0644 "$SRC/packaging/sloth.service" \
                "$PKGDIR/lib/systemd/system/sloth.service"

install -d "$PKGDIR/etc/sloth"
install -m 0640 "$SRC/packaging/sloth.conf" \
                "$PKGDIR/etc/sloth/sloth.conf"
say "launcher, systemd unit and /etc config"

# --- documentation -------------------------------------------------------
DOC="$PKGDIR/usr/share/doc/sloth"
install -d "$DOC"
install -m 0644 "$SRC/README.md" "$DOC/README.md"

cat > "$DOC/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: sloth

Files: *
Copyright: Sloth contributors
License: MIT
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 .
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
EOF

# Debian wants the changelog gzipped at maximum compression.
cat > "$BUILD/changelog.Debian" <<EOF
sloth ($VERSION) unstable; urgency=medium

  * Packaged release.

 -- $MAINTAINER  $(date -R)
EOF
gzip -9n -c "$BUILD/changelog.Debian" > "$DOC/changelog.Debian.gz"
chmod 0644 "$DOC/changelog.Debian.gz"
say "documentation and copyright"

# --- permissions ---------------------------------------------------------
find "$PKGDIR" -type d -exec chmod 0755 {} +
find "$PKGDIR$APP" -type f -exec chmod 0644 {} +
chmod 0755 "$PKGDIR/usr/bin/sloth"
chmod 0640 "$PKGDIR/etc/sloth/sloth.conf"
chmod 0750 "$PKGDIR/etc/sloth"

# --- control archive -----------------------------------------------------
CTRL="$BUILD/control"
install -d "$CTRL"
SIZE=$(du -ks "$PKGDIR" | cut -f1)
sed -e "s|@VERSION@|$VERSION|" \
    -e "s|@MAINTAINER@|$MAINTAINER|" \
    -e "s|@SIZE@|$SIZE|" \
    "$SRC/packaging/control" > "$CTRL/control"

for script in postinst prerm postrm; do
    install -m 0755 "$SRC/packaging/$script" "$CTRL/$script"
done

# Marked as a conffile so a local edit survives upgrades.
echo "/etc/sloth/sloth.conf" > "$CTRL/conffiles"

# md5sums covers everything except conffiles, per policy.
( cd "$PKGDIR" && find . -type f ! -path './etc/*' -printf '%P\0' \
  | sort -z | xargs -0 md5sum > "$CTRL/md5sums" )
chmod 0644 "$CTRL/control" "$CTRL/conffiles" "$CTRL/md5sums"
say "control, conffiles, md5sums ($SIZE KiB installed)"

# --- assemble ------------------------------------------------------------
install -d "$OUT"
DEB="$OUT/sloth_${VERSION}_all.deb"
rm -f "$DEB"

if command -v dpkg-deb >/dev/null 2>&1; then
    cp -r "$CTRL" "$PKGDIR/DEBIAN"
    dpkg-deb --root-owner-group --build "$PKGDIR" "$DEB" >/dev/null
    say "built with dpkg-deb"
else
    # Hand-assembled. --owner/--group force root ownership without needing to
    # be root, which is what dpkg-deb --root-owner-group does.
    TAR_OPTS=(--owner=root --group=root --numeric-owner --sort=name
              --mtime=@"${SOURCE_DATE_EPOCH:-$(date +%s)}")
    ( cd "$CTRL"   && tar "${TAR_OPTS[@]}" -czf "$BUILD/control.tar.gz" . )
    ( cd "$PKGDIR" && tar "${TAR_OPTS[@]}" -czf "$BUILD/data.tar.gz" . )
    echo "2.0" > "$BUILD/debian-binary"
    # Order matters: dpkg requires debian-binary first.
    ( cd "$BUILD" && ar rc "$DEB" debian-binary control.tar.gz data.tar.gz )
    say "assembled with ar (dpkg-deb not installed)"
fi

echo
echo "→ $DEB"
ls -lh "$DEB" | awk '{print "  " $5}'
echo
echo "Install with:  sudo apt install $DEB"
