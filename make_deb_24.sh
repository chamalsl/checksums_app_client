VERSION=$(<VERSION)
echo "Creating release for version - ${VERSION}"
RELEASE_FILE=checksums_v${VERSION}_amd64
RELEASE_DIR=release/Ubuntu24/${RELEASE_FILE}
mkdir -p ${RELEASE_DIR}/usr/local/bin
mkdir -p ${RELEASE_DIR}/usr/share/applications/
mkdir -p ${RELEASE_DIR}/usr/share/pixmaps/
mkdir -p ${RELEASE_DIR}/DEBIAN
touch ${RELEASE_DIR}/DEBIAN/control

cp build/release/checksums release/Ubuntu24/
cp build/release/checksums ${RELEASE_DIR}/usr/local/bin/checksums
cp app.checksums.desktop ${RELEASE_DIR}/usr/share/applications/
cp app.checksums.svg ${RELEASE_DIR}/usr/share/pixmaps/

sed -i "s/{VERSION}/${VERSION}/" ${RELEASE_DIR}/usr/share/applications/app.checksums.desktop

echo "Package: checksums" > ${RELEASE_DIR}/DEBIAN/control
echo "Version: ${VERSION}" >> ${RELEASE_DIR}/DEBIAN/control
echo "Architecture: amd64" >> ${RELEASE_DIR}/DEBIAN/control
echo "Maintainer: Chamal De Silva <chamaldesilva@gmail.com>" >> ${RELEASE_DIR}/DEBIAN/control
echo "Description: Program which verifies checksum of a file." >> ${RELEASE_DIR}/DEBIAN/control
echo "Depends: libgtkmm-3.0-1t64 (>= 3.24.9), libcurl4t64 (>= 7.16.2) , libsecret-1-0 (>= 0.21.4-1build3)" >> ${RELEASE_DIR}/DEBIAN/control
cd release/Ubuntu24/
dpkg-deb --build --root-owner-group ${RELEASE_FILE}/

echo "Done"
