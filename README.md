# checksums linux client
Application to verify checksums of files.

## Install .deb file

1. Download .deb file from either of these web pages.   
   a). https://checksums.app/   
   b). https://github.com/chamalsl/checksum_linux_client/releases
2. Run this command to install.
   `sudo apt install ./checksums_{VERSION}_amd64.deb`   

   apt will display this error message.
   > N: Download is performed unsandboxed as root as file 'checksums_{VERSION}_amd64.deb' 
   > couldn't be accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied)

   **Please ignore above error message.**
3. Run application.   
   `checksums`
   

## Build Requirements
1. gtkmm-3.0
2. openssl
3. libcurl
4. libsecret
5. libsoup

* Special thanks to maintainers of above projects

## Build

1. `make` - Build a debug build..
2. `make BUILD=release` - Build a release build.
3. `make BUILD=sanitize_address` - Build with address sanitizer.
4. `make CPPFLAGS="-DLOCAL_DEV"` - Build for local development using web server running on localhost.

Built executable will be saved in build/{BUILD}/checksums.

For debug builds, executable will be saved in build/debug/checksums.
For release builds, executable will be saved in build/release/checksums.

## Run Tests
1. `make tests` - Build tests.
2. `build/debug/run_tests` - Run tests.


## Build Snap Package for Development
1. `export SNAPCRAFT_BUILD_ENVIRONMENT=multipass` - This is required if you have docker installed.
2. `snapcraft pack --verbose`
3. `sudo snap install checksums-app_{VERSION}_amd64.snap --dangerous --devmode`
