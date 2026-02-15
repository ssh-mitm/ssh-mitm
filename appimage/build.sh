set -e

# detect machine's architecture
export ARCH=$(uname -m)

# define download urls
python_download_url="https://github.com/astral-sh/python-build-standalone/releases/download/20260211/cpython-3.11.14+20260211-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
appimagetool_download_url="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-$ARCH.AppImage"


# cleanup old build process
if [ -d build/appimage/AppDir ]; then
  rm -r build/appimage/AppDir
fi
if [ -f dist/SSH-MITM-x86_64.AppImage ]; then
  rm dist/SSH-MITM-x86_64.AppImage;
fi


# create new AppImage

mkdir -p build/appimage/AppDir

if [ ! -f build/python.tar.gz ]; then
  curl -L -o build/python.tar.gz  "$python_download_url"
fi
tar -xvf build/python.tar.gz -C build/appimage/AppDir

build/appimage/AppDir/python/bin/python3 -m pip install .[production]

# install files in AppDir
cp appimage/AppRun build/appimage/AppDir/
cp appimage/ssh-mitm* build/appimage/AppDir/

# get the missing tools if necessary
if [ ! -x build/appimagetool-$ARCH.AppImage ]; then
  curl -L -o build/appimagetool-$ARCH.AppImage https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-$ARCH.AppImage
  chmod a+x build/appimagetool-$ARCH.AppImage
fi
# the build command itself:
mkdir -p dist
cd dist
../build/appimagetool-$ARCH.AppImage -u "gh-releases-zsync|ssh-mitm|ssh-mitm|latest|ssh-mitm-x86_64.AppImage.zsync" ../build/appimage/AppDir ssh-mitm-x86_64.AppImage
