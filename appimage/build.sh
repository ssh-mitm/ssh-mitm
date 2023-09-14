if [ -d build/appimage/AppDir ]; then
  rm -r build/appimage/AppDir
fi
if [ -f dist/SSH-MITM-x86_64.AppImage ]; then 
  rm dist/SSH-MITM-x86_64.AppImage; 
fi

mkdir -p build/appimage/AppDir

if [ ! -f build/python.tar.zst ]; then
  curl -L -o build/python.tar.zst  https://github.com/indygreg/python-build-standalone/releases/download/20230726/cpython-3.11.4+20230726-x86_64_v2-unknown-linux-gnu-pgo+lto-full.tar.zst
fi
tar --use-compress-program=unzstd -xvf build/python.tar.zst -C build/appimage/AppDir --transform 's/python\/install/python/' python/install

build/appimage/AppDir/python/bin/python3 -m pip install -r requirements-dev.txt .

# install files in AppDir
ln -s python/bin/ssh-mitm build/appimage/AppDir/AppRun
cp appimage/ssh-mitm* build/appimage/AppDir/

# detect machine's architecture
export ARCH=$(uname -m)
# get the missing tools if necessary
if [ ! -x build/appimagetool-$ARCH.AppImage ]; then
  curl -L -o build/appimagetool-$ARCH.AppImage https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-$ARCH.AppImage
  chmod a+x build/appimagetool-$ARCH.AppImage 
fi
# the build command itself:
mkdir -p dist
cd dist
../build/appimagetool-$ARCH.AppImage -u "gh-releases-zsync|ssh-mitm|ssh-mitm|latest|ssh-mitm-x86_64.AppImage.zsync" ../build/appimage/AppDir ssh-mitm-x86_64.AppImage 
