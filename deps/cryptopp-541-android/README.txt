This contains pre-built Crypto++ libraries. The libraries contain ARMv7, ARMv7-a, and Neon architectures.

To use the libraries, untar them in place: `tar xzf libcryptopp.tar.gz`.

The following applies to this build (taken from setenv-android.sh):

ANDROID_NDK_ROOT: /opt/android-ndk-r8e/
ANDROID_EABI: arm-linux-androideabi-4.6
ANDROID_API: android-14
ANDROID_ARCH: armv7
ANDROID_SYSROOT: /opt/android-ndk-r8e//platforms/android-14/arch-arm
ANDROID_TOOLCHAIN: /opt/android-ndk-r8e//toolchains/arm-linux-androideabi-4.6/prebuilt/darwin-x86_64/bin
ANDROID_STL_INC: /opt/android-ndk-r8e//sources/cxx-stl/stlport/stlport/
ANDROID_STL_LIB: /opt/android-ndk-r8e//sources/cxx-stl/stlport/libs/armeabi/libstlport_static.a
