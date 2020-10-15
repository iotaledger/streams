@echo off
mkdir .cmake_build
pushd .cmake_build
cmake -G "Visual Studio 15 2017 Win64" -DNO_STD=OFF -DSTATIC=OFF -DSYNC_CLIENT=ON ..
popd
