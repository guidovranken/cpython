Build:

```sh
mkdir cpython-install

git clone git@github.com:guidovranken/cpython.git
cd cpython
git checkout fuzzing

export CC=clang
export CXX=clang++

./configure --prefix=`realpath ../cpython-install`
make -j$(nproc)
make install

cd Fuzzer
make
```
