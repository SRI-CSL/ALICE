#!/bin/bash -u

set -e
sudo apt-get install libffi-dev python-pip build-essential git cmake python-dev libglib2.0-dev libcapstone3 libcapstone-dev libboost-all-dev
sudo pip install --no-deps -r requirements.txt

echo "Installing patchkit"

mkdir build &>/dev/null

cd build

git clone https://github.com/norrathep/patchkit.git && cd patchkit && ./deps.sh && ./install.sh && cd ../
echo "Finished"




echo "Z3"
git clone https://github.com/Z3Prover/z3.git && cd z3 && python scripts/mk_make.py && cd build && make -j8 && sudo make install && cd ../../

echo "Installing Triton"

git clone https://github.com/JonathanSalwan/Triton.git && cd Triton && mkdir build && cd build && cmake .. && make -j8 && sudo make -j install



echo "Install dependecy for cgi-bin (demo server)"

sudo apt-get install apache2 openssh-server

