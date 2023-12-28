# Desc: Judge the existence of the Keys directory
if [ ! -d "./Keys" ]; then
    mkdir ./Keys
fi

if [ ! -d "./Keys/errorKeys" ]; then
    mkdir ./Keys/errorKeys
fi

# Desc: Judge the existence of the Keys in the Keys directory
if ls ./Keys/*_KEY* 1> /dev/null 2>&1; then
    rm ./Keys/*_KEY*
fi
# Desc: Generate ssh keys for the VCCD, TBOX, ADD1, and ADD2
ssh-keygen -t ecdsa -b 256 -C "VCCD" -f ./Keys/VCCD_KEY -N ""
ssh-keygen -t ecdsa -b 256 -C "TBOX" -f ./Keys/TBOX_KEY -N ""
ssh-keygen -t ecdsa -b 256 -C "ADD1" -f ./Keys/ADD1_KEY -N ""
ssh-keygen -t ecdsa -b 256 -C "ADD2" -f ./Keys/ADD2_KEY -N ""

# Desc: Convert the ssh keys to PEM format
cp ./Keys/VCCD_KEY ./Keys/VCCD_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/VCCD_KEY_PEM -P "" -N ""

cp ./Keys/TBOX_KEY ./Keys/TBOX_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/TBOX_KEY_PEM -P "" -N ""

cp ./Keys/ADD1_KEY ./Keys/ADD1_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/ADD1_KEY_PEM -P "" -N "" 

cp ./Keys/ADD2_KEY ./Keys/ADD2_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/ADD2_KEY_PEM -P "" -N ""

# Desc: Convert the PEM KEYS to der format
openssl pkcs8 -topk8 -inform PEM -in ./Keys/VCCD_KEY_PEM -outform DER -out ./Keys/VCCD_KEY.der -nocrypt
openssl pkcs8 -topk8 -inform PEM -in ./Keys/TBOX_KEY_PEM -outform DER -out ./Keys/TBOX_KEY.der -nocrypt
openssl pkcs8 -topk8 -inform PEM -in ./Keys/ADD1_KEY_PEM -outform DER -out ./Keys/ADD1_KEY.der -nocrypt
openssl pkcs8 -topk8 -inform PEM -in ./Keys/ADD2_KEY_PEM -outform DER -out ./Keys/ADD2_KEY.der -nocrypt

# Desc: Jugde the existence of the Keys in the errorKeys directory
if ls ./Keys/errorKeys/*_KEY* 1> /dev/null 2>&1; then
    rm ./Keys/errorKeys/*_KEY*
fi

# Desc: build cpp files
rm -rf build
mkdir build
cd build
cmake ..
make clean
make
./test
cd ..

# Desc: convert the openssl keys to the ssh keys
ssh-keygen -p -N "" -f ./Keys/errorKeys/VCCD_KEY 
ssh-keygen -p -N "" -f ./Keys/errorKeys/TBOX_KEY
ssh-keygen -p -N "" -f ./Keys/errorKeys/ADD1_KEY
ssh-keygen -p -N "" -f ./Keys/errorKeys/ADD2_KEY

# Desc: convert the ssh keys to the PEM keys
cp ./Keys/errorKeys/VCCD_KEY ./Keys/errorKeys/VCCD_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/errorKeys/VCCD_KEY_PEM -P "" -N ""
cp ./Keys/errorKeys/TBOX_KEY ./Keys/errorKeys/TBOX_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/errorKeys/TBOX_KEY_PEM -P "" -N ""
cp ./Keys/errorKeys/ADD1_KEY ./Keys/errorKeys/ADD1_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/errorKeys/ADD1_KEY_PEM -P "" -N ""
cp ./Keys/errorKeys/ADD2_KEY ./Keys/errorKeys/ADD2_KEY_PEM
ssh-keygen -p -m PEM -f ./Keys/errorKeys/ADD2_KEY_PEM -P "" -N ""


