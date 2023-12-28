#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <memory>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <sys/stat.h>

using namespace std;

int main(int argc, char **argv)
{
    vector<string> domains{"ADD1", "ADD2", "TBOX", "VCCD"};
    int i = 0;
    vector<string> keyfiles{"../Keys/ADD1_KEY_PEM", "../Keys/ADD2_KEY_PEM", "../Keys/TBOX_KEY_PEM", "../Keys/VCCD_KEY_PEM"};
    string pre="../Keys/errorKeys/";
    for (const auto keys : keyfiles)
    {
        // Read EC_KEY from file
        unique_ptr<EC_KEY, decltype(&EC_KEY_free)> pkey(EC_KEY_new(), EC_KEY_free);
        FILE *fp = fopen(keys.c_str(), "r");
        if (!fp)
        {
            cout << "Error: cannot open file ec_key.pem" << endl;
            return 1;
        }
        pkey.reset(PEM_read_ECPrivateKey(fp, NULL, NULL, NULL));
        fclose(fp);
        if (!pkey)
        {
            cout << "Error: PEM_read_ECPrivateKey returned NULL" << endl;
            return 1;
        }
        // read EC_KEY public key
        // unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pubKey(EC_POINT_new(EC_KEY_get0_group(pkey.get())), EC_POINT_free);
        // if (!EC_POINT_copy(pubKey.get(), EC_KEY_get0_public_key(pkey.get()))) {
        //     cout << "Error: EC_POINT_copy returned NULL" << endl;
        //     return 1;
        // }

        // set private d of EC_KEY
        unique_ptr<BIGNUM, decltype(&BN_free)> privKey(BN_new(), BN_free);
        if (!BN_rand(privKey.get(), 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        {
            cout << "Error: BN_rand returned NULL" << endl;
            return 1;
        }
        if (!EC_KEY_set_private_key(pkey.get(), privKey.get()))
        {
            cout << "Error: EC_KEY_set_private_key returned NULL" << endl;
            return 1;
        }

        // set public key of EC_KEY
        // unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pubKey(EC_POINT_new(EC_KEY_get0_group(pkey.get())), EC_POINT_free);
        // if (!EC_POINT_mul(EC_KEY_get0_group(pkey.get()), pubKey.get(), privKey.get(), NULL, NULL, NULL)) {
        //     cout << "Error: EC_POINT_mul returned NULL" << endl;
        //     return 1;
        // }
        // if (!EC_KEY_set_public_key(pkey.get(), pubKey.get())) {
        //     cout << "Error: EC_KEY_set_public_key returned NULL" << endl;
        //     return 1;
        // }

        // write EC_KEY to file
        string filename = pre + domains[i++]+"_KEY";
        cout<<filename<<endl;
        unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new_file(filename.c_str(), "w"), BIO_free);
        if (!out)
        {
            cout << "Error: BIO_new_file returned NULL" << endl;
            return 1;
        }
        chmod(filename.c_str(), S_IRUSR | S_IWUSR); 
        if (!PEM_write_bio_ECPrivateKey(out.get(), pkey.get(), NULL, NULL, 0, NULL, NULL))
        {
            cout << "Error: PEM_write_bio_ECPrivateKey returned NULL" << endl;
            return 1;
        }
    }

    return 0;
}