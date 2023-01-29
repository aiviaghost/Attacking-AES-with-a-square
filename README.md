# Attacking-AES-with-a-square
An implementation of the "Square attack" on 4 and 5 rounds of AES.

# four
The folder "four" contains a Python implementation of the attack on 4 rounds of AES. This attack boils down to guessing each possible byte of every position of the last round key. However, it turns out we can perform this guessing on each byte separately so computationally we will land somewhere in the region of 16 * 256 = 4096 guesses in the worst case scenario. Due to false positives being a possibility here the actual complexity is a bit higher, but still very reasonable. 

Because the computational load of this attack is very low I chose to take this as an opportunity to learn more about the internals of AES, specifically that it performs a lot of computations in the field GF(2^8). Therefore all relevant computations are done explicitly in this field, represented by the class "GF_256_Polynomial". This of course further adds to the complexity of the attack but it still finishes within 1-3 minutes at most during testing. 

A demo of the attack can be seen by running the script "demo.py". If tqdm is available a progress bar will be displayed showing the progress of the attack. 

```bash
python3 demo.py
```

Tests can be run with the shell script "run_tests.sh".

```bash
./run_tests.sh
```

## Requirements
- [Python 3.8 or later](https://www.python.org/downloads/)

## Optional dependencies
- [tqdm](https://github.com/tqdm/tqdm#installation)

# five
TODO: Write Rust implementation of attack on 5 rounds of AES

## Dependencies
- [rand](https://crates.io/crates/rand)
- [rand_chacha](https://crates.io/crates/rand_chacha)

# Links
- Overview of the attack by David Wong: https://www.davidwong.fr/blockbreakers/square.html
- Paper describing the original attack on the cipher Square: http://cse.iitkgp.ac.in/~debdeep/courses_iitkgp/Crypto/papers/square.pdf
