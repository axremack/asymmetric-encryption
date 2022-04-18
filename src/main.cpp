//
//  TP6_RSA
//  

#include <stdio.h>
#include <iostream>
#include <gmp.h>
#include <stdlib.h>   
#include <time.h> 
#include <list>
#include <string>
#include <cstring>



#define BITSTRENGTH  14              /* size of modulus (n) in bits */
#define PRIMESIZE (BITSTRENGTH / 2)  /* size of the primes p and q  */

/* Declare global variables */

mpz_t d, e, n, M, c;
gmp_randstate_t state;


// Initializing globally defined GMP integers
void init() {
    mpz_init(d);
    mpz_init(e);
    mpz_init(n);
    mpz_init(M);
    mpz_init(c);
}


// Cleaning up the global GMP integers
void clear() {
    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(M);
    mpz_clear(c);    
}


// Initializing pseudo random generator
void initPseudoRandomGenerator() {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
}


// This function creates the keys using preconstructed MPZ functions. The basic algorithm is... -------
//
//  1. Generate two large distinct primes p and q randomly
//  2. Calculate n = pq and x = (p-1)(q-1)
//  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
//  4. Calculate the unique d such that ed = 1(mod x)
//  5. Public key pair : (e,n), Private key pair : (d,n)
//
// ----------------------------------------------------------------------------------------------------
void creatingKeyPairWithGMP() {
    init();
    
    // ------------------------------------------
    // Step 1 - Getting two large prime numbers
    // ------------------------------------------
    mpz_t p, q, p_temp, q_temp;
    mpz_inits(p, q, p_temp, q_temp);
    
    // Initializing the global pseudo random generator
    initPseudoRandomGenerator();

    // Making p and q random prime numbers
    mpz_urandomb(p_temp, state, PRIMESIZE); // Render random number between 0 and 2 ^ PRIMESIZE
    mpz_nextprime(p, p_temp); // Selecting first prime number after the random number generated
    mpz_urandomb(q_temp, state, PRIMESIZE);
    mpz_nextprime(q, q_temp);

    // Printing results
    char p_str[1000];
    char q_str[1000];
    mpz_get_str(p_str, 10, p); // Converting int to string in base 10
    mpz_get_str(q_str, 10, q);
    
    std::cout << "Random Prime 'p' = " << p_str <<  std::endl;
    std::cout << "Random Prime 'q' = " << q_str <<  std::endl;
    std::cout << std::endl;
    

    // ------------------------------------------
    // Step 2 - Calculating n and x
    // ------------------------------------------
    mpz_t x, p_minus_1, q_minus_1;
    mpz_inits(x, p_minus_1, q_minus_1);

    // Calculating and printing n
    mpz_mul(n, p, q); 
    char n_str[1000];
    mpz_get_str(n_str, 10, n);
    std::cout << "\t n = " << n_str << std::endl;
    
    
    // Calculating and printing x
    mpz_sub_ui(p_minus_1, p, (unsigned long int)1);
    mpz_sub_ui(q_minus_1, q, (unsigned long int)1);
    mpz_mul(x,p_minus_1, q_minus_1);
    char x_str[1000];
    mpz_get_str(x_str, 10, x);
    std::cout << "\t x(n) = " << x_str << std::endl;
    

    // --------------------------------------------------------------------
    // Step 3 - Selecting odd integer e (1<e<x) such that gcd(e,x) = 1
    // Consensus value for e is 65537 but we decided to make it random
    // --------------------------------------------------------------------
    mpz_t e_temp, pgcd;
    mpz_inits(e_temp, pgcd);

    // Selecting e
    do {
        mpz_urandomb(e_temp, state, PRIMESIZE);
        mpz_init_set_str(e, std::to_string(mpz_get_ui(e_temp) % mpz_get_ui(x)).c_str(), 0);
        mpz_gcd(pgcd, e, x);
    } while (mpz_get_ui(pgcd) != 1);

    // Printing results
    char e_str[1000];
    mpz_get_str(e_str, 10, e);
    std::cout << "\t e = " << e_str << std::endl;
    

    // --------------------------------------------------------
    // Step 4 - Calculating unique d such that ed = 1(mod x)
    // --------------------------------------------------------
    mpz_invert(d, e, x);
    char d_str[1000];
    mpz_get_str(d_str,10,d);
    std::cout << "\t d = " << d_str << std::endl << std::endl;
    

    // --------------------------------------------------------
    // Step 5 - Printing the public and private key pairs
    // --------------------------------------------------------
    std::cout << "Public Keys  (e,n): ( " << e_str <<" , " << n_str << " )" << std::endl;
    std::cout << "Private Keys (d,n): ( " << d_str <<" , " << n_str << " )" << std::endl;
    std::cout << std::endl;


    // Cleaning up temporary GMP integers
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(p_temp);
    mpz_clear(q_temp);
    mpz_clear(x);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(e_temp);
    mpz_clear(pgcd);
}


// Computation of large positive integer powers of a number
// g = base
// k = exponent
// p = modulo
// m = resulting encrypted message
void exponentiationBySquaring(mpz_t &g, mpz_t &k, mpz_t &p, mpz_t &m) {
    mpz_t g_temp, k_temp, p_temp;
    mpz_inits(g_temp, k_temp, p_temp);
    mpz_set(g_temp, g);
    mpz_set(k_temp, k);
    mpz_set(p_temp, p);

    if (mpz_cmp_si(k_temp, 0) < 0) {
        mpz_t number_temp;
        mpz_init(number_temp);
        mpz_set_ui(number_temp, 1);

        mpz_fdiv_q(g_temp, number_temp, g_temp);
        mpz_mul_ui(k_temp, k_temp, -1);

        mpz_clear(number_temp);
    }

    if (mpz_cmp_si(k_temp, 0) == 0) {
        mpz_set_ui(m, 1);
        return;
    }

    mpz_t y;
    mpz_init(y);
    mpz_set_ui(y, 1);

    while (mpz_cmp_si(k_temp, 1) > 0) {
        if (mpz_even_p(k_temp) != 0) {          // K is even
            mpz_mul(g_temp, g_temp, g_temp);
            mpz_mod(g_temp, g_temp, p_temp);
            mpz_fdiv_q_ui(k_temp, k_temp, 2);
        } else {                                // K is odd
            mpz_mul(y, g_temp, y);
            mpz_mul(g_temp, g_temp, g_temp);
            mpz_sub_ui(k_temp, k_temp, 1);
            mpz_fdiv_q_ui(k_temp, k_temp, 2);
        }
    }

    mpz_mul(m, g_temp, y);
    mpz_mod(m, m, p_temp);
}


// Determining whether a given number is prime
bool primaltyMillerRabin(int k, mpz_t &n) {
    // Respecting requirements
    if (mpz_get_si(n) <= 2 && mpz_odd_p(n)) {
        return false;
    }

    // Writing n − 1 as t × 2^s by factoring powers of 2 from n − 1
    mpz_t t, s;
    mpz_inits(t, s, NULL);

    mpz_sub_ui(t, n, 1);
    mpz_set_ui(s, 0);

    while (mpz_even_p(t)) {
        mpz_fdiv_q_ui(t, t, 2);
        mpz_add_ui(s, s, 1);
    }

    mpz_t a, x, r, start, end, nMinus1;
    mpz_inits(a, x, r, start, end, nMinus1, NULL);
    mpz_init_set_ui(start, 2);
    mpz_sub_ui(nMinus1, n, 1);
    
    for(int i = 0; i < k; i++) {
        mpz_sub_ui(end, n, 2);                      // end = n - 2
        mpz_urandomm(a, state, end);                // Choosing random between 0 and n-2-1 
        mpz_add(a, a, start);                       // Shifting a for it to be between 2 and n-1
        mpz_powm(x, a, t, n);                       // x = a^t % n	
        
        if(mpz_cmp_ui(x, 1) != 0 && mpz_cmp(x, nMinus1) != 0) {
            for (mpz_set_ui(r, 1); mpz_cmp(r, s) < 0; mpz_add_ui(r, r, 1)) { // For s between 1 and s - 1
                mpz_mul(x, x, x);
                mpz_mod(x, x, n);
                                
                if (mpz_cmp_ui(x, 1) == 0) {
                    return false;
                }

                if (mpz_cmp(x, nMinus1) == 0) {
                    continue;
                }
            }
            return false;
        }
        else {
            continue;
        }
    }
    
    return true;

}

void homemadeNextPrime(mpz_t & next, const mpz_t current) {
    mpz_set(next, current);

    if (mpz_even_p(current) != 0) {
        mpz_add_ui(next, current, 1);
    }

    while (!primaltyMillerRabin(10000, next)) {
        mpz_add_ui(next, next, 2);
    }
}


// Computing the GCD of two numbers in an efficient manner
void euclidianAlgorithm(mpz_t & u, const mpz_t e, const mpz_t x, mpz_t &v) {
    mpz_t r, rbis, ubis, vbis; 
    mpz_init_set(r, e);
    mpz_init_set_ui(u, 1);
    mpz_init_set_ui(v, 0);
    mpz_init_set(rbis, x);
    mpz_init_set_ui(ubis, 0);
    mpz_init_set_ui(vbis, 1);

    mpz_t q, temp, calc;
    mpz_inits(q, temp, calc, NULL);

    while(mpz_cmp_ui(rbis, 0)){
        mpz_fdiv_q(q, r, rbis);

        // Calculating r-q*r'
        mpz_set(temp, rbis);
        mpz_mul(calc, q, rbis);
        mpz_sub(rbis, r , calc);
        mpz_set(r, temp);

        // Calculating u-q*u'
        mpz_set(temp, ubis);
        mpz_mul(calc, q, ubis);
        mpz_sub(ubis, u, calc);
        mpz_set(u, temp);

        // Calculating v-q*v'
        mpz_set(temp, vbis);
        mpz_mul(calc, q, vbis);
        mpz_sub(vbis, v, calc);
        mpz_set(v, temp);
    }

    mpz_clear(r);
    mpz_clear(rbis);
    mpz_clear(ubis);
    mpz_clear(vbis);
    mpz_clear(q);
    mpz_clear(temp);
    mpz_clear(calc);
}

void homemadeInvert(mpz_t & d, const mpz_t e, const mpz_t x) {
    mpz_t v;
    mpz_init(v);

    euclidianAlgorithm(d, e, x, v);
    
    if(mpz_cmp_ui(d, 0) < 0) {
        mpz_add(d, d, x);
    } 

    mpz_clear(v);
}


// This function creates the keys using crafted computation functions. The basic algorithm is... -------
//
//  1. Generate two large distinct primes p and q randomly
//  2. Calculate n = pq and x = (p-1)(q-1)
//  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
//  4. Calculate the unique d such that ed = 1(mod x)
//  5. Public key pair : (e,n), Private key pair : (d,n)
//
// -----------------------------------------------------------------------------------------------------
void creatingKeyPair() {
    init();
    
    // ------------------------------------------
    // Step 1 - Getting two large prime numbers
    // ------------------------------------------
    mpz_t p, q, p_temp, q_temp;
    mpz_inits(p, q, p_temp, q_temp);
    
    // Initializing the global pseudo random generator
    initPseudoRandomGenerator();

    // Making p and q random prime numbers
    mpz_urandomb(p_temp, state, PRIMESIZE); // Render random number between 0 and 2 ^ PRIMESIZE
    homemadeNextPrime(p, p_temp);
    mpz_urandomb(q_temp, state, PRIMESIZE);
    homemadeNextPrime(q, q_temp);

    // Making sure p and q are different
    if (mpz_cmp(q, p) == 0) {
        mpz_urandomb(q_temp, state, PRIMESIZE);
        homemadeNextPrime(q, q_temp);
    }

    // Printing results
    char p_str[1000];
    char q_str[1000];
    mpz_get_str(p_str, 10, p); // Converting int to string in base 10
    mpz_get_str(q_str, 10, q);
    
    std::cout << "Random Prime 'p' = " << p_str <<  std::endl;
    std::cout << "Random Prime 'q' = " << q_str <<  std::endl;
    std::cout << std::endl;


    // ------------------------------------------
    // Step 2 - Calculating n and x
    // ------------------------------------------
    mpz_t x, p_minus_1, q_minus_1;
    mpz_inits(x, p_minus_1, q_minus_1);

    // Calculating and printing n
    mpz_mul(n, p, q); 
    char n_str[1000];
    mpz_get_str(n_str, 10, n);
    std::cout << "\t n = " << n_str << std::endl;
    
    
    // Calculating and printing x
    mpz_sub_ui(p_minus_1, p, (unsigned long int)1);
    mpz_sub_ui(q_minus_1, q, (unsigned long int)1);
    mpz_mul(x,p_minus_1, q_minus_1);
    char x_str[1000];
    mpz_get_str(x_str, 10, x);
    std::cout << "\t x(n) = " << x_str << std::endl;
    

    // --------------------------------------------------------------------
    // Step 3 - Selecting odd integer e (1<e<x) such that gcd(e,x) = 1
    // Consensus value for e is 65537 but we decided to make it random
    // --------------------------------------------------------------------
    mpz_t e_temp, pgcd;
    mpz_inits(e_temp, pgcd);

    // Selecting e
    do {
        mpz_urandomb(e_temp, state, PRIMESIZE);
        mpz_init_set_str(e, std::to_string(mpz_get_ui(e_temp) % mpz_get_ui(x)).c_str(), 0);
        mpz_gcd(pgcd, e, x);
    } while (mpz_get_ui(pgcd) != 1);

    // Printing results
    char e_str[1000];
    mpz_get_str(e_str, 10, e);
    std::cout << "\t e = " << e_str << std::endl;
    

    // --------------------------------------------------------
    // Step 4 - Calculating unique d such that ed = 1(mod x)
    // --------------------------------------------------------
    homemadeInvert(d, e, x);
    char d_str[1000];
    mpz_get_str(d_str,10,d);
    std::cout << "\t d = " << d_str << std::endl << std::endl;
    

    // --------------------------------------------------------
    // Step 5 - Printing the public and private key pairs
    // --------------------------------------------------------
    std::cout << "Public Keys  (e,n): ( " << e_str <<" , " << n_str << " )" << std::endl;
    std::cout << "Private Keys (d,n): ( " << d_str <<" , " << n_str << " )" << std::endl;
    std::cout << std::endl;


    // Cleaning up temporary GMP integers
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(p_temp);
    mpz_clear(q_temp);
    mpz_clear(x);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(e_temp);
    mpz_clear(pgcd);
}


// Encryption of a message (< n) using GMP preconstructed functions
void encryptGMP(char * message, char * chiffr_str) {
    // Setting up and printing message to encrypt
    mpz_init_set_str(M, message, 0);
    size_t size_M = mpz_sizeinbase(M, 10);
    char M_str[1000];
    mpz_get_str(M_str,10,M);
    std::cout << "M = " << M_str << std::endl << std::endl;

    // Encryption
    mpz_t chiffr;
    mpz_init(chiffr);
    mpz_powm(chiffr, M, e, n);
    mpz_get_str(chiffr_str, 10, chiffr);
    std::cout << "M chiffré = " << chiffr_str << std::endl << std::endl;
}


// Encryption of a message (< n) using crafted exponentiation by squaring
void encrypt(char * message, char * chiffr_str) {
    // Setting up and printing message to encrypt
    mpz_init_set_str(M, message, 0);
    size_t size_M = mpz_sizeinbase(M, 10);
    char M_str[1000];
    mpz_get_str(M_str,10,M);
    std::cout << "M = " << M_str << std::endl << std::endl;

    // Encryption
    mpz_t chiffr;
    mpz_init(chiffr);
    exponentiationBySquaring(M, e, n, chiffr);
    mpz_get_str(chiffr_str, 10, chiffr);
    std::cout << "M chiffré = " << chiffr_str << std::endl << std::endl;
}


// Decryption of a message
void decrypt(char * chiffr_str) {
    mpz_t dechiffr, chiffr;
    mpz_inits(dechiffr, chiffr, NULL);
    mpz_init_set_str(chiffr, chiffr_str, 0);
    mpz_powm(dechiffr, chiffr, d, n);

    char dechiffr_str[1000];
    mpz_get_str(dechiffr_str, 10, dechiffr);
    std::cout << "M déchiffré = " << dechiffr_str << std::endl << std::endl;
}


int main() {
    // Subroutine using preconstructed GMP functions
    std::cout << "USING GMP FUNCTIONS ------------------------------------------------------------" << std::endl << std::endl;
    creatingKeyPairWithGMP();
    char message[4] = "44";
    char message_encrypted[1000];
    encryptGMP(message, message_encrypted);
    decrypt(message_encrypted);

    std::cout << std::endl << std::endl;
    clear();


    // Subroutine using crafted functions
    std::cout << "USING CRAFTED FUNCTIONS ------------------------------------------------------------" << std::endl << std::endl;
    creatingKeyPair();
    char message2[4] = "44";
    char message_encrypted2[1000];
    encrypt(message2, message_encrypted2);
    decrypt(message_encrypted2);

    std::cout << std::endl << std::endl;
    clear();
}

