/*
 * cpus.c -- CPUS: Code-based PQ-secure User-Server authentication
 *           with a REAL (unoptimised) RQC-I implementation.
 *
 * Build:  gcc -O2 -march=native cpus.c -o cpus -lcrypto
 *         (-march=native enables PCLMULQDQ; without it a portable
 *          shift-and-add multiplier is used and everything is ~10x slower)
 * Run:    ./cpus            protocol + RQC + wrong-key tests
 *         ./cpus bench [N]  timing (N protocol runs, default 20)
 *
 * RQC-I parameters: q=2, m=127, n=113, k=3, w=7, w1=7, w2=6, delta=55,
 *                   P = X^113 + X^9 + 1 (irreducible over F_2),
 *                   F_{2^127} = F_2[x]/(x^127 + x + 1).
 * Gabidulin code: g_j = x^j (j<113), c_j = sum_i m_i * g_j^(2^i).
 * Decoder: linearised-polynomial interpolation (solve a 113x114 linear
 *          system over F_{2^127}), O(n^3). NOT constant time, NOT optimised.
 * KEM: m uniform, theta = SHAKE256(m), c = Enc(pk,m;theta),
 *      K = H3(m||c); decapsulation re-encrypts and aborts on mismatch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#ifdef __PCLMUL__
#include <immintrin.h>
#endif

/* ===================== RQC-I parameters ===================== */
#define MDEG  127
#define NN    113
#define KK    3
#define WW    7
#define W1    7
#define W2    6
#define TAU   55                       /* = (n-k)/2 = delta        */
#define NUNK  ((TAU + 1) + (KK + TAU)) /* 114 unknowns             */
#define NPOW  (KK + TAU)               /* 58 Frobenius powers of g */

#define L      32                      /* ell/8                    */
#define GFB    16                      /* serialized bytes / elem  */
#define M_LEN  (KK * GFB)              /* 48                       */
#define CT_LEN (2 * NN * GFB)          /* 3616 (unpacked)          */

typedef unsigned __int128 gf;
#define MASK127 ((((gf)1) << 127) - 1)

/* ===================== GF(2^127) ===================== */
static gf gf_mul_soft(gf a, gf b)
{
    gf r = 0;
    for (int i = 0; i < MDEG; i++) {
        if ((b >> i) & 1) r ^= a;
        a <<= 1;
        if (a >> 127) a = (a & MASK127) ^ 3;       /* x^127 = x + 1 */
    }
    return r;
}

static gf gf_mul(gf a, gf b)
{
#ifdef __PCLMUL__
    __m128i A = _mm_set_epi64x((long long)(uint64_t)(a >> 64), (long long)(uint64_t)a);
    __m128i B = _mm_set_epi64x((long long)(uint64_t)(b >> 64), (long long)(uint64_t)b);
    __m128i lo  = _mm_clmulepi64_si128(A, B, 0x00);
    __m128i hi  = _mm_clmulepi64_si128(A, B, 0x11);
    __m128i mid = _mm_xor_si128(_mm_clmulepi64_si128(A, B, 0x01),
                                _mm_clmulepi64_si128(A, B, 0x10));
    uint64_t l[2], h[2], m[2];
    _mm_storeu_si128((__m128i *)l, lo);
    _mm_storeu_si128((__m128i *)h, hi);
    _mm_storeu_si128((__m128i *)m, mid);
    uint64_t p0 = l[0], p1 = l[1] ^ m[0], p2 = h[0] ^ m[1], p3 = h[1];
    gf Lo = ((gf)p1 << 64) | p0;
    gf Hi = ((gf)p3 << 64) | p2;                   /* product = Lo + Hi*2^128 */
    gf U  = (Lo >> 127) ^ (Hi << 1);               /* product >> 127          */
    return (Lo & MASK127) ^ U ^ (U << 1);
#else
    return gf_mul_soft(a, b);
#endif
}
static inline gf gf_sqr(gf a) { return gf_mul(a, a); }

static gf gf_inv(gf a)                              /* a^(2^127-2) */
{
    gf e = a, r = 1;
    for (int i = 1; i < MDEG; i++) { e = gf_sqr(e); r = gf_mul(r, e); }
    return r;
}
static gf gf_frob(gf a, int j) { while (j-- > 0) a = gf_sqr(a); return a; }

static int msb128(gf x)
{
    uint64_t hi = (uint64_t)(x >> 64), lo = (uint64_t)x;
    return hi ? 127 - __builtin_clzll(hi) : 63 - __builtin_clzll(lo);
}
static int rank_f2(const gf *v, int n)
{
    gf piv[128]; memset(piv, 0, sizeof piv);
    int rk = 0;
    for (int i = 0; i < n; i++) {
        gf x = v[i];
        while (x) {
            int hb = msb128(x);
            if (piv[hb]) x ^= piv[hb];
            else { piv[hb] = x; rk++; break; }
        }
    }
    return rk;
}
static void gf_ser(uint8_t *o, gf a) { for (int i = 0; i < GFB; i++) o[i] = (uint8_t)(a >> (8 * i)); }
static gf   gf_des(const uint8_t *o) { gf a = 0; for (int i = 0; i < GFB; i++) a |= (gf)o[i] << (8 * i); return a; }

/* ===================== deterministic sampler (SHAKE256) ===================== */
#define RNG_BUF 16384
typedef struct { uint8_t buf[RNG_BUF]; size_t pos; } Rng;

static void rng_init(Rng *r, const uint8_t *seed, size_t sl)
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_shake256(), NULL);
    EVP_DigestUpdate(c, seed, sl);
    EVP_DigestFinalXOF(c, r->buf, RNG_BUF);
    EVP_MD_CTX_free(c);
    r->pos = 0;
}
static void rng_fresh(Rng *r) { uint8_t s[32]; RAND_bytes(s, 32); rng_init(r, s, 32); }
static void rng_bytes(Rng *r, uint8_t *o, size_t n)
{
    if (r->pos + n > RNG_BUF) { fprintf(stderr, "rng exhausted\n"); exit(2); }
    memcpy(o, r->buf + r->pos, n); r->pos += n;
}
static gf rng_gf(Rng *r) { uint8_t b[GFB]; rng_bytes(r, b, GFB); return gf_des(b) & MASK127; }
static gf rand_gf(void) { uint8_t b[GFB]; RAND_bytes(b, GFB); return gf_des(b) & MASK127; }
static unsigned rng_u16(Rng *r) { uint8_t b[2]; rng_bytes(r, b, 2); return b[0] | (b[1] << 8); }

/* basis of dimension d (first `fixed` already set), independent over F_2 */
static void sample_basis(Rng *r, gf *B, int fixed, int d)
{
    for (int i = fixed; i < d; i++) {
        do { B[i] = rng_gf(r); } while (rank_f2(B, i + 1) != i + 1);
    }
}
static void sample_vec(Rng *r, gf *v, const gf *B, int d)
{
    for (int i = 0; i < NN; i++) {
        unsigned bits = rng_u16(r) & ((1u << d) - 1);
        gf a = 0;
        for (int j = 0; j < d; j++) if ((bits >> j) & 1) a ^= B[j];
        v[i] = a;
    }
}

/* ===================== ring F_{2^m}[X]/(X^113+X^9+1) ===================== */
static void ring_mul(gf *r, const gf *a, const gf *b)
{
    gf t[2 * NN - 1]; memset(t, 0, sizeof t);
    for (int i = 0; i < NN; i++) {
        if (!a[i]) continue;
        for (int j = 0; j < NN; j++) t[i + j] ^= gf_mul(a[i], b[j]);
    }
    for (int i = 2 * NN - 2; i >= NN; i--) { t[i - NN + 9] ^= t[i]; t[i - NN] ^= t[i]; }
    memcpy(r, t, NN * sizeof(gf));
}

/* Gabidulin evaluation points: GP[j][s] = g_j^(2^s), g_j = x^j */
static gf GP[NN][NPOW];
static void gab_init(void)
{
    for (int j = 0; j < NN; j++) {
        gf g = ((gf)1) << j;
        for (int s = 0; s < NPOW; s++) { GP[j][s] = g; g = gf_sqr(g); }
    }
}

/* ===================== RQC.PKE / KEM ===================== */
typedef struct { gf h[NN], S[NN]; uint8_t hb[NN * GFB]; } rqc_pk;
typedef struct { gf x[NN], y[NN]; } rqc_sk;

static void rqc_keygen(rqc_pk *pk, rqc_sk *sk)
{
    Rng r; gf F[WW], xy[2 * NN];
    rng_fresh(&r);
    for (;;) {
        F[0] = 1; sample_basis(&r, F, 1, WW);           /* 1 in support */
        sample_vec(&r, sk->x, F, WW);
        sample_vec(&r, sk->y, F, WW);
        memcpy(xy, sk->x, sizeof(gf) * NN); memcpy(xy + NN, sk->y, sizeof(gf) * NN);
        if (rank_f2(xy, 2 * NN) == WW) break;
    }
    do { for (int i = 0; i < NN; i++) pk->h[i] = rng_gf(&r); } while (!pk->h[0] && !pk->h[1]);
    ring_mul(pk->S, pk->h, sk->y);
    for (int i = 0; i < NN; i++) pk->S[i] ^= sk->x[i];   /* S = x + h*y */
    for (int i = 0; i < NN; i++) gf_ser(pk->hb + i * GFB, pk->h[i]);
}

static void ct_ser(uint8_t *ct, const gf *c1, const gf *c2)
{
    for (int i = 0; i < NN; i++) { gf_ser(ct + i * GFB, c1[i]); gf_ser(ct + (NN + i) * GFB, c2[i]); }
}

/* deterministic encryption: theta = SHAKE256(m) (the function G) */
static void rqc_encrypt_det(const rqc_pk *pk, const gf m[KK], uint8_t ct[CT_LEN])
{
    uint8_t mb[M_LEN]; Rng r;
    for (int i = 0; i < KK; i++) gf_ser(mb + i * GFB, m[i]);
    rng_init(&r, mb, M_LEN);

    gf Eb[W1 + W2], r1[NN], r2[NN], e[NN], tmp[2 * NN];
    for (;;) {
        sample_basis(&r, Eb, 0, W1 + W2);                /* E1 = first W1 */
        sample_vec(&r, r1, Eb, W1);
        sample_vec(&r, r2, Eb, W1);
        sample_vec(&r, e, Eb, W1 + W2);
        memcpy(tmp, r1, sizeof(gf) * NN); memcpy(tmp + NN, r2, sizeof(gf) * NN);
        if (rank_f2(tmp, 2 * NN) == W1 && rank_f2(e, NN) == W1 + W2) break;
    }
    gf c1[NN], c2[NN];
    ring_mul(c1, pk->h, r2);
    ring_mul(c2, pk->S, r2);
    for (int j = 0; j < NN; j++) {
        c1[j] ^= r1[j];
        gf mg = 0;
        for (int i = 0; i < KK; i++) mg ^= gf_mul(m[i], GP[j][i]);
        c2[j] ^= mg ^ e[j];
    }
    ct_ser(ct, c1, c2);
}

/* Gabidulin decoding via linearised-polynomial interpolation */
static gf A[NN][NUNK];
static int gab_decode(const gf *t, gf m[KK])
{
    for (int i = 0; i < NN; i++) {
        gf p = t[i];
        for (int j = 0; j <= TAU; j++) { A[i][j] = p; p = gf_sqr(p); }
        for (int s = 0; s < NPOW; s++) A[i][TAU + 1 + s] = GP[i][s];
    }
    int pivcol[NN], rk = 0;
    char ispiv[NUNK]; memset(ispiv, 0, sizeof ispiv);
    for (int c = 0; c < NUNK && rk < NN; c++) {
        int p = -1;
        for (int i = rk; i < NN; i++) if (A[i][c]) { p = i; break; }
        if (p < 0) continue;
        if (p != rk) for (int k = 0; k < NUNK; k++) { gf x = A[p][k]; A[p][k] = A[rk][k]; A[rk][k] = x; }
        gf iv = gf_inv(A[rk][c]);
        for (int k = c; k < NUNK; k++) A[rk][k] = gf_mul(A[rk][k], iv);
        for (int i = 0; i < NN; i++) {
            if (i == rk || !A[i][c]) continue;
            gf f = A[i][c];
            for (int k = c; k < NUNK; k++) A[i][k] ^= gf_mul(f, A[rk][k]);
        }
        pivcol[rk] = c; ispiv[c] = 1; rk++;
    }
    int fc = -1;
    for (int c = 0; c < NUNK; c++) if (!ispiv[c]) { fc = c; break; }
    if (fc < 0) return -1;
    gf z[NUNK]; memset(z, 0, sizeof z);
    z[fc] = 1;
    for (int r = 0; r < rk; r++) z[pivcol[r]] = A[r][fc];

    gf *lam = z, *nn = z + TAU + 1;
    int d = -1;
    for (int j = TAU; j >= 0; j--) if (lam[j]) { d = j; break; }
    if (d < 0) return -1;
    gf il = gf_inv(lam[d]);
    gf f[KK];
    for (int l = KK - 1; l >= 0; l--) {
        int s = d + l;
        gf rhs = nn[s];
        for (int j = 0; j < d; j++) {
            int lp = s - j;
            if (lp > l && lp <= KK - 1) rhs ^= gf_mul(lam[j], gf_frob(f[lp], j));
        }
        f[l] = gf_frob(gf_mul(rhs, il), MDEG - d);       /* undo Frobenius^d */
    }
    for (int s = 0; s < KK + TAU; s++) {                 /* consistency check N = Lam o f */
        gf acc = 0;
        for (int j = 0; j <= TAU && j <= s; j++) {
            int l = s - j;
            if (l < KK) acc ^= gf_mul(lam[j], gf_frob(f[l], j));
        }
        if (acc != nn[s]) return -1;
    }
    for (int i = 0; i < KK; i++) m[i] = f[i];
    return 0;
}

/* decapsulation core: decrypt + FO re-encryption check */
static int rqc_decrypt_checked(const rqc_sk *sk, const rqc_pk *pk,
                               const uint8_t ct[CT_LEN], uint8_t mb[M_LEN])
{
    gf c1[NN], c2[NN], t[NN], cy[NN], m[KK];
    for (int i = 0; i < NN; i++) {
        c1[i] = gf_des(ct + i * GFB); c2[i] = gf_des(ct + (NN + i) * GFB);
        if ((c1[i] >> 127) || (c2[i] >> 127)) return -1;   /* non-canonical */
    }
    ring_mul(cy, c1, sk->y);
    for (int i = 0; i < NN; i++) t[i] = c2[i] ^ cy[i];     /* t = c2 - c1*y */
    if (gab_decode(t, m)) return -1;
    static uint8_t ct2[CT_LEN];
    rqc_encrypt_det(pk, m, ct2);
    if (CRYPTO_memcmp(ct, ct2, CT_LEN)) return -1;          /* re-encryption check */
    for (int i = 0; i < KK; i++) gf_ser(mb + i * GFB, m[i]);
    return 0;
}

/* ===================== hashes ===================== */
enum { H0 = 0, H1 = 1, H2 = 2, H3 = 3, HKDF = 4 };
static void H(int tag, uint8_t out[L], int n, ...)
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    uint8_t t = (uint8_t)tag; unsigned int ol = L; va_list ap;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, &t, 1);
    va_start(ap, n);
    for (int i = 0; i < n; i++) {
        const void *p = va_arg(ap, const void *); size_t l = va_arg(ap, size_t);
        EVP_DigestUpdate(c, p, l);
    }
    va_end(ap);
    EVP_DigestFinal_ex(c, out, &ol);
    EVP_MD_CTX_free(c);
}
static int eq(const uint8_t *a, const uint8_t *b, size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }
static void hex(const char *lbl, const uint8_t *b, size_t n)
{ printf("  %-14s", lbl); for (size_t i = 0; i < 8 && i < n; i++) printf("%02x", b[i]); printf("...\n"); }

/* ===================== parties ===================== */
typedef struct {
    uint8_t idu[L], ids[L], pw[L];
    rqc_pk  pk;
    uint8_t ns[L], nu[L], K[L], sk[L], ids_cand[L];
} User;

typedef struct {
    rqc_pk pk; rqc_sk sk;
    uint8_t idu[L], ids_old[L], ids_new[L];
    int has_new;
    uint8_t ns[L], ids_used[L];
    int decode_count;
} Server;

static void registration(User *u, Server *s, const char *id_raw, const char *pw)
{
    uint8_t salt[L], X[L], r[L];
    H(H0, u->idu, 1, id_raw, strlen(id_raw));
    H(12, u->pw, 1, pw, strlen(pw));
    RAND_bytes(salt, L);
    H(H1, X, 3, u->idu, (size_t)L, u->pw, (size_t)L, salt, (size_t)L);
    memcpy(s->idu, u->idu, L);
    RAND_bytes(r, L);
    H(H1, s->ids_old, 3, s->idu, (size_t)L, X, (size_t)L, r, (size_t)L);
    s->has_new = 0;
    memcpy(u->ids, s->ids_old, L);
    memcpy(&u->pk, &s->pk, sizeof(rqc_pk));
}

/* Step 1 (server) */
static int srv_msg2(Server *s, const uint8_t ids[L], uint8_t A1[L], uint8_t A2[L])
{
    if (!eq(ids, s->ids_old, L) && !(s->has_new && eq(ids, s->ids_new, L))) return -1;
    memcpy(s->ids_used, ids, L);
    RAND_bytes(s->ns, L);
    for (int i = 0; i < L; i++) A1[i] = s->idu[i] ^ s->ns[i];
    H(H2, A2, 4, s->pk.hb, (size_t)(NN * GFB), s->idu, (size_t)L, ids, (size_t)L, s->ns, (size_t)L);
    return 0;
}

/* Steps 1-2 (user): check A2, ONE RQC encryption, Auth_U */
static int usr_msg3(User *u, const uint8_t A1[L], const uint8_t A2[L],
                    uint8_t ct[CT_LEN], uint8_t nu[L], uint8_t authU[L])
{
    uint8_t A2c[L], mb[M_LEN]; gf m[KK];
    for (int i = 0; i < L; i++) u->ns[i] = A1[i] ^ u->idu[i];
    H(H2, A2c, 4, u->pk.hb, (size_t)(NN * GFB), u->idu, (size_t)L, u->ids, (size_t)L, u->ns, (size_t)L);
    if (!eq(A2, A2c, L)) return -1;

    Rng r; rng_fresh(&r);
    for (int i = 0; i < KK; i++) m[i] = rng_gf(&r);          /* m <-$ F_{q^m}^k */
    RAND_bytes(u->nu, L);
    rqc_encrypt_det(&u->pk, m, ct);
    for (int i = 0; i < KK; i++) gf_ser(mb + i * GFB, m[i]);
    H(H3, u->K, 2, mb, (size_t)M_LEN, ct, (size_t)CT_LEN);
    H(HKDF, u->sk, 3, u->K, (size_t)L, u->nu, (size_t)L, u->ns, (size_t)L);
    H(H2, authU, 4, u->sk, (size_t)L, u->idu, (size_t)L, u->nu, (size_t)L, u->ns, (size_t)L);
    H(H1, u->ids_cand, 2, u->K, (size_t)L, u->ids, (size_t)L);
    memcpy(nu, u->nu, L);
    OPENSSL_cleanse(mb, M_LEN); OPENSSL_cleanse(m, sizeof m);
    return 0;
}

/* Step 3 (server): decode + re-encrypt check, verify, update, Auth_S */
static int srv_msg4(Server *s, const uint8_t ct[CT_LEN], const uint8_t nu[L],
                    const uint8_t authU[L], uint8_t authS[L], uint8_t sk_out[L])
{
    uint8_t mb[M_LEN], K2[L], sk2[L], exp[L], ids_new[L];
    s->decode_count++;
    if (rqc_decrypt_checked(&s->sk, &s->pk, ct, mb)) return -2;   /* decapsulation abort */
    H(H3, K2, 2, mb, (size_t)M_LEN, ct, (size_t)CT_LEN);
    H(HKDF, sk2, 3, K2, (size_t)L, nu, (size_t)L, s->ns, (size_t)L);
    H(H2, exp, 4, sk2, (size_t)L, s->idu, (size_t)L, nu, (size_t)L, s->ns, (size_t)L);
    if (!eq(exp, authU, L)) return -1;

    if (s->has_new && eq(s->ids_used, s->ids_new, L)) memcpy(s->ids_old, s->ids_new, L);
    H(H1, ids_new, 2, K2, (size_t)L, s->ids_used, (size_t)L);
    memcpy(s->ids_new, ids_new, L);
    s->has_new = 1;
    H(H2, authS, 4, sk2, (size_t)L, s->ids_new, (size_t)L, nu, (size_t)L, s->ns, (size_t)L);
    memcpy(sk_out, sk2, L);
    return 0;
}

/* Step 4 (user) */
static int usr_finish(User *u, const uint8_t authS[L])
{
    uint8_t exp[L];
    H(H2, exp, 4, u->sk, (size_t)L, u->ids_cand, (size_t)L, u->nu, (size_t)L, u->ns, (size_t)L);
    if (!eq(exp, authS, L)) return -1;
    memcpy(u->ids, u->ids_cand, L);
    return 0;
}

enum { OK = 0, DROP_MSG4 = 1, TAMPER_C2 = 2, BAD_IDS = 3, TAMPER_C1 = 4 };
static int run(User *u, Server *s, int fault, uint8_t sku[L], uint8_t sks[L], int quiet)
{
    static uint8_t ct[CT_LEN];
    uint8_t ids[L], A1[L], A2[L], nu[L], aU[L], aS[L];
    memcpy(ids, u->ids, L);
    if (fault == BAD_IDS) ids[0] ^= 1;
#define SAY(...) do { if (!quiet) printf(__VA_ARGS__); } while (0)
    if (srv_msg2(s, ids, A1, A2))        { SAY("  [S] unknown IDS -> rejected (no decode)\n"); return -1; }
    if (usr_msg3(u, A1, A2, ct, nu, aU)) { SAY("  [U] A2 check failed\n"); return -2; }
    if (fault == TAMPER_C2) ct[(NN + 5) * GFB + 3] ^= 1;
    if (fault == TAMPER_C1) ct[7 * GFB + 1] ^= 4;
    int rc = srv_msg4(s, ct, nu, aU, aS, sks);
    if (rc == -2)                        { SAY("  [S] decapsulation failed (re-encryption check) -> abort\n"); return -3; }
    if (rc)                              { SAY("  [S] Auth_U invalid -> abort\n"); return -3; }
    SAY("  [S] user authenticated\n");
    if (fault == DROP_MSG4)              { SAY("  [N] message 4 lost\n"); return -4; }
    if (usr_finish(u, aS))               { SAY("  [U] Auth_S invalid -> abort\n"); return -5; }
    SAY("  [U] server authenticated\n");
    memcpy(sku, u->sk, L);
    return 0;
}

/* ===================== parameter report ===================== */
static void print_params(void)
{
    static int printed = 0;          /* print the parameter block only once */
    if (printed) return;
    printed = 1;
    puts("==================== RQC-I parameters used ====================");
    printf("  q (base field F_q)            : 2\n");
    printf("  m (extension degree)          : %d     F_{q^m} = F_2[x]/(x^127 + x + 1)\n", MDEG);
    printf("  n (code length)               : %d\n", NN);
    printf("  k (Gabidulin dimension)       : %d\n", KK);
    printf("  delta (decoding radius)       : %d     = (n-k)/2\n", TAU);
    printf("  w  (rank weight of x,y)       : %d     1 in Supp(x,y)\n", WW);
    printf("  w1 (rank weight of r1,r2)     : %d\n", W1);
    printf("  w2 (extra weight of e)        : %d     ||e|| = w1+w2 = %d\n", W2, W1 + W2);
    printf("  P (ring modulus over F_2)     : X^113 + X^9 + 1\n");
    printf("  Gabidulin points g_j          : x^j, j = 0..%d  (F_2-independent)\n", NN - 1);
    printf("  Worst-case error rank bound   : w*w1 + w2 = %d  (<= delta)\n", WW * W1 + W2);
    puts("---------------------- derived sizes --------------------------");
    printf("  |PK_S| = (h,S) packed         : %d bytes\n", (2 * NN * MDEG + 7) / 8);
    printf("  |SK_S| = (x,y) packed         : %d bytes\n", (2 * NN * MDEG + 7) / 8);
    printf("  |CT| = (c1,c2) packed         : %d bytes  (this code stores %d B unpacked)\n",
           (2 * NN * MDEG + 7) / 8, CT_LEN);
    printf("  message m in F_{q^m}^k        : %d bytes  (%d x %d bits)\n", M_LEN, KK, MDEG);
    puts("---------------------- symmetric layer ------------------------");
    printf("  H0..H3, KDF                   : SHA-256 with 1-byte domain tags, ell = %d bits\n", 8 * L);
    puts("  G (seed expander)             : SHAKE256");
    printf("  nonce size                    : %d bits\n", 8 * L);
    puts("===============================================================\n");
}

/* ===================== tests ===================== */
static int g_fail = 0;
#define CHECK(c, msg) do { int ok_ = (c); printf("  %s %s\n", ok_ ? "[PASS]" : "[FAIL]", msg); if (!ok_) g_fail++; } while (0)

static double now_ms(void)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }

static void test_field_and_rqc(void)
{
    puts("== Test 0: field arithmetic and RQC-I correctness ==");
    Rng r; rng_fresh(&r);
    int okmul = 1, okinv = 1, okdist = 1;
    for (int i = 0; i < 2000; i++) {
        gf a = rand_gf(), b = rand_gf(), c = rand_gf();
        if (gf_mul(a, b) != gf_mul_soft(a, b)) okmul = 0;
        if (gf_mul(a, b) != gf_mul(b, a)) okmul = 0;
        if (gf_mul(a, b ^ c) != (gf_mul(a, b) ^ gf_mul(a, c))) okdist = 0;
        if (a && gf_mul(a, gf_inv(a)) != 1) okinv = 0;
    }
    CHECK(okmul, "multiplication matches reference, commutative");
    CHECK(okdist, "distributive law");
    CHECK(okinv, "inverse: a * a^-1 = 1");
    CHECK(gf_frob(rand_gf(), MDEG) != 0, "frobenius sanity");
    { gf a = rand_gf(); CHECK(gf_frob(a, MDEG) == a, "a^(2^127) = a"); }

    int ok = 1, trials = 10;
    rqc_pk pk; rqc_sk sk; rqc_keygen(&pk, &sk);
    {   gf xy[2 * NN];
        memcpy(xy, sk.x, sizeof(gf) * NN); memcpy(xy + NN, sk.y, sizeof(gf) * NN);
        CHECK(rank_f2(xy, 2 * NN) == WW, "secret (x,y) has rank weight w = 7");
        gf one_in = 0; (void)one_in; }
    static uint8_t ct[CT_LEN]; uint8_t mb[M_LEN], mb2[M_LEN];
    for (int t = 0; t < trials; t++) {
        gf m[KK]; for (int i = 0; i < KK; i++) m[i] = rand_gf();
        for (int i = 0; i < KK; i++) gf_ser(mb + i * GFB, m[i]);
        rqc_encrypt_det(&pk, m, ct);
        if (rqc_decrypt_checked(&sk, &pk, ct, mb2) || memcmp(mb, mb2, M_LEN)) ok = 0;
    }
    CHECK(ok, "Dec(Enc(m)) = m for 10 random messages (zero failure)");

    /* error weight really is at the decoding radius, and decoding still works */
    {   gf m[KK]; for (int i = 0; i < KK; i++) m[i] = rand_gf();
        rqc_encrypt_det(&pk, m, ct);
        gf c1[NN], c2[NN], cy[NN], t[NN], cw[NN];
        for (int i = 0; i < NN; i++) { c1[i] = gf_des(ct + i * GFB); c2[i] = gf_des(ct + (NN + i) * GFB); }
        ring_mul(cy, c1, sk.y);
        for (int i = 0; i < NN; i++) {
            t[i] = c2[i] ^ cy[i];
            gf mg = 0; for (int k = 0; k < KK; k++) mg ^= gf_mul(m[k], GP[i][k]);
            cw[i] = t[i] ^ mg;
        }
        int rw = rank_f2(cw, NN);
        printf("  [info] measured error rank = %d (decoding radius delta = %d)\n", rw, TAU);
        CHECK(rw <= TAU, "error rank <= delta");
    }
    /* decoder must fail / be rejected for a tampered ciphertext */
    {   gf m[KK]; for (int i = 0; i < KK; i++) m[i] = rand_gf();
        rqc_encrypt_det(&pk, m, ct);
        ct[(NN + 9) * GFB] ^= 1;
        CHECK(rqc_decrypt_checked(&sk, &pk, ct, mb2) != 0, "tampered ciphertext rejected by FO check");
    }
    /* wrong secret key */
    {   rqc_pk pk2; rqc_sk sk2; rqc_keygen(&pk2, &sk2);
        gf m[KK]; for (int i = 0; i < KK; i++) m[i] = rand_gf();
        rqc_encrypt_det(&pk, m, ct);
        CHECK(rqc_decrypt_checked(&sk2, &pk, ct, mb2) != 0, "decryption with wrong secret key fails");
    }
}

static void test_protocol(void)
{
    static User u; static Server s; uint8_t sku[L], sks[L];
    memset(&s, 0, sizeof s);
    rqc_keygen(&s.pk, &s.sk);
    registration(&u, &s, "alice@iot-device-17", "correct horse");

    puts("== Test 1: normal mutual authentication ==");
    uint8_t ids_before[L]; memcpy(ids_before, u.ids, L);
    CHECK(run(&u, &s, OK, sku, sks, 0) == 0, "handshake completes");
    CHECK(eq(sku, sks, L), "sk_U == sk_S");
    CHECK(eq(u.ids, s.ids_new, L), "IDS_new synchronized");
    CHECK(eq(ids_before, s.ids_old, L), "server retains IDS_old");
    hex("sk:", sku, L); hex("IDS_new:", u.ids, L);

    puts("== Test 2: second session (pseudonym rotates) ==");
    uint8_t prev[L]; memcpy(prev, u.ids, L);
    CHECK(run(&u, &s, OK, sku, sks, 0) == 0 && eq(sku, sks, L), "handshake + key agreement");
    CHECK(!eq(prev, u.ids, L), "pseudonym changed (unlinkable)");
    CHECK(eq(u.ids, s.ids_new, L), "state synchronized");

    puts("== Test 3: message 4 lost (desynchronization) ==");
    memcpy(prev, u.ids, L);
    CHECK(run(&u, &s, DROP_MSG4, sku, sks, 0) == -4, "final message dropped");
    CHECK(eq(u.ids, prev, L), "user keeps old IDS");
    CHECK(run(&u, &s, OK, sku, sks, 0) == 0 && eq(sku, sks, L), "retry succeeds via IDS_old");
    CHECK(eq(u.ids, s.ids_new, L), "re-synchronized");

    puts("== Test 4: tampered ciphertext (MITM) ==");
    CHECK(run(&u, &s, TAMPER_C2, sku, sks, 0) == -3, "server rejects modified c2");
    CHECK(run(&u, &s, TAMPER_C1, sku, sks, 0) == -3, "server rejects modified c1");

    puts("== Test 5: unknown pseudonym / DoS early rejection ==");
    int before = s.decode_count;
    CHECK(run(&u, &s, BAD_IDS, sku, sks, 0) == -1, "request rejected");
    CHECK(s.decode_count == before, "no decoding performed");

    puts("== Test 6: replay of old message 3 under new server nonce ==");
    {
        static uint8_t ct[CT_LEN];
        uint8_t ids[L], A1[L], A2[L], nu[L], aU[L], aS[L], k[L];
        srv_msg2(&s, u.ids, A1, A2);
        usr_msg3(&u, A1, A2, ct, nu, aU);
        srv_msg4(&s, ct, nu, aU, aS, k);
        usr_finish(&u, aS);
        memcpy(ids, u.ids, L);
        srv_msg2(&s, ids, A1, A2);
        CHECK(srv_msg4(&s, ct, nu, aU, aS, k) != 0, "replayed (c,nonce_U,Auth_U) rejected");
    }

    puts("== Test 7: wrong server key (server holds a different SK) ==");
    {
        static Server bad; static User v; uint8_t k1[L], k2[L];
        memcpy(&bad, &s, sizeof bad);
        rqc_pk pkx; rqc_keygen(&pkx, &bad.sk);        /* wrong SK, same PK at user */
        bad.decode_count = 0;
        uint8_t ids_v[L];
        memcpy(&v, &u, sizeof v); memcpy(ids_v, v.ids, L);
        CHECK(run(&v, &bad, OK, k1, k2, 0) == -3, "server without correct SK cannot complete");
        CHECK(eq(v.ids, ids_v, L), "user IDS unchanged");
    }

    puts("== Test 8: impostor server (passes Step 1 using public data) ==");
    {
        /* Impostor knows h, ID_U and the pseudonym (worst case for Step 1) */
        static uint8_t ct[CT_LEN]; static User v;
        uint8_t A1[L], A2[L], nu[L], aU[L], forged[L], ns[L], ids_v[L];
        memcpy(&v, &u, sizeof v); memcpy(ids_v, v.ids, L);
        RAND_bytes(ns, L);
        for (int i = 0; i < L; i++) A1[i] = v.idu[i] ^ ns[i];
        H(H2, A2, 4, s.pk.hb, (size_t)(NN * GFB), v.idu, (size_t)L, v.ids, (size_t)L, ns, (size_t)L);
        int rc = usr_msg3(&v, A1, A2, ct, nu, aU);
        CHECK(rc == 0, "impostor passes the lightweight Step-1 check (as the paper states)");
        RAND_bytes(forged, L);
        CHECK(usr_finish(&v, forged) != 0, "random Auth_S rejected at Step 4");
        /* best effort: derive keys from a failed/garbage decapsulation */
        uint8_t zero[M_LEN] = {0}, K0[L], sk0[L], ids0[L];
        H(H3, K0, 2, zero, (size_t)M_LEN, ct, (size_t)CT_LEN);
        H(HKDF, sk0, 3, K0, (size_t)L, nu, (size_t)L, ns, (size_t)L);
        H(H1, ids0, 2, K0, (size_t)L, v.ids, (size_t)L);
        H(H2, forged, 4, sk0, (size_t)L, ids0, (size_t)L, nu, (size_t)L, ns, (size_t)L);
        CHECK(usr_finish(&v, forged) != 0, "Auth_S built without m rejected at Step 4");
        CHECK(eq(v.ids, ids_v, L), "user does not commit IDS, does not accept sk");
    }
}

/* ===================== benchmark ===================== */
typedef struct { double sum, sumsq, mn, mx; int n; } Stat;
static void st_add(Stat *s, double x)
{ s->sum += x; s->sumsq += x * x; if (!s->n || x < s->mn) s->mn = x; if (!s->n || x > s->mx) s->mx = x; s->n++; }
static void st_print(const char *name, const Stat *s)
{
    double mean = s->sum / s->n, var = s->sumsq / s->n - mean * mean;
    printf("  %-34s mean %9.3f  sd %8.3f  min %9.3f  max %9.3f  (n=%d)\n",
           name, mean, var > 0 ? sqrt(var) : 0, s->mn, s->mx, s->n);
}

static void bench(int N)
{
#ifdef __PCLMUL__
    puts("Multiplier: PCLMULQDQ");
#else
    puts("Multiplier: portable shift-and-add (compile with -march=native for PCLMUL)");
#endif
    printf("Times in milliseconds. RQC-I: n=%d m=%d k=%d w=%d, |CT|(unpacked)=%d B, packed ~ %d B\n",
           NN, MDEG, KK, WW, CT_LEN, (2 * NN * MDEG + 7) / 8);
    static User u; static Server s; static uint8_t ct[CT_LEN];
    uint8_t sku[L], sks[L];
    Stat kg = {0}, enc = {0}, dec = {0}, hs = {0}, cli = {0}, srv = {0}, cli_nonkem = {0};
    memset(&s, 0, sizeof s);
    for (int i = 0; i < N; i++) { double t = now_ms(); rqc_keygen(&s.pk, &s.sk); st_add(&kg, now_ms() - t); }
    registration(&u, &s, "bench-user", "pw");

    Rng r; rng_fresh(&r);
    for (int i = 0; i < N; i++) {                          /* raw KEM operations */
        gf m[KK]; uint8_t mb[M_LEN];
        for (int k = 0; k < KK; k++) m[k] = rand_gf();
        double t = now_ms(); rqc_encrypt_det(&s.pk, m, ct); st_add(&enc, now_ms() - t);
        t = now_ms(); int rc = rqc_decrypt_checked(&s.sk, &s.pk, ct, mb); st_add(&dec, now_ms() - t);
        if (rc) { puts("bench: decrypt failed"); exit(1); }
    }
    for (int i = 0; i < N * 200; i++) {                    /* one hash evaluation */
        uint8_t o[L], in[96] = {0}; double t = now_ms(); H(H2, o, 1, in, (size_t)96);
        if (i % 200 == 0) st_add(&hs, (now_ms() - t));
    }
    for (int i = 0; i < N; i++) {                          /* full protocol, per party */
        uint8_t ids[L], A1[L], A2[L], nu[L], aU[L], aS[L];
        double a, b, c, d, t;
        memcpy(ids, u.ids, L);
        t = now_ms(); srv_msg2(&s, ids, A1, A2); a = now_ms() - t;
        t = now_ms(); usr_msg3(&u, A1, A2, ct, nu, aU); b = now_ms() - t;
        t = now_ms(); int rc = srv_msg4(&s, ct, nu, aU, aS, sks); c = now_ms() - t;
        t = now_ms(); int rc2 = usr_finish(&u, aS); d = now_ms() - t;
        if (rc || rc2) { puts("bench: protocol failed"); exit(1); }
        (void)sku;
        st_add(&cli, b + d); st_add(&srv, a + c); st_add(&cli_nonkem, b + d - 0);
    }
    puts("\nRQC primitives");
    st_print("KeyGen (server, once)", &kg);
    st_print("Encapsulation E_enc (client)", &enc);
    st_print("Decapsulation D_dec (server)", &dec);
    puts("Symmetric");
    st_print("1 SHA-256 call (approx, ms)", &hs);
    puts("Whole protocol run (per party)");
    st_print("Client total (msg3 + finish)", &cli);
    st_print("Server total (msg2 + msg4)", &srv);
    double ratio = (srv.sum / srv.n) / (cli.sum / cli.n);
    printf("\n  Server/Client cost ratio: %.1fx\n", ratio);
    puts("  Note: decapsulation here includes the FO re-encryption (one extra E_enc),\n"
         "  and the decoder is an O(n^3) reference solver, so D_dec is an upper bound.");
}

int main(int argc, char **argv)
{
    gab_init();
    // print_params();
    if (argc > 1 && !strcmp(argv[1], "bench")) { bench(argc > 2 ? atoi(argv[2]) : 20); return 0; }
    test_field_and_rqc();
    test_protocol();
    puts(g_fail ? "\nRESULT: FAILURES" : "\nRESULT: Mutual Authentication Successful, all tests passed");
    return g_fail != 0;
}