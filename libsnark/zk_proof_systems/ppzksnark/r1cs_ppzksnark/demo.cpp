#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace libsnark;

extern "C" {
typedef libff::Fr<default_r1cs_ppzksnark_pp> Fr;
struct linear_combination_t {
    linear_combination<Fr> *rep;
};
struct constraint_system_t {
    r1cs_constraint_system<Fr> *rep;
};
struct key_pair_t {
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> *pk;
    r1cs_ppzksnark_processed_verification_key<default_r1cs_ppzksnark_pp> *pvk;
};
struct proof_t {
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> *rep;
};
struct input_t {
    std::vector<Fr> *rep;
};

constraint_system_t *new_constraint_system(size_t primary_input_size, size_t auxiliary_input_size) {
    auto result = new constraint_system_t;
    auto cs = new r1cs_constraint_system<Fr>;
    cs->primary_input_size = primary_input_size;
    cs->auxiliary_input_size = auxiliary_input_size;
    result->rep = cs;
    return result;
} ;

void
add_constraint(constraint_system_t *cs, linear_combination_t *A, linear_combination_t *B, linear_combination_t *C) {
    auto constraint = r1cs_constraint<Fr>(*A->rep, *B->rep, *C->rep);
    cs->rep->add_constraint(constraint);
} ;

bool constraint_satisfied(constraint_system_t *cs, input_t *primary_input, input_t *auxiliary_input){
    return cs->rep->is_satisfied(*primary_input->rep, *auxiliary_input->rep);
}

linear_combination_t *make_linear_combination(size_t len, size_t *nums, mpz_t *big_ints) {
    auto lc = new linear_combination<Fr>;
    for (size_t i = 0; i < len; i++) {
        auto coeff = Fr(libff::bigint<Fr::num_limbs>(big_ints[i]));
        auto index = variable<Fr>(nums[i]);
        lc->add_term(index, coeff);
    }

    auto result = new linear_combination_t;
    result->rep = lc;
    return result;
}

input_t *make_input(size_t len, mpz_t *input) {
    auto convert = [](mpz_t x) {
        return Fr( libff::bigint<Fr::num_limbs>(x));
    };
    auto output = new std::vector<Fr>;
    std::transform(input, input + len, std::back_inserter(*output), convert);

    auto result = new input_t;
    result->rep = output;
    return result;
}

key_pair_t *setup(constraint_system_t *cs) {
    auto key_pair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(*cs->rep);
    auto pvk = r1cs_ppzksnark_verifier_process_vk<default_r1cs_ppzksnark_pp>(key_pair.vk);

    auto result = new key_pair_t;
    result->pk = new r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>(key_pair);
    result->pvk = new r1cs_ppzksnark_processed_verification_key<default_r1cs_ppzksnark_pp>(pvk);

    return result;
}

proof_t *prove(key_pair_t *keypair, input_t *primary_input, input_t *auxiliary_input) {
    auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair->pk->pk, *primary_input->rep,
                                                                  *auxiliary_input->rep);

    auto result = new proof_t;
    result->rep = new r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>(proof);

    return result;
}

bool verify(key_pair_t *keypair, input_t *primary_input, proof_t *proof) {
    auto verify = r1cs_ppzksnark_online_verifier_strong_IC<default_r1cs_ppzksnark_pp>(*keypair->pvk,
                                                                                      *primary_input->rep, *proof->rep);
    return verify;
}

void clear_linear_combination(linear_combination_t *lc) {
    delete lc->rep;
    delete lc;
}

void clear_constraint_system(constraint_system_t *cs) {
    delete cs->rep;
    delete cs;
}

void clear_key_pair(key_pair_t *keyPair) {
    delete keyPair->pk;
    delete keyPair->pvk;
    delete keyPair;
}

void clear_proof(proof_t *proof) {
    delete proof->rep;
    delete proof;
}

void clear_input(input_t *input) {
    delete input->rep;
    delete input;
}

void init_public_params() {
    default_r1cs_ppzksnark_pp::init_public_params();
}

void reset_profile() {
    libff::start_profiling();
}

void toggle_profile_log(bool enable) {
    libff::inhibit_profiling_counters = !enable;
}
};