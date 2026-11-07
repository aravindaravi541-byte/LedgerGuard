use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{prepare_verifying_key, ProvingKey, VerifyingKey, Groth16};
use ark_r1cs_std::{alloc::AllocVar, cmp::CmpGadget, eq::EqGadget, fields::{fp::FpVar, FieldVar}, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use pyo3::prelude::*;

pub const MAX_ITEMS: usize = 100;
pub const RATE_DENOMINATOR: u64 = 10_000;
pub const ROUNDING_OFFSET: u64 = 5_000;
pub const MAX_PROOF_BYTES: usize = 4096;
pub const MAX_KEY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceWitness {
    pub line_items: Vec<u64>,
    pub tax_rate_bps: u64,
    pub subtotal: u64,
    pub tax: u64,
    pub total: u64,
    pub remainder: u64,
}

impl InvoiceWitness {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.line_items.is_empty() || self.line_items.len() > MAX_ITEMS {
            return Err("invalid line-item count");
        }
        if self.tax_rate_bps > RATE_DENOMINATOR {
            return Err("tax rate out of range");
        }
        let subtotal = self.line_items.iter().try_fold(0u64, |sum, item| sum.checked_add(*item)).ok_or("subtotal overflow")?;
        if subtotal != self.subtotal {
            return Err("subtotal mismatch");
        }
        let numerator = (self.subtotal as u128) * (self.tax_rate_bps as u128) + ROUNDING_OFFSET as u128;
        let tax = (numerator / RATE_DENOMINATOR as u128) as u64;
        let remainder = (numerator % RATE_DENOMINATOR as u128) as u64;
        if tax != self.tax || remainder != self.remainder {
            return Err("tax or remainder mismatch");
        }
        if self.remainder >= RATE_DENOMINATOR || self.total != self.subtotal.checked_add(self.tax).ok_or("total overflow")? {
            return Err("total or remainder mismatch");
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct InvoiceCircuit {
    pub witness: Option<InvoiceWitness>,
    pub item_count: usize,
}

impl ConstraintSynthesizer<Fr> for InvoiceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let witness = self.witness.unwrap_or(InvoiceWitness {
            line_items: vec![0; self.item_count], tax_rate_bps: 0, subtotal: 0,
            tax: 0, total: 0, remainder: 0,
        });
        let rate = FpVar::new_input(cs.clone(), || Ok(Fr::from(witness.tax_rate_bps)))?;
        let subtotal = FpVar::new_input(cs.clone(), || Ok(Fr::from(witness.subtotal)))?;
        let total = FpVar::new_input(cs.clone(), || Ok(Fr::from(witness.total)))?;
        let tax = UInt64::new_witness(cs.clone(), || Ok(witness.tax))?;
        let remainder = UInt64::new_witness(cs.clone(), || Ok(witness.remainder))?;

        let mut sum = FpVar::constant(Fr::from(0u64));
        for item in witness.line_items {
            let item_var = UInt64::new_witness(cs.clone(), || Ok(item))?;
            sum += item_var.to_fp()?;
        }
        sum.enforce_equal(&subtotal)?;
        let numerator = subtotal.clone() * rate.clone() + Fr::from(ROUNDING_OFFSET);
        let expected = tax.to_fp()? * Fr::from(RATE_DENOMINATOR) + remainder.to_fp()?;
        numerator.enforce_equal(&expected)?;
        (tax.to_fp()? + subtotal).enforce_equal(&total)?;
        remainder.is_lt(&UInt64::constant(RATE_DENOMINATOR))?.enforce_equal(&ark_r1cs_std::boolean::Boolean::TRUE)?;
        Ok(())
    }
}

pub struct InvoiceProver {
    proving_key: ProvingKey<Bls12_381>,
    item_count: usize,
}

pub struct InvoiceVerifier {
    verifying_key: VerifyingKey<Bls12_381>,
}

impl InvoiceProver {
    pub fn setup<R: RngCore + CryptoRng>(rng: &mut R, item_count: usize) -> Result<(Self, InvoiceVerifier), SynthesisError> {
        if item_count == 0 || item_count > MAX_ITEMS {
            return Err(SynthesisError::Unsatisfiable);
        }
        let circuit = InvoiceCircuit { witness: None, item_count };
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)?;
        let verifier = InvoiceVerifier { verifying_key };
        Ok((Self { proving_key, item_count }, verifier))
    }

    pub fn prove<R: RngCore + CryptoRng>(&self, rng: &mut R, witness: InvoiceWitness) -> Result<Vec<u8>, &'static str> {
        witness.validate()?;
        if witness.line_items.len() != self.item_count {
            return Err("line-item count does not match proving key");
        }
        let proof = Groth16::<Bls12_381>::prove(&self.proving_key, InvoiceCircuit { item_count: self.item_count, witness: Some(witness) }, rng).map_err(|_| "proof generation failed")?;
        let mut bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut bytes).map_err(|_| "proof serialization failed")?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err("proof serialization exceeded the size limit");
        }
        Ok(bytes)
    }
}

impl InvoiceVerifier {
    pub fn verify(&self, proof_bytes: &[u8], tax_rate_bps: u64, subtotal: u64, total: u64) -> bool {
        if proof_bytes.len() == 0 || proof_bytes.len() > MAX_PROOF_BYTES || tax_rate_bps > RATE_DENOMINATOR {
            return false;
        }
        let proof: ark_groth16::Proof<Bls12_381> = match ark_serialize::CanonicalDeserialize::deserialize_compressed(proof_bytes) {
            Ok(proof) => proof,
            Err(_) => return false,
        };
        let inputs = [Fr::from(tax_rate_bps), Fr::from(subtotal), Fr::from(total)];
        let pvk = prepare_verifying_key(&self.verifying_key);
        Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap_or(false)
    }
}

#[pyfunction]
fn setup_keys(item_count: usize) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand::rngs::OsRng;
    let (prover, verifier) = InvoiceProver::setup(&mut rng, item_count)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("native setup failed"))?;
    let mut proving_key = Vec::new();
    let mut verifying_key = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&prover.proving_key, &mut proving_key)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("proving-key serialization failed"))?;
    ark_serialize::CanonicalSerialize::serialize_compressed(&verifier.verifying_key, &mut verifying_key)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("verifying-key serialization failed"))?;
    Ok((proving_key, verifying_key))
}

#[pyfunction]
fn prove_native(
    proving_key_bytes: Vec<u8>,
    line_items: Vec<u64>,
    tax_rate_bps: u64,
    subtotal: u64,
    tax: u64,
    total: u64,
    remainder: u64,
) -> PyResult<Vec<u8>> {
    if proving_key_bytes.len() > MAX_KEY_BYTES {
        return Err(pyo3::exceptions::PyValueError::new_err("proving key is oversized"));
    }
    let proving_key = ark_serialize::CanonicalDeserialize::deserialize_compressed(&*proving_key_bytes)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("malformed proving key"))?;
    let prover = InvoiceProver { proving_key, item_count: line_items.len() };
    let witness = InvoiceWitness { line_items, tax_rate_bps, subtotal, tax, total, remainder };
    let mut rng = rand::rngs::OsRng;
    prover.prove(&mut rng, witness)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn verify_native(
    verifying_key_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    tax_rate_bps: u64,
    subtotal: u64,
    total: u64,
) -> PyResult<bool> {
    if verifying_key_bytes.len() > MAX_KEY_BYTES {
        return Ok(false);
    }
    let verifying_key = ark_serialize::CanonicalDeserialize::deserialize_compressed(&*verifying_key_bytes)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("malformed verifying key"))?;
    let verifier = InvoiceVerifier { verifying_key };
    Ok(verifier.verify(&proof_bytes, tax_rate_bps, subtotal, total))
}

#[pymodule]
fn ledgerguard_zkp_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(setup_keys, m)?)?;
    m.add_function(wrap_pyfunction!(prove_native, m)?)?;
    m.add_function(wrap_pyfunction!(verify_native, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn valid() -> InvoiceWitness {
        InvoiceWitness { line_items: vec![1250, 750], tax_rate_bps: 2000, subtotal: 2000, tax: 400, total: 2400, remainder: 5000 }
    }

    #[test]
    fn valid_invoice_proof_verifies() {
        let mut rng = StdRng::seed_from_u64(7);
        let (prover, verifier) = InvoiceProver::setup(&mut rng, 2).unwrap();
        let proof = prover.prove(&mut rng, valid()).unwrap();
        assert!(verifier.verify(&proof, 2000, 2000, 2400));
    }

    #[test]
    fn invalid_tax_is_rejected_before_proving() {
        let mut invoice = valid();
        invoice.tax = 401;
        let mut rng = StdRng::seed_from_u64(8);
        let (prover, _) = InvoiceProver::setup(&mut rng, 2).unwrap();
        assert!(prover.prove(&mut rng, invoice).is_err());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let mut rng = StdRng::seed_from_u64(9);
        let (prover, verifier) = InvoiceProver::setup(&mut rng, 2).unwrap();
        let mut proof = prover.prove(&mut rng, valid()).unwrap();
        proof[0] ^= 1;
        assert!(!verifier.verify(&proof, 2000, 2000, 2400));
    }
}
