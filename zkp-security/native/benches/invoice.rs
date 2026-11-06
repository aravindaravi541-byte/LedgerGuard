use ledgerguard_zkp_native::{InvoiceProver, InvoiceWitness};
use std::time::Instant;

fn main() {
    let mut rng = rand::rngs::OsRng;
    let invoice = InvoiceWitness { line_items: vec![1250, 750], tax_rate_bps: 2000, subtotal: 2000, tax: 400, total: 2400, remainder: 5000 };
    let started = Instant::now();
    let (prover, verifier) = InvoiceProver::setup(&mut rng, 2).expect("setup");
    let setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let proof = prover.prove(&mut rng, invoice).expect("prove");
    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let valid = verifier.verify(&proof, 2000, 2000, 2400);
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!("setup_ms={setup_ms:.3} prove_ms={prove_ms:.3} verify_ms={verify_ms:.3} proof_bytes={} valid={valid}", proof.len());
}
