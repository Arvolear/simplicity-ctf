use simplicity_ctf::artifacts::ctf::CtfProgram;
use simplicity_ctf::artifacts::ctf::derived_ctf::{CtfArguments, CtfWitness};

use simplicity_ctf::artifacts::asset_lock::AssetLockProgram;
use simplicity_ctf::artifacts::asset_lock::derived_asset_lock::{AssetLockArguments, AssetLockWitness};

#[simplex::test]
fn solution(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = context.get_network();
 
    // In this harness we play the OWNER: OWNER_PUBKEY = our signer's x-only key.
    let owner_pubkey: [u8; 32] = signer.get_schnorr_public_key().serialize();
 
    // Encode a nonce exactly like asset_lock.simf's `get_nonce_slot_leaf`:
    // u256 big-endian == 24 zero bytes followed by the 8-byte nonce.
    let nonce_slot = |nonce: u64| -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&nonce.to_be_bytes());
        b
    };
 
    // Step 1: issue the AUTH asset (supply 12), one unit into each of the 12
    // asset_lock storage slots (nonces 0..12).
    let slot_scripts: Vec<_> = (0..12u64)
        .map(|n| {
            let mut p =
                AssetLockProgram::new(AssetLockArguments { owner_pubkey }).with_storage_capacity(1);
            p.set_storage_at(0, nonce_slot(n));
            p.get_script_pubkey(network)
        })
        .collect();
 
    let mut issue_tx = FinalTransaction::new();
    let issuance = issue_tx.add_issuance_input(
        PartialInput::new(signer.get_utxos()?[0].clone()),
        IssuanceInput::new_issuance(12, 0, [0x42u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    let auth_asset_id = issuance.asset_id;
    for script in &slot_scripts {
        issue_tx.add_output(PartialOutput::new(script.clone(), 1, auth_asset_id));
    }
 
    // Step 2: deploy and fund the ctf reward contract (needs AUTH_ASSET_ID).
    let auth_asset_bytes: [u8; 32] = auth_asset_id.into_tag().into();
    let ctf = CtfProgram::new(CtfArguments {
        owner_pubkey,
        auth_asset_id: auth_asset_bytes,
    });
    let ctf_script = ctf.get_script_pubkey(network);
    issue_tx.add_output(PartialOutput::new(ctf_script.clone(), 1_000_000, network.policy_asset()));
 
    signer.broadcast(&issue_tx)?.wait()?;
 
    // Step 3: a single transaction that unlocks the reward.
    let mut spend = FinalTransaction::new();
 
    // input 0 must be the ctf contract (ctf asserts current_index == 0).
    let reward_utxo = provider.fetch_scripthash_utxos(&ctf_script)?[0].clone();
    spend.add_program_input(
        PartialInput::new(reward_utxo),
        ProgramInput::new(Box::new(ctf.as_ref().clone()), Box::new(CtfWitness::default())),
        RequiredSignature::Witness("SIGNATURE".to_string()),
    );
 
    // output 0 = the 12 AUTH tokens consolidated (satisfies ctf's covenant), explicit.
    spend.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        12,
        auth_asset_id,
    ));
 
    // inputs 1..=12 = every asset_lock slot, each with its matching nonce witness.
    for nonce in 0..12u64 {
        let mut prog =
            AssetLockProgram::new(AssetLockArguments { owner_pubkey }).with_storage_capacity(1);
        prog.set_storage_at(0, nonce_slot(nonce));
        let utxo = provider.fetch_scripthash_utxos(&slot_scripts[nonce as usize])?[0].clone();
        spend.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(prog.as_ref().clone()),
                Box::new(AssetLockWitness {
                    signature: [0u8; 64], // placeholder; the signer injects the real Schnorr sig
                    nonce,
                }),
            ),
            RequiredSignature::Witness("SIGNATURE".to_string()),
        );
    }
 
    // A single SIGHASH_ALL owner signature authorizes all 13 inputs at once.
    signer.broadcast(&spend)?.wait()?;
 
    // Verify: the reward contract is emptied and we now control all 12 AUTH.
    assert!(
        provider.fetch_scripthash_utxos(&ctf_script)?.is_empty(),
        "reward contract should be emptied"
    );
    let auth_held: u64 = signer
        .get_utxos_asset(auth_asset_id)?
        .iter()
        .map(|u| u.explicit_amount())
        .sum();
    assert_eq!(auth_held, 12, "we should control all 12 AUTH units");
 
    println!("CTF solved: reward drained and 12/12 AUTH consolidated into output 0.");
    Ok(())
}
