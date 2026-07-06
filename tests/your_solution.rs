use simplicity_ctf::artifacts::ctf::CtfProgram;
use simplicity_ctf::artifacts::ctf::derived_ctf::{CtfArguments, CtfWitness};

use simplicity_ctf::artifacts::asset_lock::AssetLockProgram;
use simplicity_ctf::artifacts::asset_lock::derived_asset_lock::{AssetLockArguments, AssetLockWitness};

use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature};
use simplex::transaction::partial_input::IssuanceInput;

/// Convert a nonce (u64) to its u256 big-endian representation (32 bytes).
/// In Simplicity: <(u64, u64, u64, u64)>::into((0, 0, 0, nonce))
/// This means: 3 * 8 bytes of zeros + 8 bytes of nonce (big-endian) = 32 bytes
fn nonce_to_u256_bytes(nonce: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&nonce.to_be_bytes());
    bytes
}

#[simplex::test]
fn solution(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = context.get_network();

    // Step 1: Get signer's public key (serialized as 32 bytes for Schnorr/x-only)
    let pubkey_bytes: [u8; 32] = signer.get_schnorr_public_key().serialize();
    println!("Using pubkey: {:02x?}", &pubkey_bytes[..8]);

    // Step 2: Issue 12 auth tokens via issuance
    let signer_utxos = signer.get_utxos()?;
    assert!(!signer_utxos.is_empty(), "Signer has no UTXOs to use for issuance");

    let mut issuance_tx = FinalTransaction::new();
    let entropy = [0x42u8; 32]; // arbitrary contract hash for the issuance

    let issuance_details = issuance_tx.add_issuance_input(
        PartialInput::new(signer_utxos[0].clone()),
        IssuanceInput::new_issuance(12, 0, entropy),
        RequiredSignature::NativeEcdsa,
    );

    let auth_asset_id = issuance_details.asset_id;
    println!("Auth Asset ID: {}", auth_asset_id);

    // Convert AssetId to [u8; 32] for CtfArguments
    let auth_asset_bytes: [u8; 32] = {
        use simplex::simplicityhl::elements::encode::Encodable;
        let mut buf = Vec::new();
        auth_asset_id.consensus_encode(&mut buf).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&buf);
        arr
    };

    // Step 3: Create 12 asset_lock programs with nonce-based storage
    let asset_lock_args = AssetLockArguments {
        owner_pubkey: pubkey_bytes,
    };

    let mut asset_lock_programs: Vec<AssetLockProgram> = Vec::new();
    let mut asset_lock_scripts = Vec::new();

    for nonce in 0u64..12 {
        let mut al = AssetLockProgram::new(asset_lock_args.clone())
            .with_storage_capacity(1);

        // Set the storage slot to the nonce value (as u256 big-endian bytes)
        // This ensures current_script_hash matches get_script_hash_for_storage(nonce)
        let _ = al.set_storage_at(0, nonce_to_u256_bytes(nonce));

        let script = al.get_script_pubkey(network);
        println!("Asset lock {} script: {:02x?}", nonce, &al.get_script_hash(network)[..8]);

        // Add output: 1 auth token to this asset_lock address
        issuance_tx.add_output(PartialOutput::new(script.clone(), 1, auth_asset_id));

        asset_lock_scripts.push(script);
        asset_lock_programs.push(al);
    }

    // Step 4: Create the CTF program and fund it with L-BTC reward
    let ctf_args = CtfArguments {
        owner_pubkey: pubkey_bytes,
        auth_asset_id: auth_asset_bytes,
    };
    let ctf_program = CtfProgram::new(ctf_args);
    let ctf_script = ctf_program.get_script_pubkey(network);
    println!("CTF script: {:02x?}", &ctf_program.get_script_hash(network)[..8]);

    // Send 0.01 BTC (1_000_000 sats) to the CTF contract
    let reward_amount = 1_000_000u64;
    issuance_tx.add_output(PartialOutput::new(ctf_script.clone(), reward_amount, network.policy_asset()));

    // Broadcast and confirm the funding transaction
    let tx_receipt = signer.broadcast(&issuance_tx)?;
    println!("Funding tx broadcast: {}", tx_receipt);
    tx_receipt.wait()?;
    println!("Funding tx confirmed!");

    // Step 5: Fetch UTXOs from the funded contracts
    let ctf_utxos = provider.fetch_scripthash_utxos(&ctf_script)?;
    assert!(!ctf_utxos.is_empty(), "CTF contract has no UTXOs after funding");

    // Step 6: Build the spending/solution transaction
    let mut spend_tx = FinalTransaction::new();

    // Input 0: CTF contract (MUST be index 0 per ctf.simf's assert on current_index)
    let ctf_witness = CtfWitness::default();
    spend_tx.add_program_input(
        PartialInput::new(ctf_utxos[0].clone()),
        ProgramInput::new(
            Box::new(ctf_program.as_ref().clone()),
            Box::new(ctf_witness),
        ),
        RequiredSignature::Witness("SIGNATURE".to_string()),
    );

    // Inputs 1-12: asset_lock contracts (one per nonce 0..12)
    for nonce in 0u64..12 {
        let al_utxos = provider.fetch_scripthash_utxos(&asset_lock_scripts[nonce as usize])?;
        assert!(
            !al_utxos.is_empty(),
            "Asset lock nonce={} has no UTXOs after funding",
            nonce
        );

        let al_witness = AssetLockWitness {
            signature: [0u8; 64], // placeholder — signer will inject the real signature
            nonce,
        };

        spend_tx.add_program_input(
            PartialInput::new(al_utxos[0].clone()),
            ProgramInput::new(
                Box::new(asset_lock_programs[nonce as usize].as_ref().clone()),
                Box::new(al_witness),
            ),
            RequiredSignature::Witness("SIGNATURE".to_string()),
        );
    }

    // Output 0: All 12 auth tokens sent to our wallet
    // (CTF contract checks: output 0 has AUTH_ASSET_ID with amount 12)
    spend_tx.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        12,
        auth_asset_id,
    ));

    // Broadcast the spending transaction
    // The signer.broadcast() handles coin selection for L-BTC fees and signing all inputs
    let tx_receipt = signer.broadcast(&spend_tx)?;
    println!("Solution tx broadcast: {}", tx_receipt);
    tx_receipt.wait()?;
    println!("Solution tx confirmed! CTF SOLVED!");

    Ok(())
}
