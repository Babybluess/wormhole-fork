use solana_program::instruction::InstructionError;
use solana_program_test::BanksClientError;
use solana_sdk::transaction::TransactionError;
use bridge::error::Error as BridgeError;
use solana_program_test::BanksClientError::RpcError;

use libsecp256k1::SecretKey;
use rand::Rng;
use solana_program::{
    pubkey::Pubkey,
    system_instruction,
};
use solana_program_test::{
    tokio,
    BanksClient,
};
use solana_sdk::{
    signature::{
        Keypair,
        Signer,
    },
};
use solitaire::{
    processors::seeded::Seeded,
    AccountState,
};

use bridge::{
    accounts::{
        Bridge,
        BridgeData,
        FeeCollector,
        GuardianSet,
        GuardianSetData,
        GuardianSetDerivationData,
        PostedVAA,
        PostedVAAData,
        PostedVAADerivationData,
        SignatureSetData,
    },
    // instructions,
    types::{
        ConsistencyLevel,
        GovernancePayloadGuardianSetChange,
        GovernancePayloadSetMessageFee,
        GovernancePayloadTransferFees,
        GovernancePayloadUpgrade,
    },
    SerializeGovernancePayload,
};
use primitive_types::U256;

mod common;

// The pubkey corresponding to this key is "CiByUvEcx7w2HA4VHcPCBUAFQ73Won9kB36zW9VjirSr" and needs
// to be exported as the `EMITTER_ADDRESS` environment variable when building the program bpf in
// order for the governance related tests to pass.
const GOVERNANCE_KEY: [u8; 64] = [
    240, 133, 120, 113, 30, 67, 38, 184, 197, 72, 234, 99, 241, 21, 58, 225, 41, 157, 171, 44, 196,
    163, 134, 236, 92, 148, 110, 68, 127, 114, 177, 0, 173, 253, 199, 9, 242, 142, 201, 174, 108,
    197, 18, 102, 115, 0, 31, 205, 127, 188, 191, 56, 171, 228, 20, 247, 149, 170, 141, 231, 147,
    88, 97, 199,
];

struct Context {
    public: Vec<[u8; 20]>,
    secret: Vec<SecretKey>,
    seq: Sequencer,
}

/// Small helper to track and provide sequences during tests. This is in particular needed for
/// guardian operations that require them for derivations.
struct Sequencer {
    sequences: std::collections::HashMap<[u8; 32], u64>,
}

impl Sequencer {
    fn next(&mut self, emitter: [u8; 32]) -> u64 {
        let entry = self.sequences.entry(emitter).or_insert(0);
        *entry += 1;
        *entry - 1
    }
}

async fn initialize() -> (Context, BanksClient, Keypair, Pubkey) {
    let (public_keys, secret_keys) = common::generate_keys(6);
    let context = Context {
        public: public_keys,
        secret: secret_keys,
        seq: Sequencer {
            sequences: std::collections::HashMap::new(),
        },
    };
    let (mut client, payer, program) = common::setup().await;

    // Use a timestamp from a few seconds earlier for testing to simulate thread::sleep();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;

    common::initialize(&mut client, program, &payer, &context.public, 500)
        .await
        .expect("Failed to initialize bridge program");

    // Verify the initial bridge state is as expected.
    let bridge_key = Bridge::<'_, { AccountState::Uninitialized }>::key(None, &program);
    let guardian_set_key = GuardianSet::<'_, { AccountState::Uninitialized }>::key(
        &GuardianSetDerivationData { index: 0 },
        &program,
    );

    // Fetch account states.
    let bridge: BridgeData = common::get_account_data(&mut client, bridge_key).await;
    let guardian_set: GuardianSetData =
        common::get_account_data(&mut client, guardian_set_key).await;

    // Bridge Config should be as expected.
    assert_eq!(bridge.guardian_set_index, 0);
    assert_eq!(bridge.config.guardian_set_expiration_time, 2_000_000_000);
    assert_eq!(bridge.config.fee, 500);

    // Guardian set account must also be as expected.
    assert_eq!(guardian_set.index, 0);
    assert_eq!(guardian_set.keys, context.public);
    assert!(guardian_set.creation_time as u64 > now);

    (context, client, payer, program)
}

#[tokio::test]
async fn post_message_success() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();
    let nonce = rand::thread_rng().gen();

    // Post the message, publishing the data for guardian consumption.
    let sequence = context.seq.next(emitter.pubkey().to_bytes());
    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(posted_message.message.consistency_level, 1);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(
        &posted_message.message.emitter_address,
        emitter.pubkey().as_ref()
    );
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );
}

#[tokio::test]
async fn post_message_invalid_emitter() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Generate a message we want to persist.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();
    let nonce = rand::thread_rng().gen();
    let _sequence = context.seq.next(emitter.pubkey().to_bytes());

    let fee_collector = FeeCollector::key(None, program);

    let msg_account = Keypair::new();
    // Manually send a message that isn't signed by the emitter, which should be rejected to
    // prevent fraudulant transactions sent on behalf of an emitter.
    let mut instruction = bridge::instructions::post_message(
        *program,
        payer.pubkey(),
        emitter.pubkey(),
        msg_account.pubkey(),
        nonce,
        message,
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    // Modify account list to not require the emitter signs.
    instruction.accounts[2].is_signer = false;

    // Executing this should fail.
    assert!(common::execute(
        client,
        payer,
        &[payer, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn post_message_math_overflow() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Generate a message we want to persist.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();
    let nonce = rand::thread_rng().gen();
    let _sequence = context.seq.next(emitter.pubkey().to_bytes());

    let new_bridge = Keypair::new();
    let fee_collector = FeeCollector::key(None, &new_bridge.pubkey());
    let msg_account = Keypair::new();

    let bridge_key = Bridge::<'_, { AccountState::Uninitialized }>::key(None, program);
    let mut bridge: BridgeData = common::get_account_data(client, bridge_key).await;
    assert_eq!(bridge.config.fee, 500);
    
    bridge.last_lamports = 100u64;
    assert_eq!(bridge.last_lamports, 100u64);

    let instruction = bridge::instructions::post_message(
        *program,
        payer.pubkey(),
        emitter.pubkey(),
        msg_account.pubkey(),
        nonce,
        message,
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    // Executing this should fail.
    let err = common::execute(
        client,
        payer,
        &[payer, &emitter, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn post_message_insufficient_fee() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Generate a message we want to persist.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();
    let nonce = rand::thread_rng().gen();
    let sequence = context.seq.next(emitter.pubkey().to_bytes());
    let emitter_governance = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let sequence_governance = context.seq.next(emitter_governance.pubkey().to_bytes());

    let fee_collector = FeeCollector::key(None, program);
    let fee_collector_balance = common::get_account_balance(client, fee_collector).await;
    let msg_account = Keypair::new();

    let bridge_key = Bridge::<'_, { AccountState::Uninitialized }>::key(None, program);
    let mut bridge: BridgeData = common::get_account_data(client, bridge_key).await;
    assert_eq!(bridge.config.fee, 500);

    let message = GovernancePayloadSetMessageFee {
        fee: U256::from((fee_collector_balance + 10u64) as u128),
    }
    .try_to_vec()
    .unwrap();

    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter_governance,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    common::set_fees(
        client,
        program,
        payer,
        message_key,
        emitter_governance.pubkey(),
        sequence_governance,
    )
    .await
    .unwrap();

    let instruction = bridge::instructions::post_message(
        *program,
        payer.pubkey(),
        emitter.pubkey(),
        msg_account.pubkey(),
        nonce,
        message,
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    // Executing this should fail.
    let err = common::execute(
        client,
        payer,
        &[payer, &emitter, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await
    .expect_err("err");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn post_message_unreliable_success() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let emitter = Keypair::new();
    let message_key = Keypair::new();

    let nonce = rand::thread_rng().gen();
    let message: [u8; 32] = rand::thread_rng().gen();
    let sequence = context.seq.next(emitter.pubkey().to_bytes());

    // Post the message, publishing the data for guardian consumption.
    common::post_message_unreliable(
        client,
        program,
        payer,
        &emitter,
        &message_key,
        nonce,
        message.to_vec(),
        10_000,
    )
    .await
    .unwrap();

    // Verify on chain Message
    let posted_message: PostedVAAData =
        common::get_account_data(client, message_key.pubkey()).await;
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );
}

#[tokio::test]
async fn post_message_unreliable_invalid_payload_length() {
    let (ref mut _context, ref mut client, ref payer, ref program) = initialize().await;

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let emitter = Keypair::new();

    let nonce = rand::thread_rng().gen();
    let message: [u8; 30] = rand::thread_rng().gen();
    let message1: [u8; 32] = rand::thread_rng().gen();
    let fee_collector = FeeCollector::key(None, program);

    let msg_account = Keypair::new();

    // Post the message, publishing the data for guardian consumption.
    common::post_message_unreliable(
        client,
        program,
        payer,
        &emitter,
        &msg_account,
        nonce,
        message.to_vec(),
        10_000,
    )
    .await
    .unwrap();

    let instruction = bridge::instructions::post_message_unreliable(
        *program,
        payer.pubkey(),
        emitter.pubkey(),
        msg_account.pubkey(),
        nonce,
        message1.to_vec(),
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    // Executing this should fail.
    let err = common::execute(
        client,
        payer,
        &[payer, &emitter, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn post_message_unreliable_changed_emitter() {
    let (ref mut _context, ref mut client, ref payer, ref program) = initialize().await;

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let emitter = Keypair::new();
    let emitter1 = Keypair::new();

    let nonce = rand::thread_rng().gen();
    let message: [u8; 30] = rand::thread_rng().gen();
    let fee_collector = FeeCollector::key(None, program);

    let msg_account = Keypair::new();
  
    let instruction = bridge::instructions::post_message_unreliable(
        *program,
        payer.pubkey(),
        emitter.pubkey(),
        msg_account.pubkey(),
        nonce,
        message.to_vec(),
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    let instruction1 = bridge::instructions::post_message_unreliable(
        *program,
        payer.pubkey(),
        emitter1.pubkey(),
        msg_account.pubkey(),
        nonce,
        message.to_vec(),
        ConsistencyLevel::Confirmed,
    )
    .unwrap();

    // init message
    common::execute(
        client,
        payer,
        &[payer, &emitter, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await;

    // Executing this should fail.
    let err = common::execute(
        client,
        payer,
        &[payer, &emitter1, &msg_account],
        &[
            system_instruction::transfer(&payer.pubkey(), &fee_collector, 10_000),
            instruction1,
        ],
        solana_sdk::commitment_config::CommitmentLevel::Processed,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn post_vaa_success() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();

    let nonce = rand::thread_rng().gen();

    // Post the message, publishing the data for guardian consumption.
    let sequence = context.seq.next(emitter.pubkey().to_bytes());
    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(posted_message.message.consistency_level, 1);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(
        &posted_message.message.emitter_address,
        emitter.pubkey().as_ref()
    );
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );

    // Emulate Guardian behaviour, verifying the data and publishing signatures/VAA.
    let (vaa, body, _body_hash) =
        common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
    let vaa_time = vaa.timestamp;

    let signature_set =
        common::verify_signatures(client, program, payer, body, &context.secret, 0)
            .await
            .unwrap();

    // Derive where we expect the posted VAA to be stored.
    let message_key = PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(
        &PostedVAADerivationData {
            payload_hash: body.to_vec(),
        },
        program,
    );
    common::post_vaa(client, program, payer, signature_set, vaa)
        .await
        .unwrap();

    // Fetch chain accounts to verify state.
    let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
    let signatures: SignatureSetData = common::get_account_data(client, signature_set).await;

    // Verify on chain Message
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(
        posted_message.message.consistency_level,
        ConsistencyLevel::Confirmed as u8
    );
    assert_eq!(posted_message.message.vaa_time, vaa_time);
    assert_eq!(posted_message.message.vaa_signature_account, signature_set);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(
        &posted_message.message.emitter_address,
        emitter.pubkey().as_ref()
    );
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );

    // Verify on chain Signatures
    assert_eq!(signatures.hash, body);
    assert_eq!(signatures.guardian_set_index, 0);

    for (signature, _secret_key) in signatures.signatures.iter().zip(context.secret.iter()) {
        assert!(*signature);
    }
}

#[tokio::test]
async fn post_vaa_consensus_fail() {
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;
    let (_public_keys, secret_keys) = common::generate_keys(2);

    // Data/Nonce used for emitting a message we want to prove exists. Run this twice to make sure
    // that duplicate data does not clash.
    let message = [0u8; 32].to_vec();
    let emitter = Keypair::new();

    let nonce = rand::thread_rng().gen();

    // Post the message, publishing the data for guardian consumption.
    let sequence = context.seq.next(emitter.pubkey().to_bytes());
    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(posted_message.message.consistency_level, 1);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(
        &posted_message.message.emitter_address,
        emitter.pubkey().as_ref()
    );
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );

    // Emulate Guardian behaviour, verifying the data and publishing signatures/VAA.
    let (vaa, body, _body_hash) =
        common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);

    // Partial slice
    let sub = &context.secret[0..1];
    let signature_set =
    common::verify_signatures(client, program, payer, body, sub, 0)
        .await
        .unwrap();

    // Executing this should fail.
    let err = common::post_vaa(client, program, payer, signature_set, vaa)
        .await
        .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn set_fees_success() {
      // Initialize a wormhole bridge on Solana to test with.
      let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;
      let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
      let sequence = context.seq.next(emitter.pubkey().to_bytes());
  
      // Set Fees to 0.
      let nonce = rand::thread_rng().gen();
      let message = GovernancePayloadSetMessageFee {
          fee: U256::from(0u128),
      }
      .try_to_vec()
      .unwrap();
  
      let message_key = common::post_message(
          client,
          program,
          payer,
          &emitter,
          None,
          nonce,
          message.clone(),
          10_000,
      )
      .await
      .unwrap();
  
      let (vaa, body, _body_hash) =
          common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
      let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
          .await
          .unwrap();
      common::post_vaa(client, program, payer, signature_set, vaa)
          .await
          .unwrap();
      common::set_fees(
          client,
          program,
          payer,
          message_key,
          emitter.pubkey(),
          sequence,
      )
      .await
      .unwrap();
  
      // Fetch Bridge to check on-state value.
      let bridge_key = Bridge::<'_, { AccountState::Uninitialized }>::key(None, program);
      let bridge: BridgeData = common::get_account_data(client, bridge_key).await;
      assert_eq!(bridge.config.fee, 0);
}

#[tokio::test]
async fn set_fees_invalid_guardian_key() {
    // Initialize a wormhole bridge on Solana to test with.
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Use a random key to confirm only the governance key is respected.
    let emitter = Keypair::new();
    let sequence = context.seq.next(emitter.pubkey().to_bytes());

    let nonce = rand::thread_rng().gen();
    let message = GovernancePayloadSetMessageFee {
        fee: U256::from(100u128),
    }
    .try_to_vec()
    .unwrap();

    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let (vaa, body, _body_hash) =
        common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 2);
    let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
        .await
        .unwrap();
    common::post_vaa(client, program, payer, signature_set, vaa)
        .await
        .unwrap();
    let err = common::set_fees(
        client,
        program,
        payer,
        message_key,
        emitter.pubkey(),
        sequence,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn transfer_fees_success() {
       // Initialize a wormhole bridge on Solana to test with.
       let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;
       let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
       let sequence = context.seq.next(emitter.pubkey().to_bytes());
   
       let nonce = rand::thread_rng().gen();
       let message = GovernancePayloadTransferFees {
           amount: 100u128.into(),
           to: payer.pubkey().to_bytes(),
       }
       .try_to_vec()
       .unwrap();
   
       // Fetch accounts for chain state checking.
       let fee_collector = FeeCollector::key(None, program);
   
       let message_key = common::post_message(
           client,
           program,
           payer,
           &emitter,
           None,
           nonce,
           message.clone(),
           10_000,
       )
       .await
       .unwrap();
   
       let (vaa, body, _body_hash) =
           common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
       let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
           .await
           .unwrap();
       common::post_vaa(client, program, payer, signature_set, vaa)
           .await
           .unwrap();
   
       let previous_balance = common::get_account_balance(client, fee_collector).await;
   
       common::transfer_fees(
           client,
           program,
           payer,
           message_key,
           emitter.pubkey(),
           payer.pubkey(),
           sequence,
       )
       .await
       .unwrap();
       assert_eq!(
           common::get_account_balance(client, fee_collector).await,
           previous_balance - 100
       );
}

#[tokio::test]
async fn transfer_fees_invalid_recipient() {
    // Initialize a wormhole bridge on Solana to test with.
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;
    let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let sequence = context.seq.next(emitter.pubkey().to_bytes());

    let recipient1 = Keypair::new();
    let recipient2 = Keypair::new();
    let nonce = rand::thread_rng().gen();
    let message = GovernancePayloadTransferFees {
        amount: 100u128.into(),
        to: recipient1.pubkey().to_bytes(),
    }
    .try_to_vec()
    .unwrap();

    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let (vaa, body, _body_hash) =
        common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
    let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
        .await
        .unwrap();
    common::post_vaa(client, program, payer, signature_set, vaa)
        .await
        .unwrap();

    let err =  common::transfer_fees(
        client,
        program,
        payer,
        message_key,
        emitter.pubkey(),
        recipient2.pubkey(),
        sequence,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn transfer_fees_invalid_withdrawal() {
       // Initialize a wormhole bridge on Solana to test with.
       let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;
       let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
       let sequence = context.seq.next(emitter.pubkey().to_bytes());
   
       // Fetch accounts for chain state checking.
       let fee_collector = FeeCollector::key(None, program);
       let balance_payer_before_transfer = common::get_account_balance(client, fee_collector).await;
   
       let nonce = rand::thread_rng().gen();
       let message = GovernancePayloadTransferFees {
           amount: balance_payer_before_transfer.into(),
           to: payer.pubkey().to_bytes(),
       }
       .try_to_vec()
       .unwrap();
   
       let message_key = common::post_message(
           client,
           program,
           payer,
           &emitter,
           None,
           nonce,
           message.clone(),
           10_000,
       )
       .await
       .unwrap();
   
       let (vaa, body, _body_hash) =
           common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
       let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
           .await
           .unwrap();
       common::post_vaa(client, program, payer, signature_set, vaa)
           .await
           .unwrap();
   
       let err =  common::transfer_fees(
           client,
           program,
           payer,
           message_key,
           emitter.pubkey(),
           payer.pubkey(),
           sequence,
       )
       .await
       .expect_err("expected failure");

    match err { 
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn update_guardian_set_success() {
     // Initialize a wormhole bridge on Solana to test with.
     let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

     // Use a timestamp from a few seconds earlier for testing to simulate thread::sleep();
     let now = std::time::SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .unwrap()
         .as_secs()
         - 10;
 
     // Upgrade the guardian set with a new set of guardians.
     let (new_public_keys, _new_secret_keys) = common::generate_keys(1);
 
     let nonce = rand::thread_rng().gen();
     let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
     let sequence = context.seq.next(emitter.pubkey().to_bytes());
     let message = GovernancePayloadGuardianSetChange {
         new_guardian_set_index: 1,
         new_guardian_set: new_public_keys.clone(),
     }
     .try_to_vec()
     .unwrap();
 
     let message_key = common::post_message(
         client,
         program,
         payer,
         &emitter,
         None,
         nonce,
         message.clone(),
         10_000,
     )
     .await
     .unwrap();
 
     let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
     assert_eq!(posted_message.message.vaa_version, 0);
     assert_eq!(posted_message.message.consistency_level, 1);
     assert_eq!(posted_message.message.nonce, nonce);
     assert_eq!(posted_message.message.sequence, sequence);
     assert_eq!(posted_message.message.emitter_chain, 1);
     assert_eq!(
         &posted_message.message.emitter_address,
         emitter.pubkey().as_ref()
     );
     assert_eq!(posted_message.message.payload, message);
     assert_eq!(
         posted_message.message.emitter_address,
         emitter.pubkey().to_bytes()
     );
 
     let (vaa, body, _body_hash) =
         common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
     let vaa_time = vaa.timestamp;
     let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
         .await
         .unwrap();
     let message_key = PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(
         &PostedVAADerivationData {
             payload_hash: body.to_vec(),
         },
         program,
     );
     common::post_vaa(client, program, payer, signature_set, vaa)
         .await
         .unwrap();
     common::upgrade_guardian_set(
         client,
         program,
         payer,
         message_key,
         emitter.pubkey(),
         0,
         1,
         sequence,
     )
     .await
     .unwrap();
 
     // Derive keys for accounts we want to check.
     let bridge_key = Bridge::<'_, { AccountState::Uninitialized }>::key(None, program);
     let guardian_set_key = GuardianSet::<'_, { AccountState::Uninitialized }>::key(
         &GuardianSetDerivationData { index: 1 },
         program,
     );
 
     // Fetch account states.
     let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
     let bridge: BridgeData = common::get_account_data(client, bridge_key).await;
     let guardian_set: GuardianSetData = common::get_account_data(client, guardian_set_key).await;
 
     // Verify on chain Message
     assert_eq!(posted_message.message.vaa_version, 0);
     assert_eq!(
         posted_message.message.consistency_level,
         ConsistencyLevel::Confirmed as u8
     );
     assert_eq!(posted_message.message.vaa_time, vaa_time);
     assert_eq!(posted_message.message.vaa_signature_account, signature_set);
     assert_eq!(posted_message.message.nonce, nonce);
     assert_eq!(posted_message.message.sequence, sequence);
     assert_eq!(posted_message.message.emitter_chain, 1);
     assert_eq!(
         &posted_message.message.emitter_address,
         emitter.pubkey().as_ref()
     );
     assert_eq!(posted_message.message.payload, message);
     assert_eq!(
         posted_message.message.emitter_address,
         emitter.pubkey().to_bytes()
     );
 
     // Confirm the bridge now has a new guardian set, and no other fields have shifted.
     assert_eq!(bridge.guardian_set_index, 1);
     assert_eq!(bridge.config.guardian_set_expiration_time, 2_000_000_000);
     assert_eq!(bridge.config.fee, 500);
 
     // Verify Created Guardian Set
     assert_eq!(guardian_set.index, 1);
     assert_eq!(guardian_set.keys, new_public_keys);
     assert!(guardian_set.creation_time as u64 > now);
 
}

#[tokio::test]
async fn update_guardian_set_invalid_guardian_set_upgarde() {
    // Initialize a wormhole bridge on Solana to test with.
    let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

    // Upgrade the guardian set with a new set of guardians.
    let (new_public_keys, _new_secret_keys) = common::generate_keys(1);

    let nonce = rand::thread_rng().gen();
    let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let sequence = context.seq.next(emitter.pubkey().to_bytes());
    let message = GovernancePayloadGuardianSetChange {
        new_guardian_set_index: 2,
        new_guardian_set: new_public_keys.clone(),
    }
    .try_to_vec()
    .unwrap();

    let message_key = common::post_message(
        client,
        program,
        payer,
        &emitter,
        None,
        nonce,
        message.clone(),
        10_000,
    )
    .await
    .unwrap();

    let posted_message: PostedVAAData = common::get_account_data(client, message_key).await;
    assert_eq!(posted_message.message.vaa_version, 0);
    assert_eq!(posted_message.message.consistency_level, 1);
    assert_eq!(posted_message.message.nonce, nonce);
    assert_eq!(posted_message.message.sequence, sequence);
    assert_eq!(posted_message.message.emitter_chain, 1);
    assert_eq!(
        &posted_message.message.emitter_address,
        emitter.pubkey().as_ref()
    );
    assert_eq!(posted_message.message.payload, message);
    assert_eq!(
        posted_message.message.emitter_address,
        emitter.pubkey().to_bytes()
    );

    let (vaa, body, _body_hash) =
        common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
    let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
        .await
        .unwrap();
    let message_key = PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(
        &PostedVAADerivationData {
            payload_hash: body.to_vec(),
        },
        program,
    );
    common::post_vaa(client, program, payer, signature_set, vaa)
        .await
        .unwrap();
    let err = common::upgrade_guardian_set(
        client,
        program,
        payer,
        message_key,
        emitter.pubkey(),
        0,
        1,
        sequence,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// #[tokio::test]
// async fn update_contract_success() {
//      // Initialize a wormhole bridge on Solana to test with.
//      let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

//      // New Contract Address
//      // let new_contract = Pubkey::new_unique();
//      let new_contract = *program;
 
//      let nonce = rand::thread_rng().gen();
//      let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
//      let sequence = context.seq.next(emitter.pubkey().to_bytes());
//      let message = GovernancePayloadUpgrade { new_contract }
//          .try_to_vec()
//          .unwrap();
 
//      let message_key = common::post_message(
//          client,
//          program,
//          payer,
//          &emitter,
//          None,
//          nonce,
//          message.clone(),
//          10_000,
//      )
//      .await
//      .unwrap();
 
//      let (vaa, body, _body_hash) =
//          common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 1);
//      let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
//          .await
//          .unwrap();
//      common::post_vaa(client, program, payer, signature_set, vaa)
//          .await
//          .unwrap();
//      common::upgrade_contract(
//          client,
//          program,
//          payer,
//          message_key,
//          emitter.pubkey(),
//          new_contract,
//          Pubkey::new_unique(),
//          sequence,
//      )
//      .await
//      .unwrap();
// }


#[tokio::test]
async fn update_contract_invalid_guardian_key() {
     // Initialize a wormhole bridge on Solana to test with.
     let (ref mut context, ref mut client, ref payer, ref program) = initialize().await;

     // New Contract Address
     let new_contract = *program;
 
     let nonce = rand::thread_rng().gen();
     let emitter = Keypair::new();
     let sequence = context.seq.next(emitter.pubkey().to_bytes());
     let message = GovernancePayloadUpgrade { new_contract }
         .try_to_vec()
         .unwrap();
 
     let message_key = common::post_message(
         client,
         program,
         payer,
         &emitter,
         None,
         nonce,
         message.clone(),
         10_000,
     )
     .await
     .unwrap();
 
     let (vaa, body, _body_hash) =
         common::generate_vaa(&emitter, message.clone(), nonce, sequence, 0, 2);
     let signature_set = common::verify_signatures(client, program, payer, body, &context.secret, 0)
         .await
         .unwrap();
     common::post_vaa(client, program, payer, signature_set, vaa)
         .await
         .unwrap();
    let err = common::upgrade_contract(
         client,
         program,
         payer,
         message_key,
         emitter.pubkey(),
         new_contract,
         Pubkey::new_unique(),
         sequence,
     )
     .await
     .expect_err("expected failure");

     match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        }
        BanksClientError::RpcError(_) => {
            println!("Err: DeadlineExceeded - expected failure");
        }
        other => panic!("unexpected error: {:?}", other),
    }
}
