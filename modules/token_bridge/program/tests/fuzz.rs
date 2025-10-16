#![allow(dead_code)]
use bridge::{
    accounts::{
        PostedVAA,
        PostedVAADerivationData,
        Bridge,
        FeeCollector,
        Sequence,
        SequenceDerivationData,
    },
    SerializePayload,
};
use libsecp256k1::SecretKey;
use primitive_types::U256;
use rand::Rng;
use solana_program::{
    pubkey::Pubkey,
    instruction::{
        AccountMeta,
        Instruction,
    },
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
    transport::TransportError,
    commitment_config::CommitmentLevel,
};
use solitaire::{
    processors::seeded::Seeded,
    AccountState,
    BorshSerialize,
};
use std::{
    collections::HashMap,
    str::FromStr,
};
use token_bridge::{
    accounts::{
        ConfigAccount,
        Endpoint,
        EndpointDerivationData,
        WrappedDerivationData,
        WrappedMint,
        AuthoritySigner,
        EmitterAccount,
        SplTokenMeta,
        SplTokenMetaDerivationData,
        WrappedMetaDerivationData,
        WrappedTokenMeta,
    },
    messages::{
        PayloadAssetMeta,
        PayloadGovernanceRegisterChain,
        PayloadTransfer,
    },
    types::{
        Config,
        EndpointRegistration,
    },
    api::{
        AttestTokenData,
        TransferWrappedData
    },
};
use solana_program::instruction::InstructionError;
use solana_program_test::BanksClientError;
use solana_sdk::transaction::TransactionError;
use token_bridge::instruction::Instruction::{ 
    TransferWrapped,
    AttestToken,
};
use anyhow::Result;

use token_bridge::{
    instructions,
    TokenBridgeError
};

mod common;

const GOVERNANCE_KEY: [u8; 64] = [
    240, 133, 120, 113, 30, 67, 38, 184, 197, 72, 234, 99, 241, 21, 58, 225, 41, 157, 171, 44, 196,
    163, 134, 236, 92, 148, 110, 68, 127, 114, 177, 0, 173, 253, 199, 9, 242, 142, 201, 174, 108,
    197, 18, 102, 115, 0, 31, 205, 127, 188, 191, 56, 171, 228, 20, 247, 149, 170, 141, 231, 147,
    88, 97, 199,
];

const CHAIN_ID_SOLANA: u16 = 1;
const CHAIN_ID_ETH: u16 = 2;

struct Context {
    /// Guardian public keys.
    guardians: Vec<[u8; 20]>,

    /// Guardian secret keys.
    guardian_keys: Vec<SecretKey>,

    /// Address of the core bridge contract.
    bridge: Pubkey,

    /// Shared RPC client for tests to make transactions with.
    client: BanksClient,

    /// Payer key with a ton of lamports to ease testing with.
    payer: Keypair,

    /// Track nonces throughout the tests.
    seq: Sequencer,

    /// Address of the token bridge itself that we wish to test.
    token_bridge: Pubkey,

    /// Keypairs for mint information, required in multiple tests.
    mint_authority: Keypair,
    mint: Keypair,
    mint_meta: Pubkey,

    /// Keypairs for test token accounts.
    token_authority: Keypair,
    token_account: Keypair,
    metadata_account: Pubkey,
}

/// Small helper to track and provide sequences during tests. This is in particular needed for
/// guardian operations that require them for derivations.
struct Sequencer {
    sequences: HashMap<[u8; 32], u64>,
}

impl Sequencer {
    fn next(&mut self, emitter: [u8; 32]) -> u64 {
        let entry = self.sequences.entry(emitter).or_insert(0);
        *entry += 1;
        *entry - 1
    }

    fn peek(&mut self, emitter: [u8; 32]) -> u64 {
        *self.sequences.entry(emitter).or_insert(0)
    }
}

async fn set_up() -> Result<Context, TransportError> {
    let (guardians, guardian_keys) = common::generate_keys(6);

    let (mut client, payer, bridge, token_bridge) = common::setup().await;

    // Setup a Bridge to test against.
    common::initialize_bridge(&mut client, bridge, &payer, &guardians).await?;

    // Context for test environment.
    let mint = Keypair::new();
    let mint_pubkey = mint.pubkey();
    let metadata_pubkey = Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap();

    // SPL Token Meta
    let metadata_seeds = &[
        "metadata".as_bytes(),
        metadata_pubkey.as_ref(),
        mint_pubkey.as_ref(),
    ];

    let (metadata_key, _metadata_bump_seed) = Pubkey::find_program_address(
        metadata_seeds,
        &Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap(),
    );

    // Token Bridge Meta
    let metadata_account = WrappedTokenMeta::<'_, { AccountState::Uninitialized }>::key(
        &token_bridge::accounts::WrappedMetaDerivationData {
            mint_key: mint_pubkey,
        },
        &token_bridge,
    );

    let mut context = Context {
        guardians,
        guardian_keys,
        seq: Sequencer {
            sequences: HashMap::new(),
        },
        bridge,
        client,
        payer,
        token_bridge,
        mint_authority: Keypair::new(),
        mint,
        mint_meta: metadata_account,
        token_account: Keypair::new(),
        token_authority: Keypair::new(),
        metadata_account: metadata_key,
    };

    // Create a mint for use within tests.
    common::create_mint(
        &mut context.client,
        &context.payer,
        &context.mint_authority.pubkey(),
        &context.mint,
    )
    .await?;

    // Create Token accounts for use within tests.
    common::create_token_account(
        &mut context.client,
        &context.payer,
        &context.token_account,
        &context.token_authority.pubkey(),
        &context.mint.pubkey(),
    )
    .await?;

    // Mint tokens
    common::mint_tokens(
        &mut context.client,
        &context.payer,
        &context.mint_authority,
        &context.mint,
        &context.token_account.pubkey(),
        1000,
    )
    .await?;

    // Initialize the token bridge.
    common::initialize(
        &mut context.client,
        context.token_bridge,
        &context.payer,
        context.bridge,
    )
    .await
    .unwrap();

    // Verify Token Bridge State
    let config_key = ConfigAccount::<'_, { AccountState::Uninitialized }>::key(None, &token_bridge);
    let config: Config = common::get_account_data(&mut context.client, config_key)
        .await
        .unwrap();
    assert_eq!(config.wormhole_bridge, bridge);

    Ok(context)
}

async fn create_wrapped(context: &mut Context) -> Pubkey {
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        mint_authority: _,
        mint: _,
        mint_meta: _,
        token_account: _,
        token_authority: _,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadAssetMeta {
        token_address: [1u8; 32],
        token_chain: 2,
        decimals: 7,
        symbol: "".to_string(),
        name: "".to_string(),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa([0u8; 32], 2, message, nonce, 2);
    let signature_set =
        common::verify_signatures(client, bridge, payer, body, &context.guardian_keys, 0)
            .await
            .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, bridge);

    common::create_wrapped(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();

    WrappedMint::<'_, { AccountState::Initialized }>::key(
        &WrappedDerivationData {
            token_chain: 2,
            token_address: [1u8; 32],
        },
        token_bridge,
    )
}

// Create an SPL Metadata account to test attestations for wrapped tokens.
async fn create_wrapped_account(context: &mut Context) -> Result<Pubkey, TransportError> {
    common::create_spl_metadata(
        &mut context.client,
        &context.payer,
        context.metadata_account,
        &context.mint_authority,
        &context.mint,
        context.payer.pubkey(),
        "BTC".to_string(),
        "Bitcoin".to_string(),
    )
    .await?;

    let wrapped = create_wrapped(context).await;
    let wrapped_acc = Keypair::new();
    common::create_token_account(
        &mut context.client,
        &context.payer,
        &wrapped_acc,
        &context.token_authority.pubkey(),
        &wrapped,
    )
    .await?;

    Ok(wrapped_acc.pubkey())
}

async fn register_chain(context: &mut Context) {
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();
    let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let payload = PayloadGovernanceRegisterChain {
        chain: 2,
        endpoint_address: [0u8; 32],
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa(emitter.pubkey().to_bytes(), 1, message, nonce, 0);
    let signature_set = common::verify_signatures(client, bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, bridge);

    common::register_chain(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn register_chain_success() {
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        ref guardian_keys,
        ..
    } = set_up().await.unwrap();

    let nonce = rand::thread_rng().gen();
    let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let payload = PayloadGovernanceRegisterChain {
        chain: 2,
        endpoint_address: [0u8; 32],
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa(emitter.pubkey().to_bytes(), 1, message, nonce, 0);
    let signature_set = common::verify_signatures(client, bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, bridge);

    common::register_chain(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn register_chain_invalid_vaa() {
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        ref guardian_keys,
        ..
    } = set_up().await.unwrap();

    let nonce = rand::thread_rng().gen();
    let emitter = Keypair::from_bytes(&GOVERNANCE_KEY).unwrap();
    let payload = PayloadGovernanceRegisterChain {
        chain: 2,
        endpoint_address: [0u8; 32],
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa(emitter.pubkey().to_bytes(), 1, message, nonce, 0);
    let signature_set = common::verify_signatures(client, bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let message_key = Pubkey::from_str("28Tx7c3W8rggVNyUQEAL9Uq6pUng4xJLAeLA6V8nLH1Z").unwrap();

    let err = common::register_chain(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
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
async fn attest_success() {
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        mint_authority: _,
        ref mint,
        mint_meta: _,
        metadata_account: _,
        ..
    } = set_up().await.unwrap();

    let message = &Keypair::new();

    common::attest(
        client,
        token_bridge,
        bridge,
        payer,
        message,
        mint.pubkey(),
        0,
    )
    .await
    .unwrap();
}

// #[tokio::test]
// async fn attest_non_exit_token_metadata_account() -> Result<()> {
//     let Context {
//         ref payer,
//         ref mut client,
//         bridge,
//         token_bridge,
//         mint_authority: _,
//         ref mint,
//         mint_meta: _,
//         metadata_account: _,
//         ..
//     } = set_up().await.unwrap();

//     let message_key = &Keypair::new();

//     let config_key = ConfigAccount::<'_, { AccountState::Uninitialized }>::key(None, &token_bridge);
//     let emitter_key = EmitterAccount::key(None, &token_bridge);

//     // spl metadata with non token metatdata
//     // Context for test environment.
//     let metadata_pubkey = Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap();

//     // SPL Token Meta
//     let (metadata_key, _metadata_bump_seed) = Pubkey::find_program_address(
//         &[],
//         &Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap(),
//     );

//     // Mint Metadata
//     let mint_meta = WrappedTokenMeta::<'_, { AccountState::Uninitialized }>::key(
//         &WrappedMetaDerivationData { mint_key: mint.pubkey() },
//         &token_bridge,
//     );

//     // Bridge Keys
//     let bridge_config = Bridge::<'_, { AccountState::Uninitialized }>::key(None, &bridge);
//     let sequence_key = Sequence::key(
//         &SequenceDerivationData {
//             emitter_key: &emitter_key,
//         },
//         &bridge,
//     );
//     let fee_collector_key = FeeCollector::key(None, &bridge);
//     let nonce = rand::thread_rng().gen();

//     let instruction = Instruction {
//         program_id: token_bridge,
//         accounts: vec![
//             AccountMeta::new(payer.pubkey(), true),
//             AccountMeta::new(config_key, false),
//             AccountMeta::new_readonly(mint.pubkey(), false),
//             AccountMeta::new_readonly(mint_meta, false),
//             AccountMeta::new_readonly(metadata_key, false),
//             // Bridge accounts
//             AccountMeta::new(bridge_config, false),
//             AccountMeta::new(message_key.pubkey(), true),
//             AccountMeta::new_readonly(emitter_key, false),
//             AccountMeta::new(sequence_key, false),
//             AccountMeta::new(fee_collector_key, false),
//             AccountMeta::new_readonly(solana_program::sysvar::clock::id(), false),
//             // Dependencies
//             AccountMeta::new(solana_program::sysvar::rent::id(), false),
//             AccountMeta::new(solana_program::system_program::id(), false),
//             // Program
//             AccountMeta::new_readonly(bridge, false),
//         ],
//         data: (
//             AttestToken,
//             AttestTokenData { nonce },
//         )
//         .try_to_vec()?,
//     };

//     let err = common::execute(
//         client,
//         payer,
//         &[payer, message_key],
//         &[instruction],
//         CommitmentLevel::Processed,
//     )
//     .await
//     .expect_err("expected failure");

//     match err {
//         BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
//             assert_eq!(code, false as u32);
//         } 
//         other => panic!("unexpected error: {:?}", other),
//     }; 

//     Ok(())
// }

#[tokio::test]
async fn attest_wrong_account_owner() -> Result<()> {
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        mint_authority: _,
        ref mint,
        mint_meta: _,
        metadata_account: _,
        ..
    } = set_up().await.unwrap();

    let message_key = &Keypair::new();

    let config_key = ConfigAccount::<'_, { AccountState::Uninitialized }>::key(None, &token_bridge);
    let emitter_key = EmitterAccount::key(None, &token_bridge);

    // spl metadata ís not valid account owner
    // Context for test environment.
    let mint1 = Keypair::new();
    let mint_pubkey = mint1.pubkey();
    let metadata_pubkey = Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap();

    // SPL Token Meta
    let metadata_seeds = &[
        "metadata".as_bytes(),
        token_bridge.as_ref(),
        mint_pubkey.as_ref(),
    ];

    let (metadata_key, _metadata_bump_seed) = Pubkey::find_program_address(
        metadata_seeds,
        &Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap(),
    );

    // Token Bridge Meta
    let metadata_account = WrappedTokenMeta::<'_, { AccountState::Uninitialized }>::key(
        &token_bridge::accounts::WrappedMetaDerivationData {
            mint_key: mint_pubkey,
        },
        &token_bridge,
    );

    // Mint Metadata
    let mint_meta = WrappedTokenMeta::<'_, { AccountState::Uninitialized }>::key(
        &WrappedMetaDerivationData { mint_key: mint.pubkey() },
        &token_bridge,
    );

    // Bridge Keys
    let bridge_config = Bridge::<'_, { AccountState::Uninitialized }>::key(None, &bridge);
    let sequence_key = Sequence::key(
        &SequenceDerivationData {
            emitter_key: &emitter_key,
        },
        &bridge,
    );
    let fee_collector_key = FeeCollector::key(None, &bridge);
    let nonce = rand::thread_rng().gen();

    let instruction = Instruction {
        program_id: token_bridge,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config_key, false),
            AccountMeta::new_readonly(mint1.pubkey(), false),
            AccountMeta::new_readonly(mint_meta, false),
            AccountMeta::new_readonly(metadata_key, false),
            // Bridge accounts
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(message_key.pubkey(), true),
            AccountMeta::new_readonly(emitter_key, false),
            AccountMeta::new(sequence_key, false),
            AccountMeta::new(fee_collector_key, false),
            AccountMeta::new_readonly(solana_program::sysvar::clock::id(), false),
            // Dependencies
            AccountMeta::new(solana_program::sysvar::rent::id(), false),
            AccountMeta::new(solana_program::system_program::id(), false),
            // Program
            AccountMeta::new_readonly(bridge, false),
        ],
        data: (
            AttestToken,
            AttestTokenData { nonce },
        )
        .try_to_vec()?,
    };

    let err = common::execute(
        client,
        payer,
        &[payer, message_key],
        &[instruction],
        CommitmentLevel::Processed,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        } 
        other => panic!("unexpected error: {:?}", other),
    }; 

    Ok(())
}

#[tokio::test]
async fn create_wrapped_success() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;

    // Create a wrapped mint and a token account for it owned by the test authority
    let wrapped_mint = create_wrapped(&mut context).await;
}

#[tokio::test]
async fn create_wrapped_invalid_chain() {
    let mut context = set_up().await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        mint_authority: _,
        mint: _,
        mint_meta: _,
        token_account: _,
        token_authority: _,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadAssetMeta {
        token_address: [1u8; 32],
        token_chain: 3, //modify
        decimals: 7,
        symbol: "".to_string(),
        name: "".to_string(),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa([0u8; 32], 2, message, nonce, 2);
    let signature_set =
        common::verify_signatures(client, bridge, payer, body, &context.guardian_keys, 0)
            .await
            .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, bridge);

    let err = common::create_wrapped(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
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
async fn create_wrapped_invalid_vaa() {
    let mut context = set_up().await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        ref bridge,
        ref token_bridge,
        mint_authority: _,
        mint: _,
        mint_meta: _,
        token_account: _,
        token_authority: _,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadAssetMeta {
        token_address: [1u8; 32],
        token_chain: 3, //modify
        decimals: 7,
        symbol: "".to_string(),
        name: "".to_string(),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa([0u8; 32], 2, message, nonce, 2);
    let signature_set =
        common::verify_signatures(client, bridge, payer, body, &context.guardian_keys, 0)
            .await
            .unwrap();
    common::post_vaa(client, *bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let message_key = Pubkey::from_str("28Tx7c3W8rggVNyUQEAL9Uq6pUng4xJLAeLA6V8nLH1Z").unwrap();

    let err = common::create_wrapped(
        client,
        *token_bridge,
        *bridge,
        message_key,
        vaa,
        payload,
        payer,
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
async fn transfer_wrapped_success() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();
    common::transfer_wrapped(
        client,
        token_bridge,
        bridge,
        payer,
        message,
        to,
        token_authority,
        2,
        [1u8; 32],
        10000000,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn transfer_native_success() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref mint,
        ref token_account,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    // Do an initial transfer so that the bridge account has some native tokens. This also creates
    // the custody account.
    let message = &Keypair::new();
    common::transfer_native(
        client,
        token_bridge,
        bridge,
        payer,
        message,
        token_account,
        token_authority,
        mint.pubkey(),
        100,
    )
    .await
    .unwrap();

    let nonce = rand::thread_rng().gen();

    let payload = PayloadTransfer {
        amount: U256::from(100u128),
        token_address: mint.pubkey().to_bytes(),
        token_chain: 1,
        to: token_account.pubkey().to_bytes(),
        to_chain: 1,
        fee: U256::from(0u128),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) = common::generate_vaa([0u8; 32], 2, message, nonce, 1);
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    common::complete_native(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn transfer_wrapped_wrong_account_owner() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();

    let new_authority = &Keypair::new();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();
    let err = common::transfer_wrapped(
        client,
        token_bridge,
        bridge,
        payer,
        message,
        to,
        new_authority,
        2,
        [1u8; 32],
        10000000,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, 4);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn transfer_wrapped_invalid_chain() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();
    let instruction = instructions::transfer_wrapped(
        token_bridge,
        bridge,
        payer.pubkey(),
        message.pubkey(),
        to,
        token_authority.pubkey(),
         2,
        [1u8; 32],
        TransferWrappedData {
            nonce: 0,
            amount: 10000000,
            fee: 0,
            target_address: [5u8; 32],
            target_chain: 1,
        },
    )
    .expect("Could not create Transfer Native");

    for account in instruction.accounts.iter().enumerate() {
        println!("{}: {}", account.0, account.1.pubkey);
    }

    let err = common::execute(
        client,
        payer,
        &[payer, token_authority, message],
        &[
            spl_token::instruction::approve(
                &spl_token::id(),
                &to,
                &token_bridge::accounts::AuthoritySigner::key(None, &token_bridge),
                &token_authority.pubkey(),
                &[],
                10000000,
            )
            .unwrap(),
            instruction,
        ],
        CommitmentLevel::Processed,
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
async fn transfer_wrapped_invalid_mint() -> Result<()> {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let from = create_wrapped_account(&mut context).await.unwrap();

    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ..
    } = context;


    let message_key = &Keypair::new();
    let config_key = ConfigAccount::<'_, { AccountState::Uninitialized }>::key(None, &token_bridge);

    let wrapped_mint_key = WrappedMint::<'_, { AccountState::Uninitialized }>::key(
        &WrappedDerivationData {
            token_chain: 2,
            token_address: [12u8; 32], // Modify
        },
        &token_bridge,
    );
    let wrapped_meta_key = WrappedTokenMeta::<'_, { AccountState::Uninitialized }>::key(
        &WrappedMetaDerivationData {
            mint_key: wrapped_mint_key,
        },
        &token_bridge,
    );

    let authority_signer = AuthoritySigner::key(None, &token_bridge);
    let emitter_key = EmitterAccount::key(None, &token_bridge);

    // Bridge keys
    let bridge_config = Bridge::<'_, { AccountState::Uninitialized }>::key(None, &bridge);
    let sequence_key = Sequence::key(
        &SequenceDerivationData {
            emitter_key: &emitter_key,
        },
        &bridge,
    );
    let fee_collector_key = FeeCollector::key(None, &bridge);

    let instruction = TransferWrapped;

    let additional_data =  TransferWrappedData {
        nonce: 0,
        amount: 10000000,
        fee: 0,
        target_address: [5u8; 32],
        target_chain: 2,
    };

    let transfer_instruction = Instruction {
        program_id: token_bridge,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(from, false),
            AccountMeta::new_readonly(token_authority.pubkey(), true),
            AccountMeta::new(wrapped_mint_key, false),
            AccountMeta::new_readonly(wrapped_meta_key, false),
            AccountMeta::new_readonly(authority_signer, false),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(message_key.pubkey(), true),
            AccountMeta::new_readonly(emitter_key, false),
            AccountMeta::new(sequence_key, false),
            AccountMeta::new(fee_collector_key, false),
            AccountMeta::new_readonly(solana_program::sysvar::clock::id(), false),
            // Dependencies
            AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_program::system_program::id(), false),
            // Program
            AccountMeta::new_readonly(bridge, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: (instruction, additional_data).try_to_vec()?,
    };

    for account in transfer_instruction.accounts.iter().enumerate() {
        println!("{}: {}", account.0, account.1.pubkey);
    };

    let err = common::execute(
        client,
        payer,
        &[payer, token_authority, &message_key],
        &[
            spl_token::instruction::approve(
                &spl_token::id(),
                &from,
                &token_bridge::accounts::AuthoritySigner::key(None, &token_bridge),
                &token_authority.pubkey(),
                &[],
                10000000,
            )
            .unwrap(),
            transfer_instruction,
        ],
        CommitmentLevel::Processed,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        } 
        other => panic!("unexpected error: {:?}", other),
    }; 

    Ok(())
}

#[tokio::test]
async fn transfer_wrapped_invalid_fee() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let from = create_wrapped_account(&mut context).await.unwrap();

    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ..
    } = context;

    let message = &Keypair::new();

    let instruction = instructions::transfer_wrapped(
        token_bridge,
        bridge,
        payer.pubkey(),
        message.pubkey(),
        from,
        token_authority.pubkey(),
        2,
        [1u8; 32],
        TransferWrappedData {
            nonce: 0,
            amount: 10000000,
            fee: 20000000, // modify
            target_address: [5u8; 32],
            target_chain: 2,
        },
    )
    .expect("Could not create Transfer Native");

    for account in instruction.accounts.iter().enumerate() {
        println!("{}: {}", account.0, account.1.pubkey);
    }

    let err = common::execute(
        client,
        payer,
        &[payer, token_authority, message],
        &[
            spl_token::instruction::approve(
                &spl_token::id(),
                &from,
                &token_bridge::accounts::AuthoritySigner::key(None, &token_bridge),
                &token_authority.pubkey(),
                &[],
                10000000,
            )
            .unwrap(),
            instruction,
        ],
        CommitmentLevel::Processed,
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
async fn transfer_native_token_not_native() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;

    // Create a wrapped mint and a token account for it owned by the test authority
    let wrapped_mint = create_wrapped(&mut context).await;
    let wrapped_from = Keypair::new();
    common::create_token_account(
        &mut context.client,
        &context.payer,
        &wrapped_from,
        &context.token_authority.pubkey(),
        &wrapped_mint,
    )
    .await
    .unwrap();

    // Attempt native transfer with wrapped mint should fail with TokenNotNative
    let message = &Keypair::new();
    let result = common::transfer_native(
        &mut context.client,
        context.token_bridge,
        context.bridge,
        &context.payer,
        message,
        &wrapped_from,
        &context.token_authority,
        wrapped_mint,
        100,
    )
    .await;

    use solana_program::instruction::InstructionError;
    use solana_sdk::transaction::TransactionError;
    match result {
        Err(solana_program_test::BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code)))) => {
            assert_eq!(code, false as u32);
        }
        other => panic!("expected TokenNotNative error, got {:?}", other),
    }
}

#[tokio::test]
async fn complete_transfer_wrapped_success() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();
    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();
    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn complete_transfer_wrapped_invalid_mint() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
   
    let payload_2 = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [12u8; 32],
        token_chain: 4,
        to: to.to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
   
    let message = payload.try_to_vec().unwrap();
    let message_2 = payload_2.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());

    let (_vaa_2, _body_2, _) =
        common::generate_vaa([0u8; 32], 2, message_2, nonce, rand::thread_rng().gen());
    
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();

    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: _body_2.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    let err = common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        },
        _other => panic!("expected panic"),
    }
}

#[tokio::test]
async fn complete_transfer_wrapped_invalid_recipient() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();

    let new_target = &Keypair::new();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: new_target.pubkey().to_bytes(),
        to_chain: 1,
        fee: U256::from(0u8),
    };
   
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();

    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    let err = common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .expect_err("expected failure");

    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, false as u32);
        },
        _other => panic!("expected panic"),
    }
}

#[tokio::test]
async fn complete_transfer_wrapped_insufficient_funds() {
    let mut context = set_up().await.unwrap();
    register_chain(&mut context).await;
    let to = create_wrapped_account(&mut context).await.unwrap();
    let Context {
        ref payer,
        ref mut client,
        bridge,
        token_bridge,
        ref token_authority,
        ref guardian_keys,
        ..
    } = context;

    let nonce = rand::thread_rng().gen();

    // Now transfer the wrapped tokens back, which will burn them.
    let message = &Keypair::new();
    let new_target = &Keypair::new();

    let payload = PayloadTransfer {
        amount: U256::from(100000000u128),
        token_address: [1u8; 32],
        token_chain: 2,
        to: new_target.pubkey().to_bytes(),
        to_chain: 1,
        fee: U256::from(200000000u128),
    };
   
    let message = payload.try_to_vec().unwrap();

    let (vaa, body, _) =
        common::generate_vaa([0u8; 32], 2, message, nonce, rand::thread_rng().gen());
    
    let signature_set = common::verify_signatures(client, &bridge, payer, body, guardian_keys, 0)
        .await
        .unwrap();

    common::post_vaa(client, bridge, payer, signature_set, vaa.clone())
        .await
        .unwrap();

    let msg_derivation_data = &PostedVAADerivationData {
        payload_hash: body.to_vec(),
    };
    let message_key =
        PostedVAA::<'_, { AccountState::MaybeInitialized }>::key(msg_derivation_data, &bridge);

    assert!(common::complete_transfer_wrapped(
        client,
        token_bridge,
        bridge,
        message_key,
        vaa,
        payload,
        payer,
    )
    .await
    .is_err());
}
