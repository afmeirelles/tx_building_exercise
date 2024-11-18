import {
  LinearFee,
  BigNum,
  TransactionBuilder,
  TransactionBuilderConfigBuilder,
  Bip32PrivateKey,
  TransactionInput,
  TransactionHash,
  Value,
  BaseAddress,
  NetworkInfo,
  Credential,
  Address,
  Ed25519KeyHash,
  TransactionOutput,
  Vkeywitnesses,
  make_vkey_witness,
  TransactionWitnessSet,
  Transaction,
  FixedTransaction,
  encode_json_str_to_metadatum,
  MetadataJsonSchema,
  AuxiliaryData,
  GeneralTransactionMetadata,
  ScriptPubkey,
  ScriptNOfK,
  NativeScript,
  EnterpriseAddress,
  NativeScripts,
  ScriptAll,
  Bip32PublicKey,
  ScriptHash,
} from '@emurgo/cardano-serialization-lib-nodejs'
import { mnemonicToEntropy, validateMnemonic } from 'bip39'
import axios, { AxiosError } from 'axios'
import b4a from 'b4a'

const someRandomLuckyGuy = 'addr_test1qrxdmktv4l9gz3pt2hjgmsgg0z5wqylnz7qz8qrs94k6jg84370tdfqyxp4qppclmqf3sqkwk45z4tqx7xh7nrmcvcxqv9e2hf'
const adminAddress = 'addr_test1qrmflxntaxzfphhwmzf6yvmnrgrt43t08dunacgqm7zj0uh4370tdfqyxp4qppclmqf3sqkwk45z4tqx7xh7nrmcvcxq6xlhj5'

const mnemonic = process.env.MNEMONIC

if (!mnemonic || !validateMnemonic(mnemonic)) {
  throw new Error('Invalid mnemonic')
}

const getUTxOs = async (address: string) => {
  try {
    const { data } = await axios.post(
      'https://preprod-backend.yoroiwallet.com/api/txs/utxoForAddresses',
      {
        addresses: [address]
      },
      {
        headers: {
          'x-api-key': 'default-api-key-123456789',
          'Content-Type': 'application/json'
        }
      }
    )
    return data
  } catch (error) {
    console.error((error as AxiosError).response?.data)
    throw new Error('Failed to fetch UTxOs')
  }
}

const postTransaction = async (transaction: Transaction) => {
  try {
    const { data, status } = await axios.post(
      'https://preprod-backend.yoroiwallet.com/api/txs/signed',
      {
        signedTx: Buffer.from(transaction.to_bytes()).toString('base64')
      },
      {
        headers: {
          'x-api-key': 'default-api-key-123456789',
          'Content-Type': 'application/json'
        }
      }
    )
    return { status, data }
  } catch (error) {
    console.error((error as any).response?.data.error?.response.contents)
    throw new Error('Failed to send tx')
  }
}

const harden = (num: number): number => 0x80000000 + num;

type DerivedPaymentKeys = Awaited<ReturnType<typeof derivePaymentKeys>>

const derivePaymentKeys = async (mnemonic: string, index: number) => {
  const entropy = mnemonicToEntropy(mnemonic);

  const rootKey = Bip32PrivateKey.from_bip39_entropy(
    b4a.from(entropy, 'hex') as Uint8Array,
    b4a.from('') as Uint8Array,
  );

  const accountKey = rootKey
    .derive(harden(1852)) // Purpose
    .derive(harden(1815)) // Coin type
    .derive(harden(0)) // acount 0

  const paymentPrivateKey = accountKey
    .derive(0) // external chain
    .derive(index) // index 0

  const paymentPubKey = accountKey
    .derive(0) // external chain
    .derive(index) // index 0
    .to_public()

  const stakePubKey = accountKey
    .derive(2) // internal chain
    .derive(index) // index 0
    .to_public()

  const baseAddr = BaseAddress.new(
    NetworkInfo.testnet_preprod().network_id(),
    Credential.from_keyhash(paymentPubKey.to_raw_key().hash()),
    Credential.from_keyhash(stakePubKey.to_raw_key().hash())
  )

  return {
    paymentPubKey,
    paymentPrivateKey,
    paymentAddress: baseAddr.to_address().to_bech32()
  }
}

const buildMultisig = async (required: DerivedPaymentKeys[], optional: DerivedPaymentKeys[]) => {
  const optionalScript = NativeScripts.new()
  optional.forEach(({ paymentPubKey }) => {
    optionalScript.add(
      NativeScript.new_script_pubkey(
        ScriptPubkey.new(paymentPubKey.to_raw_key().hash())
      )
    )
  })

  const requiredScript = NativeScripts.new()

  required.forEach(({ paymentPubKey }) => {
    requiredScript.add(
      NativeScript.new_script_pubkey(
        ScriptPubkey.new(paymentPubKey.to_raw_key().hash())
      )
    )
  })

  const minimumQuorumScript = NativeScript.new_script_n_of_k(ScriptNOfK.new(1, optionalScript))
  const requiredQuorumScript = NativeScript.new_script_all(ScriptAll.new(requiredScript))

  const multisigRules = NativeScripts.new()

  multisigRules.add(minimumQuorumScript)
  multisigRules.add(requiredQuorumScript)

  const multisigScript = NativeScript.new_script_all(
    ScriptAll.new(multisigRules)
  )

  const multisig = EnterpriseAddress.new(
    NetworkInfo.testnet_preprod().network_id(),
    Credential.from_scripthash(multisigScript.hash()),
  )

  const multisigAddress = multisig.to_address().to_bech32()

  console.info(`Multisig address: ${multisigAddress}`)
  console.log(`Script hash: ${multisigScript.hash().to_hex()}`)

  return {
    multisig,
    multisigScript,
    address: multisigAddress
  }
}

const maybeDepositToMultisig = async (multisig: EnterpriseAddress) => {
  const addressWithAda = await derivePaymentKeys(mnemonic, 0)

  const multisigAddress = multisig.to_address().to_bech32()

  const utxos = await getUTxOs(multisigAddress)

  // optionally transfer ada to the multisig address
  if (utxos.length === 0) {
    console.info('No UTxOs found for multisig address, depositing ADA')

    await postTransaction(
      await buildTx({
        originAddress: addressWithAda.paymentAddress,
        pubKeyOrScript: addressWithAda.paymentPubKey,
        signers: [addressWithAda.paymentPrivateKey],
        outputData: [{ address: multisigAddress, amount: '100000000' }]
      })
    )

    console.info('Tx sent')
  }

}

const buildTx = async (
  { originAddress, pubKeyOrScript, signers, outputData, metadata }:
    { originAddress: string, pubKeyOrScript: Bip32PublicKey | NativeScript, signers: Bip32PrivateKey[], outputData: { address: string, amount: string }[], metadata?: Record<string, any> }
) => {
  console.log(`Building transaction for ${originAddress}`)

  const linearFee = LinearFee.new(
    BigNum.from_str('44'),
    BigNum.from_str('155381')
  )

  // @todo check each param
  const txBuilderConfig = TransactionBuilderConfigBuilder.new()
    .fee_algo(linearFee)
    .pool_deposit(BigNum.from_str('500000000'))
    .key_deposit(BigNum.from_str('2000000'))
    .max_value_size(4000)
    .max_tx_size(16384)
    .coins_per_utxo_byte(BigNum.from_str('44'))
    .build()

  const utxos = await getUTxOs(originAddress) as { tx_hash: string, tx_index: number, amount: string }[]

  if (utxos.length === 0) throw new Error(`No UTxOs found for address ${originAddress}`)

  console.info(`Address ${originAddress} utxo amount: ${utxos[0].amount}`)

  const { tx_hash, tx_index, amount } = utxos[0]

  const txBuilder = TransactionBuilder.new(txBuilderConfig)
  const inputAmount = BigNum.from_str(amount)

  if (pubKeyOrScript instanceof Bip32PublicKey) {
    txBuilder.add_key_input(
      pubKeyOrScript.to_raw_key().hash(),
      TransactionInput.new(
        TransactionHash.from_hex(tx_hash),
        tx_index
      ),
      Value.new(inputAmount)
    )
  } else {
    txBuilder.add_native_script_input(
      pubKeyOrScript,
      TransactionInput.new(
        TransactionHash.from_hex(tx_hash),
        tx_index
      ),
      Value.new(inputAmount)
    )
  }

  outputData.forEach(output => {
    txBuilder.add_output(
      TransactionOutput.new(
        Address.from_bech32(output.address),
        Value.new(BigNum.from_str(output.amount))
      )
    )
  });

  let auxiliaryData = metadata && addMetadata(txBuilder, metadata)

  txBuilder.add_change_if_needed(
    Address.from_bech32(originAddress)
  )

  const txBody = txBuilder.build()

  const txHash = FixedTransaction
    .new_from_body_bytes(txBody.to_bytes())
    .transaction_hash()

  const vkeyWitnesses = Vkeywitnesses.new()

  signers.forEach(signer => {
    vkeyWitnesses.add(
      make_vkey_witness(txHash, signer.to_raw_key())
    )
  })

  const witnesses = TransactionWitnessSet.new()
  witnesses.set_vkeys(vkeyWitnesses)

  if (pubKeyOrScript instanceof NativeScript) {
    const nativeScripts = NativeScripts.new()
    nativeScripts.add(pubKeyOrScript)

    witnesses.set_native_scripts(nativeScripts)
  }

  const transaction = Transaction.new(
    txBody,
    witnesses,
    auxiliaryData
  );

  if (!transaction.is_valid()) throw new Error('Invalid transaction')

  return transaction
}

const addMetadata = (txBuilder: TransactionBuilder, metadataJSON: Record<string, any>) => {
  const metadata = encode_json_str_to_metadatum(
    JSON.stringify(metadataJSON),
    MetadataJsonSchema.NoConversions
  )

  const generalMetadata = GeneralTransactionMetadata.new()
  generalMetadata.insert(
    BigNum.from_str('1'),
    metadata
  )

  const auxiliaryData = AuxiliaryData.new()

  auxiliaryData.set_metadata(generalMetadata)

  txBuilder.set_auxiliary_data(auxiliaryData)

  return auxiliaryData
}


const mojo = async () => {
  const admin = await derivePaymentKeys(mnemonic, 0)
  const bob = await derivePaymentKeys(mnemonic, 1)
  const charles = await derivePaymentKeys(mnemonic, 2)
  const dickinson = await derivePaymentKeys(mnemonic, 4)

  const {
    multisig,
    multisigScript,
    address: multisigAddress
  } = await buildMultisig([admin], [bob, charles, dickinson])

  await maybeDepositToMultisig(multisig)

  const transaction = await buildTx({
    originAddress: multisigAddress,
    pubKeyOrScript: multisigScript,
    signers: [admin.paymentPrivateKey, bob.paymentPrivateKey],
    outputData: [{ address: someRandomLuckyGuy, amount: '1000000' }],
  })

  console.log(transaction.to_json())

  // await postTransaction(transaction)
}

mojo()