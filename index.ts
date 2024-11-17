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
  TransactionMetadatum,
  MetadataMap,
  encode_json_str_to_metadatum,
  MetadataJsonSchema,
  AuxiliaryData,
  GeneralTransactionMetadata,
  hash_auxiliary_data,
} from '@emurgo/cardano-serialization-lib-nodejs'
import { mnemonicToEntropy, validateMnemonic } from 'bip39'
import axios, { AxiosError } from 'axios'
import b4a from 'b4a'


const aliceOutputAddress = 'addr_test1qrxdmktv4l9gz3pt2hjgmsgg0z5wqylnz7qz8qrs94k6jg84370tdfqyxp4qppclmqf3sqkwk45z4tqx7xh7nrmcvcxqv9e2hf'
const bobOutputAddress = 'addr_test1qqgsysyltetnahpe4ynpxhldr2fvcv0n8gdee9kag2va6cl4370tdfqyxp4qppclmqf3sqkwk45z4tqx7xh7nrmcvcxqgwyx3c'
const mainAddress = 'addr_test1qrmflxntaxzfphhwmzf6yvmnrgrt43t08dunacgqm7zj0uh4370tdfqyxp4qppclmqf3sqkwk45z4tqx7xh7nrmcvcxq6xlhj5'

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


const postTransaction = async (encodedTx: Uint8Array) => {
  try {
    const { data, status } = await axios.post(
      'https://preprod-backend.yoroiwallet.com/api/txs/signed',
      {
        signedTx: Buffer.from(encodedTx).toString('base64')
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
    console.error((error as AxiosError).response?.data.error.response.contents)
    throw new Error('Failed to send tx')
  }
}

const harden = (num: number): number => 0x80000000 + num;

const derivePrivateKey = async () => {

  const entropy = mnemonicToEntropy(mnemonic);

  const rootKey = Bip32PrivateKey.from_bip39_entropy(
    b4a.from(entropy, 'hex') as Uint8Array,
    b4a.from('') as Uint8Array,
  );

  const accountKey = rootKey
    .derive(harden(1852)) // Purpose
    .derive(harden(1815)) // Coin type
    .derive(harden(0)) // acount 0

  const paymentPubKey = accountKey
    .derive(0) // external chain
    .derive(0) // index 0
    .to_public()

  const stakeKey = accountKey
    .derive(2) // staking key index
    .derive(0)
    .to_public()

  const baseAddr = BaseAddress.new(
    NetworkInfo.testnet_preprod().network_id(),
    Credential.from_keyhash(paymentPubKey.to_raw_key().hash()),
    Credential.from_keyhash(stakeKey.to_raw_key().hash()),
  );

  console.assert(baseAddr.to_address().to_bech32() === mainAddress, 'Incorrect payment address')

  return {
    address: paymentPubKey.to_raw_key().hash(),
    paymentKey: accountKey.derive(0).derive(0),
  }
}

const buildTx = async ({ address, paymentKey }: { address: Ed25519KeyHash, paymentKey: Bip32PrivateKey }) => {
  // @todo check fee calculation and incentives (burning?)
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
    .coins_per_utxo_byte(BigNum.from_str('34482'))
    .build()

  const utxos = await getUTxOs(mainAddress)

  if (utxos.length === 0) throw new Error('No UTxOs found')

  const { tx_hash, tx_index, amount } = utxos[0] as { tx_hash: string, tx_index: number, amount: string }

  const txBuilder = TransactionBuilder.new(txBuilderConfig)
  const inputAmount = BigNum.from_str(amount)
  const outputAmount1 = BigNum.from_str('8000000')
  const outputAmount2 = BigNum.from_str('8000000')

  txBuilder.add_key_input(
    address,
    TransactionInput.new(
      TransactionHash.from_hex(tx_hash),
      tx_index
    ),
    Value.new(inputAmount)
  )

  txBuilder.add_output(
    TransactionOutput.new(
      Address.from_bech32(aliceOutputAddress),
      Value.new(outputAmount1)
    )
  )
  txBuilder.add_output(
    TransactionOutput.new(
      Address.from_bech32(bobOutputAddress),
      Value.new(outputAmount2)
    )
  )

  txBuilder.add_change_if_needed(Address.from_bech32(mainAddress))

  // const metadata = encode_json_str_to_metadatum(
  //   JSON.stringify({
  //     who: 'you',
  //     gonna: 'call?'
  //   }),
  //   MetadataJsonSchema.NoConversions
  // )

  // const generalMetadata = GeneralTransactionMetadata.new()
  // generalMetadata.insert(
  //   BigNum.from_str('1'),
  //   metadata
  // )

  // const auxiliaryData = AuxiliaryData.new()

  // console.log('Calculated Fee:', txBuilder.min_fee().to_str());
  // console.log('Fee Set in Builder:', txBuilder.get_fee_if_set()?.to_str());

  // Build the transaction body
  const txBody = txBuilder.build();
  console.log('Transaction Fee in Built Body:', txBody.fee().to_str());

  const txHash = FixedTransaction
    .new_from_body_bytes(txBody.to_bytes())
    .transaction_hash()

  const vkeyWitnesses = Vkeywitnesses.new()
  const vkeyWitness = make_vkey_witness(txHash, paymentKey.to_raw_key())

  vkeyWitnesses.add(vkeyWitness)

  const witnesses = TransactionWitnessSet.new()

  witnesses.set_vkeys(vkeyWitnesses)

  const transaction = Transaction.new(
    txBody,
    witnesses,
    // auxiliaryData
  );

  return transaction.to_bytes()
}

derivePrivateKey()
  .then(buildTx)
  .then(postTransaction)
  .then(console.info)