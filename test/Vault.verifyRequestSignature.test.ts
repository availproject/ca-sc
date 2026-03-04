import { expect } from "chai";
import hre from "hardhat";
import { hashMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const { ethers } = hre;

const MESSAGE_PREFIX = "Sign this intent to proceed \n";
const PK_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const PK_1 =
  "0x59c6995e998f97a5a0044976f094538e7c7f1c43b6e6b7965a7ab6a8f7f4d7a0" as const;

function toBytes32Address(address: string): string {
  return ethers.zeroPadValue(address, 32);
}

describe("Vault verifyRequestSignature (viem signed message)", function () {
  it("accepts a signature produced by viem signMessage over prefix + 0xhash", async function () {
    const vault = await ethers.deployContract("Vault");
    await vault.waitForDeployment();

    const account = privateKeyToAccount(PK_0);

    const request = {
      sources: [],
      destinationUniverse: 0,
      destinationChainID: 31337,
      recipientAddress: ethers.ZeroHash,
      destinations: [],
      nonce: 1n,
      expiry: 2_000_000_000n,
      parties: [{ universe: 0, address_: toBytes32Address(account.address) }],
    };

    const hash = await vault.getHashToSign(request);
    const encodedMessage = MESSAGE_PREFIX + hash;
    const signature = await account.signMessage({ message: encodedMessage });

    const [ok, signedMessageHash] = await vault.verifyRequestSignature(request, signature);
    expect(ok).to.equal(true);
    expect(signedMessageHash).to.equal(hashMessage(encodedMessage));
  });

  it("rejects signature when signer is not the Ethereum party", async function () {
    const vault = await ethers.deployContract("Vault");
    await vault.waitForDeployment();

    const signerAccount = privateKeyToAccount(PK_1);

    const request = {
      sources: [],
      destinationUniverse: 0,
      destinationChainID: 31337,
      recipientAddress: ethers.ZeroHash,
      destinations: [],
      nonce: 2n,
      expiry: 2_000_000_000n,
      parties: [{ universe: 0, address_: toBytes32Address(privateKeyToAccount(PK_0).address) }],
    };

    const hash = await vault.getHashToSign(request);
    const signature = await signerAccount.signMessage({ message: MESSAGE_PREFIX + hash });
    const [ok] = await vault.verifyRequestSignature(request, signature);
    expect(ok).to.equal(false);
  });
});
