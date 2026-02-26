import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { keccak256, getBytes, toUtf8Bytes } from "ethers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const SIGNATURE_PREFIX = "Sign this intent to proceed";

describe("Vault Contract - Signature Prefix", function () {
  let vault: any;
  let owner: any;
  let user: any;

  beforeEach(async function () {
    [owner, user] = await ethers.getSigners();

    const VaultContract = await ethers.getContractFactory("Vault");
    vault = (await upgrades.deployProxy(VaultContract, [owner.address], {
      initializer: "initialize",
    })) as unknown as any;
  });

  it("should verify signature with prefix", async function () {
    const requestHash = keccak256(toUtf8Bytes("test request"));
    
    const prefixBytes = toUtf8Bytes(SIGNATURE_PREFIX);
    const prefixedHash = keccak256(
      ethers.concat([prefixBytes, getBytes(requestHash)])
    );

    const signature = await user.signMessage(getBytes(prefixedHash));

    const request = {
      sources: [{
        universe: 0,
        chainID: 31337,
        contractAddress: ethers.zeroPadValue(user.address, 32),
        value: 100
      }],
      destinationUniverse: 0,
      destinationChainID: 31337,
      recipientAddress: ethers.zeroPadValue(user.address, 32),
      destinations: [{
        contractAddress: ethers.zeroPadValue(ethers.ZeroAddress, 32),
        value: 100
      }],
      nonce: 1,
      expiry: (await time.latest()) + 3600,
      parties: [{
        universe: 0,
        address_: ethers.zeroPadValue(user.address, 32)
      }]
    };

    const requestHashFromContract = await vault.hashRequest(request);
    
    const prefixedRequestHash = keccak256(
      ethers.concat([prefixBytes, getBytes(requestHashFromContract)])
    );
    
    const requestSignature = await user.signMessage(getBytes(prefixedRequestHash));

    const [isValid, signedMessageHash] = await vault.verifyRequestSignature(request, requestSignature);
    
    expect(isValid).to.be.true;
    expect(signedMessageHash).to.not.equal(ethers.ZeroHash);
  });

  it("should reject signature without prefix", async function () {
    const request = {
      sources: [{
        universe: 0,
        chainID: 31337,
        contractAddress: ethers.zeroPadValue(user.address, 32),
        value: 100
      }],
      destinationUniverse: 0,
      destinationChainID: 31337,
      recipientAddress: ethers.zeroPadValue(user.address, 32),
      destinations: [{
        contractAddress: ethers.zeroPadValue(ethers.ZeroAddress, 32),
        value: 100
      }],
      nonce: 1,
      expiry: (await time.latest()) + 3600,
      parties: [{
        universe: 0,
        address_: ethers.zeroPadValue(user.address, 32)
      }]
    };

    const requestHashFromContract = await vault.hashRequest(request);
    
    const requestSignature = await user.signMessage(getBytes(requestHashFromContract));

    const [isValid, signedMessageHash] = await vault.verifyRequestSignature(request, requestSignature);
    
    expect(isValid).to.be.false;
  });
});
