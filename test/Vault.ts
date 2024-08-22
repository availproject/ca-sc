// test/VaultTest.ts
import { ethers, upgrades, version } from "hardhat";
import { expect } from "chai";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { Contract } from "ethers";
import { USDC, Vault } from "../typechain-types";

describe("Vault Contract", function () {
  let vault: Vault;
  let usdc: USDC;
  let owner: HardhatEthersSigner;
  let user: HardhatEthersSigner;
  let solver: HardhatEthersSigner;
  let chainID: number;
  let EIP712Domain = {
    name: "ArcanaCredit",
    version: "0.0.1",
    chainId: 1337,
    verifyingContract: "",
  };

  const types = {
    Request: [
      { name: "sources", type: "SourcePair[]" },
      { name: "destinationchainID", type: "uint256" },
      { name: "destinations", type: "DestinationPair[]" },
      { name: "nonce", type: "uint256" },
      { name: "expiry", type: "uint256" },
    ],
    SourcePair: [
      { name: "chainID", type: "uint256" },
      { name: "tokenAddress", type: "address" },
      { name: "value", type: "uint256" },
    ],
    DestinationPair: [
      { name: "tokenAddress", type: "address" },
      { name: "value", type: "uint256" },
    ],
  };

  beforeEach(async function () {
    [owner, user, solver] = await ethers.getSigners();
    const network = await ethers.provider.getNetwork();
    chainID = Number(network.chainId);
    EIP712Domain.chainId = chainID;

    // Deploy mock USDC token
    const USDCMock = await ethers.getContractFactory("USDC");
    usdc = await USDCMock.deploy();

    // Deploy the Vault contract
    const VaultContract = await ethers.getContractFactory("Vault");
    vault = (await upgrades.deployProxy(VaultContract, [], {
      initializer: "initialize",
    })) as unknown as Vault;
    EIP712Domain.verifyingContract = await vault.getAddress();
  });

  it("should assign admin role to deployer", async function () {
    const adminRole = await vault.DEFAULT_ADMIN_ROLE();
    expect(await vault.hasRole(adminRole, owner.address)).to.be.true;
  });

  it("should not allow non-admin to have admin access", async function () {
    const adminRole = await vault.DEFAULT_ADMIN_ROLE();
    expect(await vault.hasRole(adminRole, user.address)).to.be.false;
  });

  async function prepareDeposit(
    from: HardhatEthersSigner,
    sourceToken: USDC,
    destinationToken: USDC,
    amount: number,
    destinationchainID: number,
    nonce: number
  ) {
    const request = {
      sources: [
        {
          chainID: chainID,
          tokenAddress: await sourceToken.getAddress(),
          value: amount,
        },
      ],
      destinationchainID: destinationchainID,
      destinations: [
        { value: amount, tokenAddress: await destinationToken.getAddress() },
      ],
      nonce: nonce,
      expiry: Math.floor(Date.now() / 1000) + 3600, // Expiry 1 hour from now
    };
    const signature = await user.signTypedData(EIP712Domain, types, request);

    await sourceToken.mint(from.address, amount);
    await sourceToken.connect(from).approve(await vault.getAddress(), amount);

    return { request, signature };
  }

  it("should deposit tokens", async function () {
    const amount = 100;
    const nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      usdc,
      usdc,
      amount,
      2,
      nonce
    );

    await expect(vault.deposit(request, signature, user.address, 0)).to.emit(
      vault,
      "Deposit"
    );

    expect(await usdc.balanceOf(user.address)).to.equal(0);
    expect(await usdc.balanceOf(await vault.getAddress())).to.equal(amount);
  });

  it("should fail to deposit with the same nonce", async function () {
    const amount = 100;
    const nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      usdc,
      usdc,
      amount,
      2,
      nonce
    );

    await vault.deposit(request, signature, user.address, 0);

    await expect(
      vault.deposit(request, signature, user.address, 0)
    ).to.be.revertedWith("ArcanaCredit: Nonce already used");
  });

  it("should fill a request correctly", async function () {
    const amount = 100;
    const nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      usdc,
      usdc,
      amount,
      chainID,
      nonce
    );

    await vault.deposit(request, signature, user.address, 0);

    await usdc.mint(await solver.getAddress(), amount);
    await usdc.connect(solver).approve(await vault.getAddress(), amount);
    await expect(
      vault.connect(solver).fill(request, signature, user.address)
    ).to.emit(vault, "Fill");

    expect(await usdc.balanceOf(user.address)).to.equal(amount);
  });

  it("should not allow filling a request with the same nonce again", async function () {
    const amount = 100;
    const nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      usdc,
      usdc,
      amount,
      chainID,
      nonce
    );

    await vault.deposit(request, signature, user.address, 0);

    await usdc.mint(await solver.getAddress(), 2 * amount);
    await usdc.connect(solver).approve(await vault.getAddress(), 2 * amount);

    await vault.connect(solver).fill(request, signature, user.address);

    await expect(
      vault.connect(solver).fill(request, signature, user.address)
    ).to.be.revertedWith("ArcanaCredit: Nonce already used");
  });

  it("should allow admin to rebalance tokens", async function () {
    await usdc.mint(await vault.getAddress(), 100);

    await expect(vault.rebalance(await usdc.getAddress(), 100))
      .to.emit(vault, "Rebalance")
      .withArgs(await usdc.getAddress(), 100);

    expect(await usdc.balanceOf(await vault.getAddress())).to.equal(0);
    expect(await usdc.balanceOf(owner.address)).to.equal(100);
  });
});
