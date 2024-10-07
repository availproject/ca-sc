// test/VaultTest.ts
import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { keccak256, getBytes } from "ethers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

enum Function {
  DEPOSIT = 0,
  SETTLE = 1,
}

describe("Vault Contract", function () {
  const OVERHEAD = 33138;
  let vault: any;
  let usdc: any;
  let owner: any;
  let user: any;
  let solver: any;
  let chainID: number;

  beforeEach(async function () {
    [owner, user, solver] = await ethers.getSigners();
    const network = await ethers.provider.getNetwork();
    chainID = Number(network.chainId);

    // Deploy mock USDC token
    const USDCMock = await ethers.getContractFactory("USDC");
    usdc = await USDCMock.deploy();

    // Deploy the Vault contract
    const VaultContract = await ethers.getContractFactory("Vault");
    vault = (await upgrades.deployProxy(VaultContract, [], {
      initializer: "initialize",
    })) as unknown as any;

    // Transfer ETH to the Vault contract
    await owner.sendTransaction({
      to: await vault.getAddress(),
      value: ethers.parseEther("0.0005"), // enough to cover gas fees for 1 tx
    });

    await vault.setOverHead(Function.DEPOSIT, OVERHEAD);
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
    from: any,
    sourceToken: any | string,
    destinationToken: any | string,
    amount: number,
    destinationChainID: number,
    nonce: number
  ) {
    const request = {
      sources: [
        {
          chainID: chainID,
          tokenAddress:
            typeof sourceToken === "string"
              ? sourceToken
              : await sourceToken.getAddress(),
          value: amount,
        },
      ],
      destinationChainID: destinationChainID,
      destinations: [
        {
          value: amount,
          tokenAddress:
            typeof destinationToken === "string"
              ? destinationToken
              : await destinationToken.getAddress(),
        },
      ],
      nonce: nonce,
      expiry: (await time.latest()) + 3600, // Expiry 1 hour from now
    };

    if (typeof sourceToken !== "string") {
      await sourceToken.mint(from.address, amount);
      await sourceToken.connect(from).approve(await vault.getAddress(), amount);
    }

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    // Create the message hash for personal signature
    const requestHash = keccak256(
      abiCoder.encode(
        [
          "tuple(uint256,address,uint256)[]",
          "uint256",
          "tuple(address,uint256)[]",
          "uint256",
          "uint256",
        ],
        [
          request.sources.map((s) => [s.chainID, s.tokenAddress, s.value]),
          request.destinationChainID,
          request.destinations.map((d) => [d.tokenAddress, d.value]),
          request.nonce,
          request.expiry,
        ]
      )
    );

    const signature = await from.signMessage(getBytes(requestHash));
    return { request, signature };
  }

  it("should allow to deposit ERC20 tokens", async function () {
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

    // Eth balance of the owner before deposit
    const ethBalanceBefore = await owner.provider.getBalance(owner.address);

    await expect(vault.deposit(request, signature, user.address, 0)).to.emit(
      vault,
      "Deposit"
    );

    const ethBalanceAfter = await owner.provider.getBalance(owner.address);

    expect(ethBalanceBefore - ethBalanceAfter).to.be.closeTo(
      0,
      ethers.parseEther("0.00001")
    );

    expect(await usdc.balanceOf(user.address)).to.equal(0);
    expect(await usdc.balanceOf(await vault.getAddress())).to.equal(amount);
  });

  it("should allow to deposit native tokens", async function () {
    const amount = 100000;
    const nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      amount,
      2,
      nonce
    );

    await expect(
      vault.deposit(request, signature, user.address, 0, {
        value: amount,
      })
    ).to.emit(vault, "Deposit");
  });

  it("should not refund money if vault balance is low", async function () {
    const amount = 100000;
    let nonce = 1;

    const { request, signature } = await prepareDeposit(
      user,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      amount,
      2,
      nonce
    );

    await expect(
      vault.deposit(request, signature, user.address, 0, {
        value: amount,
      })
    ).to.emit(vault, "Deposit");

    nonce++;
    const { request: request2, signature: signature2 } = await prepareDeposit(
      user,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      amount,
      2,
      nonce
    );
    const vaultEthBalanceBefore = await vault.vaultBalance();
    await expect(
      vault.deposit(request2, signature2, user.address, 0, {
        value: amount,
      })
    );
    expect(await vault.vaultBalance()).to.equal(vaultEthBalanceBefore);
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
    ).to.be.revertedWith("Vault: Nonce already used");
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
    ).to.be.revertedWith("Vault: Nonce already used");
  });

  it("should allow admin to rebalance tokens", async function () {
    await usdc.mint(await vault.getAddress(), 100);

    await expect(vault.withdraw(owner, await usdc.getAddress(), 100))
      .to.emit(vault, "Withdraw")
      .withArgs(owner, await usdc.getAddress(), 100);

    expect(await usdc.balanceOf(await vault.getAddress())).to.equal(0);
    expect(await usdc.balanceOf(owner.address)).to.equal(100);
  });

  it("Admin should be able to settle all solver", async function () {
    // do a deposit in ERC20 and eth first
    let amount = 100;
    let nonce = 1;

    let { request, signature } = await prepareDeposit(
      user,
      usdc,
      usdc,
      amount,
      2,
      nonce
    );

    await vault.deposit(request, signature, user.address, 0);

    amount = 100000;
    nonce = 2;

    let dep = await prepareDeposit(
      user,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      amount,
      2,
      nonce
    );

    request = dep.request;
    signature = dep.signature;

    await vault.connect(user).deposit(request, signature, user.address, 0, {
      value: amount,
    });

    // settle all solvers
    const solvers = [await solver.getAddress(), await solver.getAddress()];
    const tokens = [await usdc.getAddress(), ethers.ZeroAddress];
    const amounts = [100, 100000];
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const nonceSettle = 1;
    const chainID = (await ethers.provider.getNetwork()).chainId;
    const settleHash = keccak256(
      abiCoder.encode(
        ["address[]", "address[]", "uint256[]", "uint256", "uint256"],
        [solvers, tokens, amounts, nonceSettle, chainID]
      )
    );
    const settleSignature = await owner.signMessage(getBytes(settleHash));

    // balance before of the solvers
    let balanceBefore = await usdc.balanceOf(await solver.getAddress());
    let ethBalanceBefore = await solver.provider.getBalance(solver.address);
    await vault.settle(
      { solvers, tokens, amounts, nonce: nonceSettle },
      settleSignature
    );
    expect(await usdc.balanceOf(await solver.getAddress())).to.equal(
      balanceBefore + 100n
    );
    expect(await solver.provider.getBalance(solver.address)).to.equal(
      ethBalanceBefore + 100000n
    );
  });

  it("Admin should be able to set max gas price", async function () {
    await vault.setMaxGasPrice(100);
    expect(await vault.maxGasPrice()).to.equal(100);
  });
});
