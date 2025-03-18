// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
const { ethers, upgrades } = require("hardhat");

async function main() {
    const signers = await ethers.getSigners()
    const Vault = await ethers.getContractFactory('Vault')
    const vault = await upgrades.deployProxy(Vault, [signers[0].address], {
        kind: 'uups',
        timeout: 0,
    })
    console.log('Generated address:', await vault.getAddress())
    await vault.waitForDeployment()

    console.log(
        `Vault deployed to ${await vault.getAddress()}`
    );
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
}).then(() => {
    console.log('All done!')
});
