# Arcana Credit

Vault contracts are where users' funds are locked. Currently, deposits are made by the backend server in our protocol on behalf of the user. The user needs to approve the ERC20 token allowance during onboarding, which is the only instance where they actually spend gas; however, it's a one-time activity, and gas handling is managed externally from the smart contracts. After the allowance, whenever a user wants to create an intent, they sign a message and send it to the server. The server verifies the signature and pulls funds from the user. The backend server that executes the transaction also receives a refund for this. Once the entire intent is fulfilled, the Arcana blockchain (via multisig) calls the settle function, which finalizes all solver payments.

```shell
npx hardhat test
```
