# RBAC
Smart contract based on Substrate INK

Implementation of Roles bases access control

## Contract Source Code
The ink! CLI works with the source code for the "RBAC" contract for Role Based Access Control. 

The RBAC contract have below mentioned facilities;
    User can be added to the Groups
    
    Roles can be assigned to Users/Groups
    
    Permission is given based on Roles.
    
    Check Access if particular User have certain permission
    
## Testing Your Contract

You will see at the bottom of the source code there are simple test cases which verify the functionality of the contract. We can quickly test this code is functioning as expected using the off-chain test environment that ink! provides.

In your project folder run in which you should see a successful test completion:

    cargo +nightly test

## Building Your Contract

Run the following command to compile your smart contract in the RBAC project directory:

    cargo +nightly contract build

Information
    If you run into a call to unsafe function error, run cargo install --force cargo-contract && rustup update to make sure everything is up to date.

This command will build a Wasm binary for the ink! project, a metadata file (which contains the contract's ABI) and a .contract file which bundles both. This .contract file can be used for deploying your contract to your chain. If all goes well, you should see a target folder which contains these files

    Let's take a look at the structure of metadata.json:
    {
      "metadataVersion": "0.1.0",
      "source": {...},
      "contract": {...},
      "spec": {
        "constructors": [...],
        "docs": [],
        "events": [],
        "messages": [...],
      },
      "storage": {...},
      "types": [...]
    }

This file describes all the interfaces that can be used to interact with your contract:

    **types** provides the custom data types used throughout the rest of the JSON.
    **storage** defines all the storage items managed by your contract and how to ultimately access them.
    **spec** stores information about the callable functions like constructors and messages a user can call to interact with the contract. It also has helpful information like the events that are emitted by the contract or any docs.
    If you look closely at the **constructors** and **messages**, you will also notice a selector which contains a 4-byte hash of the function name and is used to route your contract calls to the correct functions.

Running a contract on Node:

Start a Substrate Smart Contracts node and configure the Canvas UI to interact with it.
        
    https://docs.substrate.io/tutorials/v3/ink-workshop/pt1/#running-a-substrate-smart-contracts-node

Deploying a Smart Contract:

    https://docs.substrate.io/tutorials/v3/ink-workshop/pt1/#deploying-your-contract

## Docker
We can use Docker image to build and test this contract; please follow the below commands. The contract files are under the folder, `target/ink/`.
```
# Build
docker run --rm -it -v $(pwd):/sources -w /sources rust-stable:ubuntu-20.04 cargo +nightly contract build
# Test
docker run --rm -it -v $(pwd):/sources -w /sources rust-stable:ubuntu-20.04 cargo +nightly contract test
```

## Testing
We can run the behavior test in the test folder to check RBAC can work efficiently. Please follow the below instruction.
```
cd test
npm install

npm run test
```
However, before you run the scripts, you have to generate the ink contract file in advance.

## Seed Data
Another script in the test folder is the rbac_deploy script. It'll help to deploy the fake data for checking on polkadot.js UI.
```
cd test
npm install

npm run deploy
```

However, before you run the scripts, you have to generate the ink contract file in advance.

The deployed data and the relationship are below
| Type | Name | DID |
| ---- | ---- | --- |
| group | PeaqOffice | 0x1122334455667788990011223344556677889900112233445566778899000010 |
| user | Tanisha | 0x1122334455667788990011223344556677889900112233445566778899000000 |
| user | Leo | 0x1122334455667788990011223344556677889900112233445566778899000001 |
| user | Anton | 0x1122334455667788990011223344556677889900112233445566778899000002 |
| user | Maryna | 0x1122334455667788990011223344556677889900112233445566778899000003 |
| role | AccessToOffice | 0x1122334455667788990011223344556677889900112233445566778899000020 |
| permission | GrantMainDoorUnlock | 0x1122334455667788990011223344556677889900112233445566778899000031 |

```
`PeaqOffice` has two users, `Tanisha` and `Anton`.
`Leo` and `PeaqOffice` are assigned to the role, `AccessToOffice`.
`AccessToOffice` has the `GrantMainDoorUnlock` permission.
```
