# RBAC
Smart contract based on Substrate INK

Implementation of Roles bases access control

1.Contract Source Code
The ink! CLI works with the source code for the "RBAC" contract for Role Based Access Control. 

The RBAC contract have below mentioned facilities;
    User can be added to the Groups
    
    Roles can be assigned to Users/Groups
    
    Permission is given based on Roles.
    
    Check Access if particular User have certain permission
    
2.Testing Your Contract

You will see at the bottom of the source code there are simple test cases which verify the functionality of the contract. We can quickly test this code is functioning as expected using the off-chain test environment that ink! provides.

In your project folder run in which you should see a successful test completion:

    cargo +nightly test

3. Building Your Contract

Run the following command to compile your smart contract in the Flipper project directory:

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

Deploying a Smart Contract:

    https://docs.substrate.io/tutorials/v3/ink-workshop/pt1/#deploying-your-contract
